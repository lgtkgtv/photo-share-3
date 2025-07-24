from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from schemas.user import UserCreate, UserOut, Token
from services.db import get_db
from models.user import User
from dao.user_dao import UserDAO
from dao.email_verification_dao import EmailVerificationDAO
from services.auth import get_password_hash, verify_password, create_access_token, get_current_user
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timezone

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@router.post("/register", response_model=UserOut)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    dao = UserDAO(db)
    existing_user = await dao.get_by_email(user_in.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_pw = get_password_hash(user_in.password)
    new_user = User(email=user_in.email, hashed_password=hashed_pw)
    return await dao.create_user(new_user)

@router.post("/request-verification")
async def request_verification(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    email = body.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Missing email")

    dao = UserDAO(db)
    user = await dao.get_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_verified:
        return {"message": "Email already verified"}

    ev_dao = EmailVerificationDAO(db)
    record = await ev_dao.create_verification(email)
    print(f"[DEBUG] Verification link: http://localhost:8000/api/users/verify-email?secret={record.secret}")
    return {"message": "Verification email sent (simulated)"}

@router.get("/verify-email")
async def verify_email(secret: str, db: AsyncSession = Depends(get_db)):
    ev_dao = EmailVerificationDAO(db)
    record = await ev_dao.verify_secret(secret)
    if not record:
        raise HTTPException(status_code=404, detail="Invalid or expired secret")
    if record.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Secret expired")
    user_dao = UserDAO(db)
    user = await user_dao.get_by_email(record.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_verified = True
    await db.commit()
    await ev_dao.delete_by_id(record.id)
    return {"message": f"Email {record.email} successfully verified."}

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = await UserDAO(db).get_by_email(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user
