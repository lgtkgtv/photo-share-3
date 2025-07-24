from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from services.db import get_db
from dao.email_verification_dao import EmailVerificationDAO
from dao.user_dao import UserDAO
from schemas.email_verification import VerificationRequest, VerificationResponse

router = APIRouter()

@router.post("/request-verification", response_model=VerificationResponse)
async def request_verification(data: VerificationRequest, db: AsyncSession = Depends(get_db)):
    verification_dao = EmailVerificationDAO(db)
    user_dao = UserDAO(db)
    user = await user_dao.get_by_email(data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    record = await verification_dao.create_verification(email=data.email)
    # Simulated email output
    link = f"http://localhost:8000/api/users/verify-email?secret={record.secret}"
    print(f"📧 Simulated Email Link: {link}")
    return {"message": "Verification email sent (simulated)."}

@router.get("/verify-email", response_model=VerificationResponse)
async def verify_email(secret: str = Query(...), db: AsyncSession = Depends(get_db)):
    verification_dao = EmailVerificationDAO(db)
    user_dao = UserDAO(db)

    record = await verification_dao.verify_secret(secret)
    if not record:
        raise HTTPException(status_code=400, detail="Invalid or expired secret")

    user = await user_dao.get_by_email(record.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_verified = True
    await db.commit()
    await verification_dao.delete_secret(secret)

    return {"message": "Email successfully verified."}
