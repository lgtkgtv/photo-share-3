from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from schemas.user import UserCreate, UserOut, Token
from services.db import get_db
from models.user import User
from dao.user_dao import UserDAO
from dao.email_verification_dao import EmailVerificationDAO
from services.auth import (
    get_password_hash, verify_password, create_access_token, create_refresh_token,
    get_current_user, authenticate_user_secure, validate_password_strength
)
from services.security import SecurityUtils
from services.rate_limiter import get_rate_limiter
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@router.post("/register", response_model=UserOut)
async def register(user_in: UserCreate, request: Request, db: AsyncSession = Depends(get_db)):
    """Register new user with enhanced security validation."""
    client_ip = SecurityUtils.get_client_ip(request)
    email = SecurityUtils.sanitize_email(user_in.email)
    
    # Validate password strength
    is_strong, password_errors = validate_password_strength(user_in.password)
    if not is_strong:
        SecurityUtils.log_security_event(
            "weak_password_registration_attempt",
            {"password_errors": password_errors},
            user_email=email,
            client_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Password does not meet security requirements", "errors": password_errors}
        )
    
    dao = UserDAO(db)
    existing_user = await dao.get_by_email(email)
    if existing_user:
        SecurityUtils.log_security_event(
            "duplicate_registration_attempt",
            {},
            user_email=email,
            client_ip=client_ip
        )
        # Generic error to avoid user enumeration
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration failed. Please check your information."
        )
    
    hashed_pw = get_password_hash(user_in.password)
    new_user = User(email=email, hashed_password=hashed_pw)
    
    try:
        created_user = await dao.create_user(new_user)
        SecurityUtils.log_security_event(
            "user_registration_success",
            {"user_id": created_user.id},
            user_email=email,
            client_ip=client_ip
        )
        return created_user
    except Exception as e:
        logger.error(f"User registration failed: {e}")
        SecurityUtils.log_security_event(
            "user_registration_failed",
            {"error": str(e)},
            user_email=email,
            client_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed. Please try again."
        )

@router.post("/request-verification")
async def request_verification(request: Request, db: AsyncSession = Depends(get_db)):
    """Request email verification with security protections."""
    client_ip = SecurityUtils.get_client_ip(request)
    
    body = await request.json()
    email = body.get("email")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request format"
        )
    
    email = SecurityUtils.sanitize_email(email)
    
    dao = UserDAO(db)
    user = await dao.get_by_email(email)
    
    # Always return success to avoid user enumeration
    # Log the actual result for security monitoring
    if not user:
        SecurityUtils.log_security_event(
            "verification_request_nonexistent_user",
            {},
            user_email=email,
            client_ip=client_ip
        )
    elif user.is_verified:
        SecurityUtils.log_security_event(
            "verification_request_already_verified",
            {"user_id": user.id},
            user_email=email,
            client_ip=client_ip
        )
    else:
        # Create verification record for valid, unverified users
        ev_dao = EmailVerificationDAO(db)
        record = await ev_dao.create_verification(email)
        
        SecurityUtils.log_security_event(
            "verification_request_created",
            {"user_id": user.id, "secret_length": len(record.secret)},
            user_email=email,
            client_ip=client_ip
        )
        
        # In production, send actual email here instead of logging
        logger.info(f"Verification email would be sent to {email} (dev mode)")
    
    # Always return generic success message
    return {"message": "If the email address is registered, a verification email will be sent."}

@router.get("/verify-email")
async def verify_email(secret: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Verify email with enhanced security validation."""
    client_ip = SecurityUtils.get_client_ip(request)
    
    if not secret or len(secret) < 16:
        SecurityUtils.log_security_event(
            "invalid_verification_secret_format",
            {"secret_length": len(secret) if secret else 0},
            client_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification link"
        )
    
    ev_dao = EmailVerificationDAO(db)
    record = await ev_dao.verify_secret(secret)
    
    if not record:
        SecurityUtils.log_security_event(
            "verification_attempt_invalid_secret",
            {"secret_prefix": secret[:8] + "..."},
            client_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification link"
        )
    
    if record.expires_at < datetime.now(timezone.utc):
        SecurityUtils.log_security_event(
            "verification_attempt_expired_secret",
            {"email": record.email, "expired_at": record.expires_at.isoformat()},
            user_email=record.email,
            client_ip=client_ip
        )
        # Clean up expired record
        await ev_dao.delete_by_id(record.id)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification link has expired. Please request a new one."
        )
    
    user_dao = UserDAO(db)
    user = await user_dao.get_by_email(record.email)
    if not user:
        SecurityUtils.log_security_event(
            "verification_attempt_user_not_found",
            {"email": record.email},
            user_email=record.email,
            client_ip=client_ip
        )
        # Clean up orphaned record
        await ev_dao.delete_by_id(record.id)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification link"
        )
    
    if user.is_verified:
        SecurityUtils.log_security_event(
            "verification_attempt_already_verified",
            {"user_id": user.id},
            user_email=record.email,
            client_ip=client_ip
        )
        # Clean up unnecessary record
        await ev_dao.delete_by_id(record.id)
        return {"message": "Email address has already been verified."}
    
    # Verify the user
    user.is_verified = True
    await db.commit()
    await ev_dao.delete_by_id(record.id)
    
    SecurityUtils.log_security_event(
        "email_verification_success",
        {"user_id": user.id},
        user_email=record.email,
        client_ip=client_ip
    )
    
    return {"message": "Email address successfully verified."}

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), 
               request: Request = None, db: AsyncSession = Depends(get_db)):
    """Secure login with timing attack protection and comprehensive logging."""
    client_ip = SecurityUtils.get_client_ip(request) if request else "unknown"
    rate_limiter = get_rate_limiter()
    
    # Check if client is locked out
    is_locked, lockout_until = await rate_limiter.is_locked_out(client_ip)
    if is_locked:
        SecurityUtils.log_security_event(
            "login_attempt_during_lockout",
            {"lockout_until": lockout_until.isoformat()},
            user_email=form_data.username,
            client_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked due to too many failed attempts"
        )
    
    # Check login rate limits
    login_rate_result = await rate_limiter.check_login_attempts(f"login:{client_ip}")
    if not login_rate_result.allowed:
        SecurityUtils.log_security_event(
            "login_rate_limit_exceeded",
            {"retry_after": login_rate_result.retry_after},
            user_email=form_data.username,
            client_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
            headers={"Retry-After": str(login_rate_result.retry_after or 3600)}
        )
    
    # Authenticate user with timing attack protection
    user = await authenticate_user_secure(db, form_data.username, form_data.password, client_ip)
    
    if not user:
        # Record failed attempt
        await rate_limiter.record_failed_login(client_ip, form_data.username)
        
        # Generic error message to avoid information disclosure
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    if not user.is_verified:
        SecurityUtils.log_security_event(
            "login_attempt_unverified_user",
            {"user_id": user.id},
            user_email=user.email,
            client_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email address must be verified before login"
        )
    
    if not user.is_active:
        SecurityUtils.log_security_event(
            "login_attempt_inactive_user",
            {"user_id": user.id},
            user_email=user.email,
            client_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )
    
    # Reset failed attempts on successful login
    await rate_limiter.reset_failed_attempts(client_ip)
    
    # Create tokens
    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(user.email)
    
    SecurityUtils.log_security_event(
        "successful_login",
        {"user_id": user.id},
        user_email=user.email,
        client_ip=client_ip
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.get("/me", response_model=UserOut)
async def get_me(request: Request, current_user: User = Depends(get_current_user)):
    """Get current user profile information."""
    client_ip = SecurityUtils.get_client_ip(request)
    
    SecurityUtils.log_security_event(
        "user_profile_accessed",
        {"user_id": current_user.id},
        user_email=current_user.email,
        client_ip=client_ip
    )
    
    return current_user
