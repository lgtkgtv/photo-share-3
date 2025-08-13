from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from dao.user_dao import UserDAO
from models.user import User
from services.db import get_db
from services.security import security_config, SecurityUtils, password_validator
import asyncio
import secrets
import logging

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/users/login")

async def verify_password_secure(plain: str, hashed: str, fake_user_email: str = None) -> bool:
    """
    Secure password verification with constant-time operations to prevent timing attacks.
    Always performs hashing operation even for non-existent users.
    """
    # Always perform a hash operation to maintain constant time
    if fake_user_email:
        # For non-existent users, hash a fake password to maintain constant time
        fake_password = f"fake_password_for_{fake_user_email}"
        pwd_context.verify(fake_password, "$2b$12$dummy.hash.that.will.always.fail.validation")
        return False
    else:
        # Real password verification
        return pwd_context.verify(plain, hashed)

def verify_password(plain: str, hashed: str) -> bool:
    """Legacy function for backward compatibility."""
    return pwd_context.verify(plain, hashed)

def get_password_hash(password: str) -> str:
    """Hash password using bcrypt with secure settings."""
    return pwd_context.hash(password)

def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """Validate password against security policy."""
    return password_validator.validate_password(password)

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    """
    Create JWT access token with secure configuration.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=security_config.jwt_access_token_expire_minutes)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access"
    })
    
    return jwt.encode(to_encode, security_config.jwt_secret_key, algorithm=security_config.jwt_algorithm)

def create_refresh_token(user_email: str) -> str:
    """
    Create JWT refresh token with longer expiration.
    """
    expire = datetime.now(timezone.utc) + timedelta(days=security_config.jwt_refresh_token_expire_days)
    
    to_encode = {
        "sub": user_email,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh",
        "jti": SecurityUtils.generate_secure_token(16)  # JWT ID for blacklisting
    }
    
    return jwt.encode(to_encode, security_config.jwt_secret_key, algorithm=security_config.jwt_algorithm)

async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    """
    Get current authenticated user with enhanced security validation.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode and validate JWT token
        payload = jwt.decode(
            token, 
            security_config.jwt_secret_key, 
            algorithms=[security_config.jwt_algorithm]
        )
        
        email: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if not email or token_type != "access":
            SecurityUtils.log_security_event(
                "invalid_token_format",
                {"reason": "missing_subject_or_wrong_type"},
                client_ip=SecurityUtils.get_client_ip(request)
            )
            raise credentials_exception
            
    except JWTError as e:
        SecurityUtils.log_security_event(
            "jwt_decode_error",
            {"error": str(e)},
            client_ip=SecurityUtils.get_client_ip(request)
        )
        raise credentials_exception

    # Get user from database
    user = await UserDAO(db).get_by_email(email)
    if not user:
        SecurityUtils.log_security_event(
            "token_user_not_found",
            {"email": email},
            user_email=email,
            client_ip=SecurityUtils.get_client_ip(request)
        )
        raise credentials_exception
        
    # Check if user account is active
    if not user.is_active:
        SecurityUtils.log_security_event(
            "inactive_user_token_use",
            {"user_id": user.id},
            user_email=email,
            client_ip=SecurityUtils.get_client_ip(request)
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )
    
    return user

async def authenticate_user_secure(db: AsyncSession, email: str, password: str, client_ip: str = None) -> User | None:
    """
    Authenticate user with timing attack protection and security logging.
    """
    # Always normalize email
    email = SecurityUtils.sanitize_email(email)
    
    # Get user from database
    user = await UserDAO(db).get_by_email(email)
    
    # Perform password verification with constant-time operations
    if user:
        is_valid = await verify_password_secure(password, user.hashed_password)
        if is_valid:
            SecurityUtils.log_security_event(
                "successful_login",
                {"user_id": user.id},
                user_email=email,
                client_ip=client_ip
            )
            return user
        else:
            SecurityUtils.log_security_event(
                "failed_login_wrong_password",
                {"user_id": user.id},
                user_email=email,
                client_ip=client_ip
            )
    else:
        # For non-existent users, still perform password verification to maintain constant time
        await verify_password_secure(password, "", fake_user_email=email)
        SecurityUtils.log_security_event(
            "failed_login_user_not_found",
            {},
            user_email=email,
            client_ip=client_ip
        )
    
    return None
