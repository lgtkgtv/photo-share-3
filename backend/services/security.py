"""
Enterprise-grade security utilities and configuration management.
Implements secure secrets management, cryptographic functions, and security validation.
"""
import os
import secrets
import string
import hashlib
from typing import Optional
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

class SecurityConfig:
    """Centralized security configuration with validation."""
    
    def __init__(self):
        self.jwt_secret_key = self._get_or_generate_jwt_secret()
        self.jwt_algorithm = os.getenv("JWT_ALGORITHM", "HS256")
        self.jwt_access_token_expire_minutes = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
        self.jwt_refresh_token_expire_days = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))
        
        # Password security settings
        self.password_min_length = int(os.getenv("PASSWORD_MIN_LENGTH", "12"))
        self.password_require_uppercase = os.getenv("PASSWORD_REQUIRE_UPPERCASE", "true").lower() == "true"
        self.password_require_lowercase = os.getenv("PASSWORD_REQUIRE_LOWERCASE", "true").lower() == "true"
        self.password_require_digits = os.getenv("PASSWORD_REQUIRE_DIGITS", "true").lower() == "true"
        self.password_require_special = os.getenv("PASSWORD_REQUIRE_SPECIAL", "true").lower() == "true"
        
        # Rate limiting settings
        self.rate_limit_requests_per_minute = int(os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"))
        self.rate_limit_login_attempts_per_hour = int(os.getenv("RATE_LIMIT_LOGIN_ATTEMPTS_PER_HOUR", "5"))
        self.account_lockout_attempts = int(os.getenv("ACCOUNT_LOCKOUT_ATTEMPTS", "5"))
        self.account_lockout_duration_minutes = int(os.getenv("ACCOUNT_LOCKOUT_DURATION_MINUTES", "30"))
        
        # Security headers
        self.enable_csrf_protection = os.getenv("ENABLE_CSRF_PROTECTION", "true").lower() == "true"
        self.enable_security_headers = os.getenv("ENABLE_SECURITY_HEADERS", "true").lower() == "true"
        
        self._validate_config()
    
    def _get_or_generate_jwt_secret(self) -> str:
        """
        Get JWT secret from environment or generate a secure one.
        In production, this should come from a secure secret management service.
        """
        secret = os.getenv("JWT_SECRET_KEY")
        
        if not secret:
            logger.warning("JWT_SECRET_KEY not found in environment. Generating secure random secret.")
            secret = self._generate_secure_secret()
            logger.info("Generated secure JWT secret. In production, store this securely!")
            
        elif len(secret) < 32:
            logger.error("JWT_SECRET_KEY is too short! Must be at least 32 characters.")
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters long")
            
        elif secret in ["super-secret-key", "secret", "password", "key"]:
            logger.error("JWT_SECRET_KEY appears to be a default/weak value!")
            raise ValueError("JWT_SECRET_KEY cannot be a default or weak value")
            
        return secret
    
    def _generate_secure_secret(self, length: int = 64) -> str:
        """Generate cryptographically secure secret key."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def _validate_config(self):
        """Validate security configuration for production readiness."""
        issues = []
        
        # JWT validation
        if self.jwt_algorithm not in ["HS256", "HS384", "HS512"]:
            issues.append(f"Unsupported JWT algorithm: {self.jwt_algorithm}")
            
        if self.jwt_access_token_expire_minutes > 60:
            issues.append("JWT access token expiration too long (>60 minutes) for production")
            
        # Password policy validation
        if self.password_min_length < 8:
            issues.append("Password minimum length too short (<8 characters)")
            
        # Rate limiting validation
        if self.rate_limit_login_attempts_per_hour > 10:
            issues.append("Login rate limit too permissive (>10 attempts/hour)")
            
        if issues:
            logger.warning("Security configuration issues detected:")
            for issue in issues:
                logger.warning(f"  - {issue}")

class PasswordValidator:
    """Enterprise-grade password validation and strength checking."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.common_passwords = self._load_common_passwords()
    
    def validate_password(self, password: str) -> tuple[bool, list[str]]:
        """
        Validate password against security policy.
        Returns (is_valid, list_of_errors).
        """
        errors = []
        
        # Length check
        if len(password) < self.config.password_min_length:
            errors.append(f"Password must be at least {self.config.password_min_length} characters long")
            
        # Character requirements
        if self.config.password_require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
            
        if self.config.password_require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
            
        if self.config.password_require_digits and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
            
        if self.config.password_require_special:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                errors.append("Password must contain at least one special character")
        
        # Common password check
        if password.lower() in self.common_passwords:
            errors.append("Password is too common. Please choose a more unique password")
            
        # Sequential character check
        if self._has_sequential_chars(password):
            errors.append("Password cannot contain sequential characters (e.g., '123', 'abc')")
            
        return len(errors) == 0, errors
    
    def _load_common_passwords(self) -> set:
        """Load list of common passwords to reject."""
        # In production, load from a file or database
        return {
            "password", "123456", "password123", "admin", "letmein",
            "welcome", "monkey", "1234567890", "qwerty", "abc123",
            "Password1", "password1", "123456789", "welcome123"
        }
    
    def _has_sequential_chars(self, password: str, min_seq_length: int = 4) -> bool:
        """Check for sequential characters in password (4+ chars to be less strict)."""
        password_lower = password.lower()
        
        # Check for sequential numbers (4+ digits)
        for i in range(len(password_lower) - min_seq_length + 1):
            substr = password_lower[i:i + min_seq_length]
            if substr.isdigit():
                if all(int(substr[j]) == int(substr[0]) + j for j in range(len(substr))):
                    return True
                    
        # Check for sequential letters (4+ letters)
        for i in range(len(password_lower) - min_seq_length + 1):
            substr = password_lower[i:i + min_seq_length]
            if substr.isalpha():
                if all(ord(substr[j]) == ord(substr[0]) + j for j in range(len(substr))):
                    return True
        
        # Check for obvious long sequences regardless of length
        obvious_sequences = [
            "0123", "1234", "2345", "3456", "4567", "5678", "6789",
            "abcd", "bcde", "cdef", "defg", "efgh", "fghi", "ghij",
            "hijk", "ijkl", "jklm", "klmn", "lmno", "mnop", "nopq",
            "opqr", "pqrs", "qrst", "rstu", "stuv", "tuvw", "uvwx",
            "vwxy", "wxyz"
        ]
        
        for seq in obvious_sequences:
            if seq in password_lower:
                return True
                    
        return False

class SecurityUtils:
    """Security utility functions for enterprise applications."""
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure URL-safe token."""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_sensitive_data(data: str, salt: Optional[str] = None) -> tuple[str, str]:
        """
        Hash sensitive data with salt for secure storage.
        Returns (hash, salt).
        """
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 with SHA256 for additional security
        hash_obj = hashlib.pbkdf2_hmac('sha256', data.encode(), salt.encode(), 100000)
        return hash_obj.hex(), salt
    
    @staticmethod
    def verify_hashed_data(data: str, stored_hash: str, salt: str) -> bool:
        """Verify data against stored hash with constant-time comparison."""
        computed_hash, _ = SecurityUtils.hash_sensitive_data(data, salt)
        return secrets.compare_digest(computed_hash, stored_hash)
    
    @staticmethod
    def get_client_ip(request) -> str:
        """Extract client IP address handling proxies and load balancers."""
        # Check for forwarded IP first (behind load balancer/proxy)
        forwarded_ips = request.headers.get("X-Forwarded-For")
        if forwarded_ips:
            # Take the first IP (original client)
            client_ip = forwarded_ips.split(",")[0].strip()
            return client_ip
            
        # Check for real IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
            
        # Fallback to direct connection IP
        return request.client.host if request.client else "unknown"
    
    @staticmethod
    def sanitize_email(email: str) -> str:
        """Sanitize email address for safe processing."""
        if not email:
            return ""
        
        # Convert to lowercase and strip whitespace
        email = email.lower().strip()
        
        # Basic email format validation will be handled by EmailStr
        # This is just for additional sanitization
        return email
    
    @staticmethod
    def log_security_event(event_type: str, details: dict, user_email: Optional[str] = None, 
                          client_ip: Optional[str] = None):
        """Log security events for monitoring and analysis."""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user_email": user_email,
            "client_ip": client_ip,
            "details": details
        }
        
        # In production, send to security monitoring system
        logger.info(f"SECURITY_EVENT: {log_entry}")
    
    @staticmethod
    def get_utc_now() -> datetime:
        """Get current UTC datetime."""
        return datetime.now(timezone.utc)

# Global security configuration instance
security_config = SecurityConfig()
password_validator = PasswordValidator(security_config)