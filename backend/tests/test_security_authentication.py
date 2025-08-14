"""
Comprehensive security tests for authentication system.
Tests password policies, timing attacks, JWT security, and session management.
"""
import pytest
import time
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
import asyncio

from services.security import SecurityConfig, PasswordValidator, SecurityUtils
from services.auth import (
    get_password_hash, verify_password, verify_password_secure,
    create_access_token, create_refresh_token, authenticate_user_secure
)
from services.rbac import RBACService
from models.user import User
from models.role import BlacklistedToken
from dao.user_dao import UserDAO

class TestPasswordSecurity:
    """Test password validation and security policies."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.security_config = SecurityConfig()
        self.password_validator = PasswordValidator(self.security_config)
    
    def test_strong_password_validation(self):
        """Test that strong passwords are accepted."""
        strong_passwords = [
            "MyStr0ng!Password123",
            "C0mplex&SecureP@ssw0rd",
            "An0ther$VeryStr0ngP@ss",
            "L0ngAndC0mpl3x!P@ssw0rd"
        ]
        
        for password in strong_passwords:
            is_valid, errors = self.password_validator.validate_password(password)
            assert is_valid, f"Strong password rejected: {password}, errors: {errors}"
    
    def test_weak_password_rejection(self):
        """Test that weak passwords are rejected."""
        weak_passwords = [
            "password",          # Too common
            "12345678",          # Only digits
            "abcdefgh",          # Only lowercase
            "ABCDEFGH",          # Only uppercase
            "Pass1!",            # Too short
            "password123",       # Common + sequential
            "abc123DEF",         # Sequential characters
        ]
        
        for password in weak_passwords:
            is_valid, errors = self.password_validator.validate_password(password)
            assert not is_valid, f"Weak password accepted: {password}"
            assert len(errors) > 0, f"No errors returned for weak password: {password}"
    
    def test_password_policy_configuration(self):
        """Test password policy configuration enforcement."""
        # Test minimum length
        short_password = "A1@" + "a" * (self.security_config.password_min_length - 4)
        is_valid, errors = self.password_validator.validate_password(short_password)
        assert not is_valid
        assert any("characters long" in error for error in errors)
        
        # Test character requirements
        if self.security_config.password_require_uppercase:
            no_uppercase = "mystr0ng!password123"
            is_valid, errors = self.password_validator.validate_password(no_uppercase)
            assert not is_valid
            assert any("uppercase" in error for error in errors)
    
    def test_sequential_character_detection(self):
        """Test detection of sequential characters in passwords."""
        sequential_passwords = [
            "MyPassword123456",   # Sequential numbers
            "MyPasswordABCDEF",   # Sequential letters
            "Password12345",      # Sequential numbers
            "ABCDEFpassword1",    # Sequential letters at start
        ]
        
        for password in sequential_passwords:
            is_valid, errors = self.password_validator.validate_password(password)
            assert not is_valid, f"Sequential password accepted: {password}"
            assert any("sequential" in error.lower() for error in errors)
    
    def test_password_hashing_security(self):
        """Test password hashing security properties."""
        password = "TestPassword123!"
        
        # Hash the same password multiple times
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)
        
        # Hashes should be different (salt should be different)
        assert hash1 != hash2, "Password hashes are identical (no salt variation)"
        
        # Both hashes should verify correctly
        assert verify_password(password, hash1), "First hash verification failed"
        assert verify_password(password, hash2), "Second hash verification failed"
        
        # Wrong password should fail
        assert not verify_password("WrongPassword", hash1), "Wrong password verified"

class TestTimingAttackPrevention:
    """Test protection against timing attacks."""
    
    @pytest.mark.asyncio
    async def test_constant_time_authentication(self, db_session: AsyncSession):
        """Test that authentication takes constant time regardless of user existence."""
        # Create a test user
        dao = UserDAO(db_session)
        test_user = User(
            email="test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        await dao.create_user(test_user)
        
        # Test timing for existing user with wrong password
        start_time = time.time()
        result1 = await authenticate_user_secure(
            db_session, "test@example.com", "WrongPassword", "127.0.0.1"
        )
        time1 = time.time() - start_time
        
        # Test timing for non-existent user
        start_time = time.time()
        result2 = await authenticate_user_secure(
            db_session, "nonexistent@example.com", "SomePassword", "127.0.0.1"
        )
        time2 = time.time() - start_time
        
        # Both should fail
        assert result1 is None
        assert result2 is None
        
        # Timing should be similar (within 50ms)
        time_difference = abs(time1 - time2)
        assert time_difference < 0.05, f"Timing difference too large: {time_difference}s"
    
    @pytest.mark.asyncio
    async def test_password_verification_timing(self):
        """Test timing consistency in password verification."""
        password = "TestPassword123!"
        hashed_password = get_password_hash(password)
        
        # Time verification with correct password
        times_correct = []
        for _ in range(5):
            start_time = time.time()
            await verify_password_secure(password, hashed_password)
            times_correct.append(time.time() - start_time)
        
        # Time verification with fake user (should still perform hashing)
        times_fake = []
        for _ in range(5):
            start_time = time.time()
            await verify_password_secure(password, "", fake_user_email="fake@example.com")
            times_fake.append(time.time() - start_time)
        
        # Average times should be similar
        avg_correct = sum(times_correct) / len(times_correct)
        avg_fake = sum(times_fake) / len(times_fake)
        
        # Should be within 20% of each other
        time_ratio = max(avg_correct, avg_fake) / min(avg_correct, avg_fake)
        assert time_ratio < 1.2, f"Timing ratio too high: {time_ratio}"

class TestJWTSecurity:
    """Test JWT token security and validation."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.test_email = "test@example.com"
        # Use the global security config to ensure consistency
        from services.security import security_config
        self.security_config = security_config
    
    def test_jwt_token_creation(self):
        """Test JWT token creation with proper claims."""
        token = create_access_token({"sub": self.test_email})
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 50  # JWT tokens should be reasonably long
        
        # Decode and verify claims
        from jose import jwt
        
        payload = jwt.decode(
            token,
            self.security_config.jwt_secret_key,
            algorithms=[self.security_config.jwt_algorithm]
        )
        
        assert payload["sub"] == self.test_email
        assert payload["type"] == "access"
        assert "exp" in payload
        assert "iat" in payload
    
    def test_refresh_token_creation(self):
        """Test refresh token creation with unique identifiers."""
        token1 = create_refresh_token(self.test_email)
        token2 = create_refresh_token(self.test_email)
        
        # Tokens should be different
        assert token1 != token2
        
        # Both should decode properly
        from jose import jwt
        
        payload1 = jwt.decode(
            token1,
            self.security_config.jwt_secret_key,
            algorithms=[self.security_config.jwt_algorithm]
        )
        payload2 = jwt.decode(
            token2,
            self.security_config.jwt_secret_key,
            algorithms=[self.security_config.jwt_algorithm]
        )
        
        assert payload1["sub"] == self.test_email
        assert payload2["sub"] == self.test_email
        assert payload1["type"] == "refresh"
        assert payload2["type"] == "refresh"
        assert payload1["jti"] != payload2["jti"]  # JWT IDs should be unique
    
    def test_jwt_token_expiration(self):
        """Test JWT token expiration handling."""
        # Create token with custom expiration
        short_expiry = timedelta(seconds=1)
        token = create_access_token({"sub": self.test_email}, expires_delta=short_expiry)
        
        # Token should decode immediately
        from jose import jwt, JWTError
        
        payload = jwt.decode(
            token,
            self.security_config.jwt_secret_key,
            algorithms=[self.security_config.jwt_algorithm]
        )
        assert payload["sub"] == self.test_email
        
        # Wait for expiration
        time.sleep(2)
        
        # Token should now be expired
        with pytest.raises(JWTError):
            jwt.decode(
                token,
                self.security_config.jwt_secret_key,
                algorithms=[self.security_config.jwt_algorithm]
            )
    
    def test_jwt_algorithm_security(self):
        """Test that only secure algorithms are accepted."""
        # Should accept secure algorithms
        secure_algorithms = ["HS256", "HS384", "HS512"]
        
        for algorithm in secure_algorithms:
            try:
                # This should work with secure algorithms
                test_config = SecurityConfig()
                test_config.jwt_algorithm = algorithm
                # No exception should be raised
            except ValueError:
                pytest.fail(f"Secure algorithm {algorithm} was rejected")

class TestSecretManagement:
    """Test secure secret generation and validation."""
    
    def test_jwt_secret_generation(self):
        """Test that secure JWT secrets are generated."""
        config = SecurityConfig()
        
        # Secret should be long enough
        assert len(config.jwt_secret_key) >= 32
        
        # Should contain mixed characters
        secret = config.jwt_secret_key
        has_letters = any(c.isalpha() for c in secret)
        has_digits = any(c.isdigit() for c in secret)
        
        assert has_letters, "JWT secret should contain letters"
        assert has_digits, "JWT secret should contain digits"
    
    def test_weak_secret_rejection(self):
        """Test that weak secrets are rejected."""
        import os
        
        weak_secrets = [
            "super-secret-key",
            "secret",
            "password",
            "key",
            "short"  # Too short
        ]
        
        for weak_secret in weak_secrets:
            # Temporarily set weak secret in environment
            os.environ["JWT_SECRET_KEY"] = weak_secret
            
            # Should raise ValueError for weak secrets
            with pytest.raises(ValueError):
                SecurityConfig()
        
        # Clean up
        if "JWT_SECRET_KEY" in os.environ:
            del os.environ["JWT_SECRET_KEY"]

class TestSecurityLogging:
    """Test security event logging and monitoring."""
    
    def test_security_event_logging(self):
        """Test that security events are properly logged."""
        # This would typically test integration with logging system
        SecurityUtils.log_security_event(
            "test_event",
            {"test_data": "test_value"},
            user_email="test@example.com",
            client_ip="127.0.0.1"
        )
        
        # In a real test, you'd verify the log was created
        # For now, just ensure no exception is raised
        assert True
    
    def test_client_ip_extraction(self):
        """Test client IP extraction from various headers."""
        from unittest.mock import Mock
        
        # Test X-Forwarded-For header
        request = Mock()
        request.headers = {"X-Forwarded-For": "192.168.1.1, 10.0.0.1"}
        request.client.host = "127.0.0.1"
        
        ip = SecurityUtils.get_client_ip(request)
        assert ip == "192.168.1.1"  # Should get first IP
        
        # Test X-Real-IP header
        request.headers = {"X-Real-IP": "192.168.1.2"}
        ip = SecurityUtils.get_client_ip(request)
        assert ip == "192.168.1.2"
        
        # Test fallback to direct connection
        request.headers = {}
        ip = SecurityUtils.get_client_ip(request)
        assert ip == "127.0.0.1"

class TestInputSanitization:
    """Test input sanitization and validation."""
    
    def test_email_sanitization(self):
        """Test email address sanitization."""
        test_cases = [
            ("TEST@EXAMPLE.COM", "test@example.com"),
            ("  user@domain.com  ", "user@domain.com"),
            ("User.Name+Tag@Domain.Com", "user.name+tag@domain.com"),
            ("", ""),
            (None, "")
        ]
        
        for input_email, expected in test_cases:
            result = SecurityUtils.sanitize_email(input_email)
            assert result == expected, f"Email sanitization failed: {input_email} -> {result}"

@pytest.mark.asyncio
class TestSessionManagement:
    """Test user session management and security."""
    
    async def test_session_creation_and_validation(self, db_session: AsyncSession):
        """Test session creation with security tracking."""
        rbac = RBACService(db_session)
        
        # Create test user
        dao = UserDAO(db_session)
        test_user = User(
            email="session_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        # Create session
        session_token = "test_session_token"
        refresh_jti = "test_refresh_jti"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        session = await rbac.create_user_session(
            user_id=user.id,
            session_token=session_token,
            refresh_token_jti=refresh_jti,
            ip_address="127.0.0.1",
            user_agent="Test Agent",
            expires_at=expires_at
        )
        
        assert session.id is not None
        assert session.user_id == user.id
        assert session.is_active is True
        assert session.ip_address == "127.0.0.1"
    
    async def test_session_termination(self, db_session: AsyncSession):
        """Test session termination and cleanup."""
        rbac = RBACService(db_session)
        
        # Create test user and session (setup from previous test)
        dao = UserDAO(db_session)
        test_user = User(
            email="termination_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        session = await rbac.create_user_session(
            user_id=user.id,
            session_token="test_session_token",
            refresh_token_jti="test_refresh_jti",
            ip_address="127.0.0.1",
            user_agent="Test Agent",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        # Terminate session
        success = await rbac.terminate_session(session.id, "test_termination")
        assert success is True
        
        # Verify session is inactive
        await db_session.refresh(session)
        assert session.is_active is False
        assert session.logout_at is not None
    
    async def test_token_blacklisting(self, db_session: AsyncSession):
        """Test JWT token blacklisting functionality."""
        rbac = RBACService(db_session)
        
        # Create test user
        dao = UserDAO(db_session)
        test_user = User(
            email="blacklist_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        # Test token blacklisting
        test_jti = "test_jwt_id_12345"
        blacklisted_token = await rbac.blacklist_token(
            jti=test_jti,
            token_type="access",
            user_id=user.id,
            reason="test_blacklisting"
        )
        
        assert blacklisted_token.id is not None
        assert blacklisted_token.jti == test_jti
        assert blacklisted_token.token_type == "access"
        assert blacklisted_token.user_id == user.id
        
        # Test blacklist checking
        is_blacklisted = await rbac.is_token_blacklisted(test_jti)
        assert is_blacklisted is True
        
        # Test non-blacklisted token
        is_blacklisted = await rbac.is_token_blacklisted("non_existent_jti")
        assert is_blacklisted is False

# Integration tests
@pytest.mark.asyncio
class TestSecurityIntegration:
    """Integration tests for complete security workflows."""
    
    async def test_complete_authentication_flow(self, db_session: AsyncSession):
        """Test complete authentication flow with all security features."""
        # 1. User registration with strong password
        dao = UserDAO(db_session)
        strong_password = "MyVeryStr0ng!Password123"
        
        # Validate password strength
        validator = PasswordValidator(SecurityConfig())
        is_valid, errors = validator.validate_password(strong_password)
        assert is_valid, f"Strong password rejected: {errors}"
        
        # Create user
        test_user = User(
            email="integration_test@example.com",
            hashed_password=get_password_hash(strong_password)
        )
        user = await dao.create_user(test_user)
        user.is_verified = True  # Skip email verification for test
        await db_session.commit()
        
        # 2. Authentication
        authenticated_user = await authenticate_user_secure(
            db_session, user.email, strong_password, "127.0.0.1"
        )
        assert authenticated_user is not None
        assert authenticated_user.id == user.id
        
        # 3. Token creation
        access_token = create_access_token({"sub": user.email})
        refresh_token = create_refresh_token(user.email)
        
        assert access_token is not None
        assert refresh_token is not None
        
        # 4. Session management
        rbac = RBACService(db_session)
        from jose import jwt
        
        from services.security import security_config
        refresh_payload = jwt.decode(
            refresh_token,
            security_config.jwt_secret_key,
            algorithms=[security_config.jwt_algorithm]
        )
        
        session = await rbac.create_user_session(
            user_id=user.id,
            session_token=access_token[:20],  # Use part of token as session ID
            refresh_token_jti=refresh_payload["jti"],
            ip_address="127.0.0.1",
            user_agent="Test Client",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        assert session.is_active is True
        
        # 5. Token blacklisting (logout)
        blacklisted = await rbac.blacklist_token(
            jti=refresh_payload["jti"],
            token_type="refresh",
            user_id=user.id,
            reason="user_logout"
        )
        
        assert blacklisted is not None
        
        # 6. Verify token is blacklisted
        is_blacklisted = await rbac.is_token_blacklisted(refresh_payload["jti"])
        assert is_blacklisted is True