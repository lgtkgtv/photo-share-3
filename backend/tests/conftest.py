"""
Pytest configuration and fixtures for security testing.
Provides test database setup, user fixtures, and security test utilities.
"""
import pytest
import pytest_asyncio
import asyncio
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool
import os
import tempfile

from services.db import Base
from models.user import User
from models.role import Role, Permission, UserSession, SecurityEvent, BlacklistedToken
from dao.user_dao import UserDAO
from services.auth import get_password_hash

# Test database URL (in-memory SQLite for testing)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False
    )
    
    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Clean up
    await engine.dispose()

@pytest.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    async_session = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
        await session.rollback()

@pytest.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create a test user."""
    dao = UserDAO(db_session)
    
    test_user = User(
        email="testuser@example.com",
        hashed_password=get_password_hash("TestPassword123!"),
        is_verified=True,
        is_active=True,
        first_name="Test",
        last_name="User"
    )
    
    user = await dao.create_user(test_user)
    return user

@pytest.fixture
async def admin_user(db_session: AsyncSession) -> User:
    """Create an admin test user with admin permissions."""
    from services.rbac import RBACService
    
    dao = UserDAO(db_session)
    
    # Create admin user
    admin_user = User(
        email="admin@example.com",
        hashed_password=get_password_hash("AdminPassword123!"),
        is_verified=True,
        is_active=True,
        first_name="Admin",
        last_name="User"
    )
    
    user = await dao.create_user(admin_user)
    
    # Create admin permission and role
    admin_permission = Permission(
        name="admin:manage",
        resource="admin", 
        action="manage",
        description="Full administrative access"
    )
    
    admin_role = Role(
        name="ADMIN",
        display_name="Administrator",
        description="System administrator role",
        is_system_role=True,
        permissions=[admin_permission]
    )
    
    db_session.add(admin_permission)
    db_session.add(admin_role)
    await db_session.commit()
    
    # Assign admin role to user
    rbac = RBACService(db_session)
    await rbac.assign_role_to_user(user.id, admin_role.id, user.id)
    
    return user

@pytest.fixture
async def regular_user(db_session: AsyncSession) -> User:
    """Create a regular user with basic permissions."""
    from services.rbac import RBACService
    
    dao = UserDAO(db_session)
    
    # Create regular user
    regular_user = User(
        email="regular@example.com",
        hashed_password=get_password_hash("RegularPassword123!"),
        is_verified=True,
        is_active=True,
        first_name="Regular",
        last_name="User"
    )
    
    user = await dao.create_user(regular_user)
    
    # Create basic user permissions
    permissions = [
        Permission(name="user:read", resource="user", action="read"),
        Permission(name="user:update", resource="user", action="update"),
        Permission(name="photo:create", resource="photo", action="create"),
        Permission(name="photo:read", resource="photo", action="read"),
    ]
    
    user_role = Role(
        name="USER",
        display_name="Regular User",
        description="Standard user role",
        permissions=permissions
    )
    
    for perm in permissions:
        db_session.add(perm)
    db_session.add(user_role)
    await db_session.commit()
    
    # Assign user role
    rbac = RBACService(db_session)
    await rbac.assign_role_to_user(user.id, user_role.id, user.id)
    
    return user

@pytest.fixture
def mock_request():
    """Create a mock FastAPI request for testing."""
    from unittest.mock import Mock
    
    request = Mock()
    request.url.path = "/api/test"
    request.method = "GET"
    request.headers = {"user-agent": "Test Client/1.0"}
    request.client.host = "127.0.0.1"
    request.path_params = {}
    
    return request

@pytest.fixture
async def test_permissions(db_session: AsyncSession):
    """Create a set of test permissions."""
    permissions = [
        Permission(name="photo:create", resource="photo", action="create"),
        Permission(name="photo:read", resource="photo", action="read"),
        Permission(name="photo:update", resource="photo", action="update"),
        Permission(name="photo:delete", resource="photo", action="delete"),
        Permission(name="album:create", resource="album", action="create"),
        Permission(name="album:read", resource="album", action="read"),
        Permission(name="user:manage", resource="user", action="manage"),
        Permission(name="admin:manage", resource="admin", action="manage"),
    ]
    
    for perm in permissions:
        db_session.add(perm)
    
    await db_session.commit()
    
    return permissions

@pytest.fixture
async def test_roles(db_session: AsyncSession, test_permissions):
    """Create a set of test roles with permissions."""
    # Map permissions by name for easy access
    perm_map = {perm.name: perm for perm in test_permissions}
    
    roles = [
        Role(
            name="VIEWER",
            display_name="Viewer",
            description="Can view photos and albums",
            permissions=[perm_map["photo:read"], perm_map["album:read"]]
        ),
        Role(
            name="CREATOR", 
            display_name="Content Creator",
            description="Can create and manage own content",
            permissions=[
                perm_map["photo:create"], perm_map["photo:read"], 
                perm_map["photo:update"], perm_map["album:create"], 
                perm_map["album:read"]
            ]
        ),
        Role(
            name="MODERATOR",
            display_name="Content Moderator", 
            description="Can moderate all content",
            permissions=[
                perm_map["photo:read"], perm_map["photo:update"], perm_map["photo:delete"],
                perm_map["album:read"], perm_map["album:update"]
            ]
        ),
        Role(
            name="ADMIN",
            display_name="Administrator",
            description="Full system access",
            is_system_role=True,
            permissions=[perm_map["admin:manage"], perm_map["user:manage"]]
        )
    ]
    
    for role in roles:
        db_session.add(role)
    
    await db_session.commit()
    
    return roles

class SecurityTestUtils:
    """Utility class for security testing helpers."""
    
    @staticmethod
    async def create_user_with_permissions(db_session: AsyncSession, email: str, 
                                         permissions: list) -> User:
        """Create a user with specific permissions."""
        from services.rbac import RBACService
        
        dao = UserDAO(db_session)
        
        user = User(
            email=email,
            hashed_password=get_password_hash("TestPassword123!"),
            is_verified=True,
            is_active=True
        )
        user = await dao.create_user(user)
        
        # Create role with permissions
        role_name = f"TEST_ROLE_{user.id}"
        role = Role(
            name=role_name,
            display_name=f"Test Role for {email}",
            permissions=permissions
        )
        
        db_session.add(role)
        await db_session.commit()
        
        # Assign role to user
        rbac = RBACService(db_session)
        await rbac.assign_role_to_user(user.id, role.id, user.id)
        
        return user
    
    @staticmethod
    async def create_test_session(db_session: AsyncSession, user: User, 
                                ip_address: str = "127.0.0.1") -> UserSession:
        """Create a test user session."""
        from datetime import datetime, timezone, timedelta
        from services.rbac import RBACService
        
        rbac = RBACService(db_session)
        
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        session = await rbac.create_user_session(
            user_id=user.id,
            session_token=f"test_session_{user.id}",
            refresh_token_jti=f"test_refresh_{user.id}",
            ip_address=ip_address,
            user_agent="Test Client/1.0",
            expires_at=expires_at
        )
        
        return session
    
    @staticmethod
    def create_jwt_token(user_email: str, expires_minutes: int = 30) -> str:
        """Create a JWT token for testing."""
        from services.auth import create_access_token
        from datetime import timedelta
        
        return create_access_token(
            {"sub": user_email},
            expires_delta=timedelta(minutes=expires_minutes)
        )
    
    @staticmethod
    async def simulate_failed_logins(rate_limiter, client_key: str, count: int):
        """Simulate multiple failed login attempts."""
        for i in range(count):
            await rate_limiter.record_failed_login(client_key, f"user{i}@example.com")
    
    @staticmethod
    async def wait_for_rate_limit_reset(seconds: int = 1):
        """Wait for rate limit window to reset."""
        import asyncio
        await asyncio.sleep(seconds)

@pytest.fixture
def security_utils():
    """Provide security testing utilities."""
    return SecurityTestUtils

# Custom pytest markers for different test categories
pytest_plugins = ["pytest_asyncio"]

def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security tests"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance tests"
    )

# Environment setup for tests
@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Setup test environment variables."""
    os.environ["JWT_SECRET_KEY"] = "test_secret_key_for_testing_purposes_only_very_long_and_secure"
    os.environ["JWT_ALGORITHM"] = "HS256"
    os.environ["JWT_ACCESS_TOKEN_EXPIRE_MINUTES"] = "30"
    os.environ["PASSWORD_MIN_LENGTH"] = "8"  # Shorter for testing
    os.environ["RATE_LIMIT_LOGIN_ATTEMPTS_PER_HOUR"] = "5"
    os.environ["ACCOUNT_LOCKOUT_ATTEMPTS"] = "5"
    os.environ["ENABLE_SECURITY_HEADERS"] = "true"
    os.environ["ENABLE_CSRF_PROTECTION"] = "false"  # Disabled for API testing
    
    yield
    
    # Cleanup
    test_env_vars = [
        "JWT_SECRET_KEY", "JWT_ALGORITHM", "JWT_ACCESS_TOKEN_EXPIRE_MINUTES",
        "PASSWORD_MIN_LENGTH", "RATE_LIMIT_LOGIN_ATTEMPTS_PER_HOUR", 
        "ACCOUNT_LOCKOUT_ATTEMPTS", "ENABLE_SECURITY_HEADERS", "ENABLE_CSRF_PROTECTION"
    ]
    
    for var in test_env_vars:
        if var in os.environ:
            del os.environ[var]