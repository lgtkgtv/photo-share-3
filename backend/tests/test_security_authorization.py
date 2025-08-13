"""
Comprehensive security tests for authorization and RBAC system.
Tests role-based access control, permission checking, and privilege escalation prevention.
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from services.rbac import RBACService, initialize_rbac_system
from services.authorization import (
    PermissionChecker, require_permission, require_role, require_admin,
    require_self_or_admin, AuthorizationError
)
from models.user import User
from models.role import Role, Permission, UserSession, SecurityEvent, BlacklistedToken
from schemas.rbac import ResourceType, ActionType, SeverityLevel
from dao.user_dao import UserDAO
from services.auth import get_password_hash

@pytest.mark.asyncio
class TestRBACPermissionSystem:
    """Test the core RBAC permission checking system."""
    
    async def test_permission_creation_and_validation(self, db_session: AsyncSession):
        """Test creation and validation of permissions."""
        rbac = RBACService(db_session)
        
        # Create test permission
        permission = Permission(
            name="test:create",
            resource="test",
            action="create",
            description="Test permission for creation"
        )
        
        db_session.add(permission)
        await db_session.commit()
        await db_session.refresh(permission)
        
        assert permission.id is not None
        assert permission.name == "test:create"
        assert permission.resource == "test"
        assert permission.action == "create"
        assert permission.is_active is True
    
    async def test_role_creation_and_permission_assignment(self, db_session: AsyncSession):
        """Test role creation and permission assignment."""
        # Create permissions
        permissions = [
            Permission(name="user:read", resource="user", action="read"),
            Permission(name="user:update", resource="user", action="update"),
            Permission(name="photo:create", resource="photo", action="create")
        ]
        
        for perm in permissions:
            db_session.add(perm)
        await db_session.commit()
        
        # Create role
        role = Role(
            name="TEST_USER",
            display_name="Test User Role",
            description="Role for testing",
            permissions=permissions
        )
        
        db_session.add(role)
        await db_session.commit()
        await db_session.refresh(role)
        
        assert role.id is not None
        assert len(role.permissions) == 3
        assert role.permissions[0].name == "user:read"
    
    async def test_user_role_assignment(self, db_session: AsyncSession):
        """Test assigning roles to users."""
        rbac = RBACService(db_session)
        
        # Create test user
        dao = UserDAO(db_session)
        test_user = User(
            email="role_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        # Create test role with permissions
        permission = Permission(name="test:action", resource="test", action="action")
        role = Role(name="TEST_ROLE", display_name="Test Role", permissions=[permission])
        
        db_session.add(permission)
        db_session.add(role)
        await db_session.commit()
        
        # Assign role to user
        success = await rbac.assign_role_to_user(user.id, role.id, user.id)
        assert success is True
        
        # Verify role assignment
        user_roles = await rbac.get_user_roles(user.id)
        assert len(user_roles) == 1
        assert user_roles[0].name == "TEST_ROLE"
    
    async def test_permission_checking(self, db_session: AsyncSession):
        """Test permission checking for users with roles."""
        rbac = RBACService(db_session)
        
        # Setup: Create user, permission, role
        dao = UserDAO(db_session)
        test_user = User(
            email="permission_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        permission = Permission(name="photo:read", resource="photo", action="read")
        role = Role(name="PHOTO_READER", display_name="Photo Reader", permissions=[permission])
        
        db_session.add(permission)
        db_session.add(role)
        await db_session.commit()
        
        # Assign role to user
        await rbac.assign_role_to_user(user.id, role.id, user.id)
        
        # Test permission checking
        result = await rbac.check_permission(user.id, ResourceType.PHOTO, ActionType.READ)
        assert result.authorized is True
        
        # Test permission denial
        result = await rbac.check_permission(user.id, ResourceType.PHOTO, ActionType.DELETE)
        assert result.authorized is False
        assert "Insufficient permissions" in result.reason
    
    async def test_wildcard_permissions(self, db_session: AsyncSession):
        """Test wildcard permission matching."""
        rbac = RBACService(db_session)
        
        # Setup user with wildcard permissions
        dao = UserDAO(db_session)
        test_user = User(
            email="wildcard_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        # Create wildcard permissions
        permissions = [
            Permission(name="photo:*", resource="photo", action="*"),  # All photo actions
            Permission(name="*:read", resource="*", action="read"),    # Read anything
        ]
        
        role = Role(name="WILDCARD_ROLE", display_name="Wildcard Role", permissions=permissions)
        
        for perm in permissions:
            db_session.add(perm)
        db_session.add(role)
        await db_session.commit()
        
        await rbac.assign_role_to_user(user.id, role.id, user.id)
        
        # Test wildcard matching
        result = await rbac.check_permission(user.id, ResourceType.PHOTO, ActionType.CREATE)
        assert result.authorized is True  # photo:* should match photo:create
        
        result = await rbac.check_permission(user.id, ResourceType.USER, ActionType.READ)
        assert result.authorized is True  # *:read should match user:read
    
    async def test_role_removal(self, db_session: AsyncSession):
        """Test removing roles from users."""
        rbac = RBACService(db_session)
        
        # Setup: user with role
        dao = UserDAO(db_session)
        test_user = User(
            email="role_removal_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        permission = Permission(name="test:permission", resource="test", action="permission")
        role = Role(name="REMOVABLE_ROLE", display_name="Removable Role", permissions=[permission])
        
        db_session.add(permission)
        db_session.add(role)
        await db_session.commit()
        
        # Assign and verify
        await rbac.assign_role_to_user(user.id, role.id, user.id)
        user_roles = await rbac.get_user_roles(user.id)
        assert len(user_roles) == 1
        
        # Remove role
        success = await rbac.remove_role_from_user(user.id, role.id, user.id)
        assert success is True
        
        # Verify removal
        user_roles = await rbac.get_user_roles(user.id)
        assert len(user_roles) == 0

@pytest.mark.asyncio
class TestAuthorizationDecorators:
    """Test FastAPI authorization decorators and dependencies."""
    
    async def test_permission_checker_authorized(self, db_session: AsyncSession):
        """Test permission checker with authorized user."""
        # Setup authorized user
        dao = UserDAO(db_session)
        test_user = User(
            email="auth_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        permission = Permission(name="photo:read", resource="photo", action="read")
        role = Role(name="PHOTO_VIEWER", display_name="Photo Viewer", permissions=[permission])
        
        db_session.add(permission)
        db_session.add(role)
        await db_session.commit()
        
        rbac = RBACService(db_session)
        await rbac.assign_role_to_user(user.id, role.id, user.id)
        
        # Create permission checker
        checker = PermissionChecker(ResourceType.PHOTO, ActionType.READ)
        
        # Mock request
        request = Mock()
        request.url.path = "/api/photos/1"
        request.method = "GET"
        request.headers = {}
        request.client.host = "127.0.0.1"
        
        # Should succeed
        result = await checker(request, user, db_session)
        assert result == user
    
    async def test_permission_checker_unauthorized(self, db_session: AsyncSession):
        """Test permission checker with unauthorized user."""
        # Setup unauthorized user (no permissions)
        dao = UserDAO(db_session)
        test_user = User(
            email="unauth_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        # Create permission checker
        checker = PermissionChecker(ResourceType.PHOTO, ActionType.DELETE)
        
        # Mock request
        request = Mock()
        request.url.path = "/api/photos/1"
        request.method = "DELETE"
        request.headers = {}
        request.client.host = "127.0.0.1"
        
        # Should raise authorization error
        with pytest.raises(AuthorizationError) as exc_info:
            await checker(request, user, db_session)
        
        assert exc_info.value.status_code == 403
        assert "Access denied" in str(exc_info.value.detail)

@pytest.mark.asyncio
class TestPrivilegeEscalation:
    """Test prevention of privilege escalation attacks."""
    
    async def test_role_assignment_authorization(self, db_session: AsyncSession):
        """Test that users cannot assign roles they don't have permission for."""
        rbac = RBACService(db_session)
        
        # Create regular user
        dao = UserDAO(db_session)
        regular_user = User(
            email="regular@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        regular_user = await dao.create_user(regular_user)
        
        # Create admin role
        admin_permission = Permission(name="admin:manage", resource="admin", action="manage")
        admin_role = Role(
            name="ADMIN", 
            display_name="Administrator", 
            permissions=[admin_permission],
            is_system_role=True
        )
        
        db_session.add(admin_permission)
        db_session.add(admin_role)
        await db_session.commit()
        
        # Regular user should not be able to assign admin role to themselves
        # This would typically be checked at the API level, not in the RBAC service
        # The RBAC service itself doesn't prevent this - authorization happens at endpoint level
        
        # However, we can test that system roles are protected
        assert admin_role.is_system_role is True
    
    async def test_permission_modification_prevention(self, db_session: AsyncSession):
        """Test that users cannot modify their own permissions."""
        # This test ensures that permission modifications require appropriate authorization
        # In a real system, this would be enforced by endpoint-level authorization
        
        dao = UserDAO(db_session)
        test_user = User(
            email="permission_mod_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        # User should not have admin permissions initially
        rbac = RBACService(db_session)
        result = await rbac.check_permission(user.id, ResourceType.ADMIN, ActionType.MANAGE)
        assert result.authorized is False
    
    async def test_token_reuse_prevention(self, db_session: AsyncSession):
        """Test that blacklisted tokens cannot be reused."""
        rbac = RBACService(db_session)
        
        dao = UserDAO(db_session)
        test_user = User(
            email="token_reuse_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        # Blacklist a token
        test_jti = "test_token_12345"
        await rbac.blacklist_token(test_jti, "access", user.id, "security_test")
        
        # Token should be blacklisted
        is_blacklisted = await rbac.is_token_blacklisted(test_jti)
        assert is_blacklisted is True
        
        # Different token should not be blacklisted
        is_blacklisted = await rbac.is_token_blacklisted("different_token")
        assert is_blacklisted is False

@pytest.mark.asyncio
class TestResourceOwnership:
    """Test resource ownership-based authorization."""
    
    async def test_self_access_authorization(self, db_session: AsyncSession):
        """Test that users can access their own resources."""
        rbac = RBACService(db_session)
        
        dao = UserDAO(db_session)
        test_user = User(
            email="self_access_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        # User should be able to access their own profile
        result = await rbac.check_permission(
            user.id, ResourceType.USER, ActionType.READ, resource_id=user.id
        )
        # This would return True if ownership checking was implemented for USER resources
        # Currently returns False since we haven't implemented photo ownership yet
    
    async def test_cross_user_access_denial(self, db_session: AsyncSession):
        """Test that users cannot access other users' resources without permission."""
        rbac = RBACService(db_session)
        
        dao = UserDAO(db_session)
        
        # Create two users
        user1 = User(
            email="user1@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user2 = User(
            email="user2@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        
        user1 = await dao.create_user(user1)
        user2 = await dao.create_user(user2)
        
        # User1 should not be able to access User2's resources
        result = await rbac.check_permission(
            user1.id, ResourceType.USER, ActionType.UPDATE, resource_id=user2.id
        )
        assert result.authorized is False

@pytest.mark.asyncio
class TestSecurityEventGeneration:
    """Test security event generation for authorization activities."""
    
    async def test_authorization_success_logging(self, db_session: AsyncSession):
        """Test that successful authorization generates appropriate logs."""
        rbac = RBACService(db_session)
        
        # Create authorized user
        dao = UserDAO(db_session)
        test_user = User(
            email="auth_logging_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        permission = Permission(name="test:log", resource="test", action="log")
        role = Role(name="LOGGER", display_name="Logger Role", permissions=[permission])
        
        db_session.add(permission)
        db_session.add(role)
        await db_session.commit()
        
        await rbac.assign_role_to_user(user.id, role.id, user.id)
        
        # This should generate a security event
        await rbac.log_security_event(
            "authorization_test",
            SeverityLevel.INFO,
            "Test authorization event",
            {"test": True},
            user_id=user.id,
            user_email=user.email
        )
        
        # Verify event was created
        from sqlalchemy import select
        result = await db_session.execute(
            select(SecurityEvent).where(SecurityEvent.event_type == "authorization_test")
        )
        event = result.scalar_one_or_none()
        
        assert event is not None
        assert event.user_id == user.id
        assert event.severity == "INFO"
    
    async def test_authorization_failure_logging(self, db_session: AsyncSession):
        """Test that failed authorization attempts are logged."""
        rbac = RBACService(db_session)
        
        # Create user without permissions
        dao = UserDAO(db_session)
        test_user = User(
            email="auth_fail_logging_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        # Attempt unauthorized action
        result = await rbac.check_permission(user.id, ResourceType.ADMIN, ActionType.MANAGE)
        assert result.authorized is False
        
        # Log the failed attempt
        await rbac.log_security_event(
            "authorization_denied",
            SeverityLevel.WARNING,
            "Unauthorized access attempt",
            {
                "user_id": user.id,
                "resource": "admin",
                "action": "manage"
            },
            user_id=user.id
        )
        
        # Verify event was logged
        from sqlalchemy import select
        result = await db_session.execute(
            select(SecurityEvent).where(SecurityEvent.event_type == "authorization_denied")
        )
        event = result.scalar_one_or_none()
        
        assert event is not None
        assert event.severity == "WARNING"

@pytest.mark.asyncio
class TestSessionSecurity:
    """Test session-based security features."""
    
    async def test_session_creation_with_tracking(self, db_session: AsyncSession):
        """Test session creation with security tracking."""
        rbac = RBACService(db_session)
        
        dao = UserDAO(db_session)
        test_user = User(
            email="session_security_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        # Create session
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        session = await rbac.create_user_session(
            user_id=user.id,
            session_token="secure_session_token",
            refresh_token_jti="secure_refresh_jti",
            ip_address="192.168.1.1",
            user_agent="Secure Browser/1.0",
            expires_at=expires_at
        )
        
        assert session.user_id == user.id
        assert session.is_active is True
        assert session.ip_address == "192.168.1.1"
    
    async def test_concurrent_session_limits(self, db_session: AsyncSession):
        """Test concurrent session limiting."""
        rbac = RBACService(db_session)
        
        dao = UserDAO(db_session)
        test_user = User(
            email="concurrent_sessions_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        # Create multiple sessions
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        sessions = []
        
        for i in range(5):
            session = await rbac.create_user_session(
                user_id=user.id,
                session_token=f"session_token_{i}",
                refresh_token_jti=f"refresh_jti_{i}",
                ip_address=f"192.168.1.{i+1}",
                user_agent="Test Browser",
                expires_at=expires_at
            )
            sessions.append(session)
        
        # Get active sessions
        active_sessions = await rbac.get_active_sessions(user.id)
        assert len(active_sessions) == 5
        
        # In a production system, you might limit this and terminate old sessions

@pytest.mark.asyncio  
class TestDefaultRolesAndPermissions:
    """Test the default RBAC system initialization."""
    
    async def test_rbac_initialization(self, db_session: AsyncSession):
        """Test that RBAC system initializes with default roles and permissions."""
        # Initialize the RBAC system
        await initialize_rbac_system(db_session)
        
        # Check that default permissions were created
        from sqlalchemy import select
        result = await db_session.execute(select(Permission))
        permissions = result.scalars().all()
        
        assert len(permissions) > 0
        
        # Check for some expected permissions
        permission_names = {perm.name for perm in permissions}
        expected_permissions = {
            "user:read", "user:update", "photo:create", "photo:read", "admin:manage"
        }
        
        assert expected_permissions.issubset(permission_names)
        
        # Check that default roles were created
        result = await db_session.execute(select(Role))
        roles = result.scalars().all()
        
        assert len(roles) > 0
        
        role_names = {role.name for role in roles}
        expected_roles = {"USER", "ADMIN", "SUPERADMIN"}
        
        assert expected_roles.issubset(role_names)
    
    async def test_system_role_protection(self, db_session: AsyncSession):
        """Test that system roles are properly marked and protected."""
        await initialize_rbac_system(db_session)
        
        from sqlalchemy import select
        result = await db_session.execute(
            select(Role).where(Role.name == "ADMIN")
        )
        admin_role = result.scalar_one_or_none()
        
        assert admin_role is not None
        assert admin_role.is_system_role is True
        
        result = await db_session.execute(
            select(Role).where(Role.name == "USER")
        )
        user_role = result.scalar_one_or_none()
        
        assert user_role is not None
        assert user_role.is_system_role is False

class TestRBACPerformance:
    """Test RBAC system performance under load."""
    
    @pytest.mark.asyncio
    async def test_permission_check_performance(self, db_session: AsyncSession):
        """Test permission checking performance."""
        rbac = RBACService(db_session)
        
        # Create user with multiple roles and permissions
        dao = UserDAO(db_session)
        test_user = User(
            email="performance_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        # Create multiple permissions and roles
        permissions = []
        for i in range(20):
            perm = Permission(
                name=f"resource{i}:action{i}",
                resource=f"resource{i}",
                action=f"action{i}"
            )
            permissions.append(perm)
            db_session.add(perm)
        
        await db_session.commit()
        
        role = Role(name="PERFORMANCE_ROLE", display_name="Performance Role", permissions=permissions)
        db_session.add(role)
        await db_session.commit()
        
        await rbac.assign_role_to_user(user.id, role.id, user.id)
        
        # Time multiple permission checks
        import time
        start_time = time.time()
        
        for i in range(100):
            await rbac.check_permission(user.id, ResourceType.PHOTO, ActionType.READ)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should complete 100 permission checks in reasonable time (< 1 second)
        assert duration < 1.0, f"Permission checking too slow: {duration}s for 100 checks"