"""
Authorization decorators and dependencies for FastAPI endpoint protection.
Provides enterprise-grade authorization controls with RBAC integration.
"""
from functools import wraps
from typing import List, Optional, Callable, Any
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from models.user import User
from services.db import get_db
from services.rbac import RBACService
from services.auth import get_current_user
from services.security import SecurityUtils
from schemas.rbac import ResourceType, ActionType

logger = logging.getLogger(__name__)

class AuthorizationError(HTTPException):
    """Custom authorization error with security logging."""
    
    def __init__(self, detail: str, required_permissions: List[str] = None):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )
        self.required_permissions = required_permissions or []

class PermissionChecker:
    """
    Permission checker class for reusable authorization logic.
    """
    
    def __init__(self, resource: ResourceType, action: ActionType, 
                 allow_owner: bool = False, resource_id_param: Optional[str] = None):
        """
        Initialize permission checker.
        
        Args:
            resource: Resource type being protected
            action: Action being performed
            allow_owner: Whether resource owner has implicit access
            resource_id_param: Parameter name containing resource ID for ownership check
        """
        self.resource = resource
        self.action = action
        self.allow_owner = allow_owner
        self.resource_id_param = resource_id_param
    
    async def __call__(self, request: Request, current_user: User = Depends(get_current_user), 
                      db: AsyncSession = Depends(get_db)) -> User:
        """
        Check permissions and return user if authorized.
        """
        client_ip = SecurityUtils.get_client_ip(request)
        rbac = RBACService(db)
        
        # Extract resource ID if specified
        resource_id = None
        if self.resource_id_param and hasattr(request, 'path_params'):
            resource_id = request.path_params.get(self.resource_id_param)
            if resource_id:
                try:
                    resource_id = int(resource_id)
                except (ValueError, TypeError):
                    resource_id = None
        
        # Check permissions
        auth_result = await rbac.check_permission(
            current_user.id,
            self.resource,
            self.action,
            resource_id
        )
        
        if not auth_result.authorized:
            # Log authorization failure
            SecurityUtils.log_security_event(
                "authorization_denied",
                {
                    "user_id": current_user.id,
                    "resource": self.resource.value,
                    "action": self.action.value,
                    "resource_id": resource_id,
                    "endpoint": str(request.url.path),
                    "method": request.method,
                    "reason": auth_result.reason,
                    "required_permissions": auth_result.required_permissions
                },
                user_email=current_user.email,
                client_ip=client_ip
            )
            
            raise AuthorizationError(
                detail=f"Access denied: {auth_result.reason}",
                required_permissions=auth_result.required_permissions
            )
        
        # Log successful authorization
        SecurityUtils.log_security_event(
            "authorization_granted",
            {
                "user_id": current_user.id,
                "resource": self.resource.value,
                "action": self.action.value,
                "resource_id": resource_id,
                "endpoint": str(request.url.path),
                "method": request.method
            },
            user_email=current_user.email,
            client_ip=client_ip
        )
        
        return current_user

# Convenience functions for common permission patterns
def require_permission(resource: ResourceType, action: ActionType, 
                      allow_owner: bool = False, resource_id_param: Optional[str] = None):
    """
    Decorator factory for requiring specific permissions.
    
    Usage:
        @require_permission(ResourceType.PHOTO, ActionType.DELETE, resource_id_param="photo_id")
        async def delete_photo(photo_id: int, user: User = Depends(...)):
            # User is guaranteed to have photo:delete permission or own the photo
    """
    return Depends(PermissionChecker(resource, action, allow_owner, resource_id_param))

def require_role(role_names: List[str]):
    """
    Decorator factory for requiring specific roles.
    
    Usage:
        @require_role(["ADMIN", "MODERATOR"])
        async def admin_function(user: User = Depends(...)):
            # User is guaranteed to have one of the specified roles
    """
    async def role_checker(request: Request, current_user: User = Depends(get_current_user),
                          db: AsyncSession = Depends(get_db)) -> User:
        client_ip = SecurityUtils.get_client_ip(request)
        rbac = RBACService(db)
        
        # Get user roles
        user_roles = await rbac.get_user_roles(current_user.id)
        user_role_names = {role.name for role in user_roles}
        
        # Check if user has any of the required roles
        if not any(role in user_role_names for role in role_names):
            SecurityUtils.log_security_event(
                "role_authorization_denied",
                {
                    "user_id": current_user.id,
                    "required_roles": role_names,
                    "user_roles": list(user_role_names),
                    "endpoint": str(request.url.path),
                    "method": request.method
                },
                user_email=current_user.email,
                client_ip=client_ip
            )
            
            raise AuthorizationError(
                detail=f"Access denied: requires one of roles: {', '.join(role_names)}"
            )
        
        SecurityUtils.log_security_event(
            "role_authorization_granted",
            {
                "user_id": current_user.id,
                "granted_role": next(role for role in role_names if role in user_role_names),
                "endpoint": str(request.url.path),
                "method": request.method
            },
            user_email=current_user.email,
            client_ip=client_ip
        )
        
        return current_user
    
    return Depends(role_checker)

def require_admin():
    """
    Convenience function for requiring admin access.
    """
    return require_role(["ADMIN", "SUPERADMIN"])

def require_self_or_admin(user_id_param: str = "user_id"):
    """
    Require user to be accessing their own resource or be an admin.
    
    Usage:
        @require_self_or_admin("user_id")
        async def get_user_profile(user_id: int, user: User = Depends(...)):
            # User can access their own profile or be an admin
    """
    async def self_or_admin_checker(request: Request, current_user: User = Depends(get_current_user),
                                   db: AsyncSession = Depends(get_db)) -> User:
        client_ip = SecurityUtils.get_client_ip(request)
        
        # Extract user ID from path parameters
        target_user_id = request.path_params.get(user_id_param)
        if target_user_id:
            try:
                target_user_id = int(target_user_id)
            except (ValueError, TypeError):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid user ID"
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User ID required"
            )
        
        # Allow if user is accessing their own resource
        if current_user.id == target_user_id:
            return current_user
        
        # Check if user has admin privileges
        rbac = RBACService(db)
        user_roles = await rbac.get_user_roles(current_user.id)
        admin_roles = {"ADMIN", "SUPERADMIN"}
        
        if any(role.name in admin_roles for role in user_roles):
            SecurityUtils.log_security_event(
                "admin_access_granted",
                {
                    "admin_user_id": current_user.id,
                    "target_user_id": target_user_id,
                    "endpoint": str(request.url.path),
                    "method": request.method
                },
                user_email=current_user.email,
                client_ip=client_ip
            )
            return current_user
        
        # Access denied
        SecurityUtils.log_security_event(
            "self_or_admin_access_denied",
            {
                "user_id": current_user.id,
                "target_user_id": target_user_id,
                "endpoint": str(request.url.path),
                "method": request.method
            },
            user_email=current_user.email,
            client_ip=client_ip
        )
        
        raise AuthorizationError(
            detail="Access denied: can only access own resources or requires admin privileges"
        )
    
    return Depends(self_or_admin_checker)

class ConditionalPermissionChecker:
    """
    Advanced permission checker with conditional logic.
    """
    
    def __init__(self, conditions: List[Callable[[User, Request], bool]]):
        """
        Initialize with list of condition functions.
        User must satisfy at least one condition.
        """
        self.conditions = conditions
    
    async def __call__(self, request: Request, current_user: User = Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)) -> User:
        """
        Check if user satisfies any of the conditions.
        """
        client_ip = SecurityUtils.get_client_ip(request)
        
        for condition in self.conditions:
            try:
                if await condition(current_user, request, db):
                    return current_user
            except Exception as e:
                logger.warning(f"Condition check failed: {e}")
                continue
        
        # No conditions satisfied
        SecurityUtils.log_security_event(
            "conditional_authorization_denied",
            {
                "user_id": current_user.id,
                "endpoint": str(request.url.path),
                "method": request.method,
                "conditions_count": len(self.conditions)
            },
            user_email=current_user.email,
            client_ip=client_ip
        )
        
        raise AuthorizationError(
            detail="Access denied: insufficient privileges for this operation"
        )

def require_any_condition(*conditions: Callable[[User, Request, AsyncSession], bool]):
    """
    Require that user satisfies any of the given conditions.
    
    Usage:
        async def is_photo_owner(user: User, request: Request, db: AsyncSession) -> bool:
            photo_id = request.path_params.get("photo_id")
            # Check if user owns photo
            return await check_photo_ownership(user.id, photo_id, db)
        
        async def is_admin(user: User, request: Request, db: AsyncSession) -> bool:
            rbac = RBACService(db)
            roles = await rbac.get_user_roles(user.id)
            return any(role.name in ["ADMIN", "SUPERADMIN"] for role in roles)
        
        @require_any_condition(is_photo_owner, is_admin)
        async def delete_photo(photo_id: int, user: User = Depends(...)):
            # User can delete if they own the photo or are admin
    """
    return Depends(ConditionalPermissionChecker(list(conditions)))

# Token validation dependency
async def validate_token_not_blacklisted(request: Request, current_user: User = Depends(get_current_user),
                                       db: AsyncSession = Depends(get_db)) -> User:
    """
    Validate that the current token is not blacklisted.
    """
    try:
        # Extract JWT token from Authorization header
        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header"
            )
        
        token = auth_header[7:]  # Remove "Bearer " prefix
        
        # Decode token to get JTI (JWT ID)
        from jose import jwt
        from services.security import security_config
        
        payload = jwt.decode(token, security_config.jwt_secret_key, 
                           algorithms=[security_config.jwt_algorithm])
        jti = payload.get("jti")
        
        if jti:
            # Check if token is blacklisted
            rbac = RBACService(db)
            if await rbac.is_token_blacklisted(jti):
                client_ip = SecurityUtils.get_client_ip(request)
                SecurityUtils.log_security_event(
                    "blacklisted_token_usage_attempt",
                    {
                        "user_id": current_user.id,
                        "jti": jti[:8] + "...",  # Partial JTI for security
                        "endpoint": str(request.url.path),
                        "method": request.method
                    },
                    user_email=current_user.email,
                    client_ip=client_ip
                )
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )
        
        return current_user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating token blacklist: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token validation failed"
        )

# Combined authentication and authorization dependency
def require_auth_and_permission(resource: ResourceType, action: ActionType,
                               allow_owner: bool = False, resource_id_param: Optional[str] = None,
                               check_token_blacklist: bool = True):
    """
    Combined dependency that requires authentication, token validation, and specific permissions.
    
    This is the recommended way to protect endpoints in production.
    """
    async def combined_checker(request: Request, db: AsyncSession = Depends(get_db)) -> User:
        # First, get authenticated user
        user = await get_current_user(request, db)
        
        # Check token blacklist if enabled
        if check_token_blacklist:
            user = await validate_token_not_blacklisted(request, user, db)
        
        # Check permissions
        permission_checker = PermissionChecker(resource, action, allow_owner, resource_id_param)
        user = await permission_checker(request, user, db)
        
        return user
    
    return Depends(combined_checker)

# Endpoint protection examples and usage patterns:
"""
USAGE EXAMPLES:

# Basic permission check
@app.get("/photos/{photo_id}")
async def get_photo(photo_id: int, user: User = require_permission(ResourceType.PHOTO, ActionType.READ)):
    # User has photo:read permission
    pass

# Owner or admin access
@app.delete("/photos/{photo_id}")
async def delete_photo(photo_id: int, 
                      user: User = require_permission(ResourceType.PHOTO, ActionType.DELETE, 
                                                     allow_owner=True, resource_id_param="photo_id")):
    # User has photo:delete permission OR owns the photo
    pass

# Role-based access
@app.get("/admin/users")
async def list_all_users(user: User = require_admin()):
    # User has ADMIN or SUPERADMIN role
    pass

# Self or admin access
@app.get("/users/{user_id}/profile")
async def get_user_profile(user_id: int, user: User = require_self_or_admin("user_id")):
    # User can access their own profile or is an admin
    pass

# Combined authentication and authorization (RECOMMENDED)
@app.put("/photos/{photo_id}")
async def update_photo(photo_id: int, 
                      user: User = require_auth_and_permission(ResourceType.PHOTO, ActionType.UPDATE,
                                                              allow_owner=True, resource_id_param="photo_id")):
    # Complete security check: auth + token validation + permissions
    pass

# Complex conditional access
async def can_moderate_photo(user: User, request: Request, db: AsyncSession) -> bool:
    # Custom logic for photo moderation access
    rbac = RBACService(db)
    roles = await rbac.get_user_roles(user.id)
    return any(role.name in ["ADMIN", "MODERATOR"] for role in roles)

@app.post("/photos/{photo_id}/moderate")
async def moderate_photo(photo_id: int, user: User = require_any_condition(can_moderate_photo)):
    # User can moderate if they have appropriate role
    pass
"""