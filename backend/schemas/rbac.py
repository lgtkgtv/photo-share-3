"""
RBAC (Role-Based Access Control) Pydantic schemas for API request/response validation.
Defines data models for roles, permissions, and authorization operations.
"""
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

# Enums for validation
class ResourceType(str, Enum):
    """Resource types in the application."""
    USER = "user"
    PHOTO = "photo"
    ALBUM = "album"
    COMMENT = "comment"
    ADMIN = "admin"

class ActionType(str, Enum):
    """Action types for permissions."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    MANAGE = "manage"  # Full administrative control

class SeverityLevel(str, Enum):
    """Security event severity levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

# Permission schemas
class PermissionBase(BaseModel):
    """Base permission schema with common fields."""
    name: str = Field(..., min_length=1, max_length=100)
    resource: ResourceType
    action: ActionType
    description: Optional[str] = Field(None, max_length=500)
    is_active: bool = True

class PermissionCreate(PermissionBase):
    """Schema for creating new permissions."""
    pass

class PermissionUpdate(BaseModel):
    """Schema for updating permissions."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    is_active: Optional[bool] = None

class Permission(PermissionBase):
    """Permission response schema."""
    id: int
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True

# Role schemas
class RoleBase(BaseModel):
    """Base role schema with common fields."""
    name: str = Field(..., min_length=1, max_length=50, pattern="^[a-zA-Z0-9_-]+$")
    display_name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    is_active: bool = True

class RoleCreate(RoleBase):
    """Schema for creating new roles."""
    permission_ids: List[int] = Field(default_factory=list)
    
    @field_validator('name')
    def validate_role_name(cls, v):
        """Validate role name format."""
        if v.lower() in ['admin', 'superuser', 'root', 'system']:
            if not v.isupper():
                raise ValueError('System role names must be uppercase')
        return v

class RoleUpdate(BaseModel):
    """Schema for updating roles."""
    display_name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    is_active: Optional[bool] = None
    permission_ids: Optional[List[int]] = None

class Role(RoleBase):
    """Role response schema."""
    id: int
    is_system_role: bool
    parent_role_id: Optional[int]
    created_at: datetime
    updated_at: Optional[datetime]
    created_by: Optional[int]
    permissions: List[Permission] = []
    
    class Config:
        from_attributes = True

# User role assignment schemas
class UserRoleAssignment(BaseModel):
    """Schema for assigning roles to users."""
    user_id: int = Field(..., gt=0)
    role_id: int = Field(..., gt=0)

class UserRoleAssignmentResponse(BaseModel):
    """Response schema for user role assignments."""
    user_id: int
    role_id: int
    assigned_at: datetime
    assigned_by: Optional[int]
    
    class Config:
        from_attributes = True

# Session management schemas
class UserSessionBase(BaseModel):
    """Base user session schema."""
    ip_address: Optional[str] = Field(None, max_length=45)
    user_agent: Optional[str] = Field(None, max_length=500)
    location: Optional[str] = Field(None, max_length=100)

class UserSession(UserSessionBase):
    """User session response schema."""
    id: int
    user_id: int
    session_token: str
    is_active: bool
    login_at: datetime
    last_activity_at: datetime
    logout_at: Optional[datetime]
    expires_at: datetime
    is_suspicious: bool
    login_method: str
    
    class Config:
        from_attributes = True

class SessionTerminate(BaseModel):
    """Schema for terminating user sessions."""
    session_id: int = Field(..., gt=0)
    reason: str = Field(..., min_length=1, max_length=100)

# Security event schemas
class SecurityEventBase(BaseModel):
    """Base security event schema."""
    event_type: str = Field(..., min_length=1, max_length=100)
    severity: SeverityLevel = SeverityLevel.INFO
    message: str = Field(..., min_length=1, max_length=1000)
    details: Optional[Dict[str, Any]] = None

class SecurityEventCreate(SecurityEventBase):
    """Schema for creating security events."""
    user_id: Optional[int] = None
    user_email: Optional[str] = None
    session_id: Optional[int] = None
    ip_address: Optional[str] = Field(None, max_length=45)
    user_agent: Optional[str] = Field(None, max_length=500)
    endpoint: Optional[str] = Field(None, max_length=255)
    http_method: Optional[str] = Field(None, max_length=10)

class SecurityEvent(SecurityEventBase):
    """Security event response schema."""
    id: int
    user_id: Optional[int]
    user_email: Optional[str]
    session_id: Optional[int]
    ip_address: Optional[str]
    user_agent: Optional[str]
    endpoint: Optional[str]
    http_method: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True

# Token blacklisting schemas
class TokenBlacklistRequest(BaseModel):
    """Schema for blacklisting tokens."""
    token: str = Field(..., min_length=1)
    reason: str = Field(default="manual_logout", max_length=100)

class BlacklistedToken(BaseModel):
    """Blacklisted token response schema."""
    id: int
    jti: str
    token_type: str
    user_id: int
    reason: str
    expires_at: datetime
    created_at: datetime
    
    class Config:
        from_attributes = True

# Authorization check schemas
class AuthorizationCheck(BaseModel):
    """Schema for checking user permissions."""
    resource: ResourceType
    action: ActionType
    resource_id: Optional[int] = None

class AuthorizationResult(BaseModel):
    """Result of authorization check."""
    authorized: bool
    reason: Optional[str] = None
    required_permissions: List[str] = []

# Enhanced user schema with RBAC
class UserWithRoles(BaseModel):
    """User schema including role and permission information."""
    id: int
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login_at: Optional[datetime]
    roles: List[Role] = []
    permissions: List[str] = []  # Computed permissions from all roles
    
    class Config:
        from_attributes = True

# Admin dashboard schemas
class SecurityDashboard(BaseModel):
    """Security dashboard data schema."""
    active_sessions: int
    failed_logins_today: int
    security_events_today: int
    blacklisted_tokens: int
    locked_accounts: int
    recent_events: List[SecurityEvent] = []

class RoleManagement(BaseModel):
    """Role management dashboard schema."""
    total_roles: int
    system_roles: int
    custom_roles: int
    total_permissions: int
    role_assignments: int
    recent_changes: List[Dict[str, Any]] = []

# Bulk operations schemas
class BulkRoleAssignment(BaseModel):
    """Schema for bulk role assignments."""
    user_ids: List[int] = Field(..., min_length=1, max_length=100)
    role_id: int = Field(..., gt=0)

class BulkRoleAssignmentResult(BaseModel):
    """Result of bulk role assignment."""
    successful_assignments: int
    failed_assignments: int
    errors: List[str] = []