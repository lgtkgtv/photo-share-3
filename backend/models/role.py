"""
Role-Based Access Control (RBAC) database models.
Implements enterprise-grade authorization with roles, permissions, and user associations.
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Table
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from services.db import Base

# Association table for many-to-many relationship between roles and permissions
role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True),
    Column('created_at', DateTime(timezone=True), server_default=func.now())
)

# Association table for many-to-many relationship between users and roles
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('assigned_at', DateTime(timezone=True), server_default=func.now()),
    Column('assigned_by', Integer, ForeignKey('users.id'), nullable=True)  # Who assigned this role
)

class Role(Base):
    """
    Role model for RBAC system.
    Represents a collection of permissions that can be assigned to users.
    """
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    display_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_system_role = Column(Boolean, default=False, nullable=False)  # Prevents deletion of critical roles
    
    # Hierarchy support (future enhancement)
    parent_role_id = Column(Integer, ForeignKey('roles.id'), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    
    # Relationships
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")
    users = relationship("User", secondary=user_roles, back_populates="roles")
    parent_role = relationship("Role", remote_side=[id])
    child_roles = relationship("Role", remote_side=[parent_role_id])
    
    def __repr__(self):
        return f"<Role(name='{self.name}', display_name='{self.display_name}')>"

class Permission(Base):
    """
    Permission model for RBAC system.
    Represents specific actions or access rights within the application.
    """
    __tablename__ = "permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    resource = Column(String(50), nullable=False, index=True)  # e.g., 'user', 'photo', 'album'
    action = Column(String(50), nullable=False, index=True)    # e.g., 'create', 'read', 'update', 'delete'
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")
    
    def __repr__(self):
        return f"<Permission(name='{self.name}', resource='{self.resource}', action='{self.action}')>"

class UserSession(Base):
    """
    User session tracking for enhanced security.
    Tracks active sessions, login history, and enables session management.
    """
    __tablename__ = "user_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    refresh_token_jti = Column(String(255), unique=True, nullable=True, index=True)  # JWT ID for refresh tokens
    
    # Session metadata
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(String(500), nullable=True)
    device_fingerprint = Column(String(255), nullable=True)
    location = Column(String(100), nullable=True)  # City, Country
    
    # Session state
    is_active = Column(Boolean, default=True, nullable=False)
    login_at = Column(DateTime(timezone=True), server_default=func.now())
    last_activity_at = Column(DateTime(timezone=True), server_default=func.now())
    logout_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    
    # Security flags
    is_suspicious = Column(Boolean, default=False, nullable=False)
    login_method = Column(String(50), default='password')  # 'password', 'oauth', 'mfa'
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def __repr__(self):
        return f"<UserSession(user_id={self.user_id}, ip='{self.ip_address}', active={self.is_active})>"

class SecurityEvent(Base):
    """
    Security event logging for audit trails and threat detection.
    Stores structured security events for monitoring and analysis.
    """
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), default='INFO', index=True)  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    
    # Event context
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    user_email = Column(String(255), nullable=True, index=True)
    session_id = Column(Integer, ForeignKey('user_sessions.id'), nullable=True)
    
    # Request context
    ip_address = Column(String(45), nullable=True, index=True)
    user_agent = Column(String(500), nullable=True)
    endpoint = Column(String(255), nullable=True)
    http_method = Column(String(10), nullable=True)
    
    # Event data
    message = Column(Text, nullable=False)
    details = Column(Text, nullable=True)  # JSON string with additional details
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    # Relationships
    user = relationship("User")
    session = relationship("UserSession")
    
    def __repr__(self):
        return f"<SecurityEvent(type='{self.event_type}', severity='{self.severity}', user_id={self.user_id})>"

class BlacklistedToken(Base):
    """
    Token blacklisting for secure logout and token revocation.
    Prevents use of revoked JWT tokens before their natural expiration.
    """
    __tablename__ = "blacklisted_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(255), unique=True, nullable=False, index=True)  # JWT ID
    token_type = Column(String(20), nullable=False)  # 'access' or 'refresh'
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    
    # Blacklisting context
    reason = Column(String(100), default='manual_logout')  # 'manual_logout', 'security_breach', 'admin_action'
    blacklisted_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    
    # Token metadata
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    blacklisted_by_user = relationship("User", foreign_keys=[blacklisted_by])
    
    def __repr__(self):
        return f"<BlacklistedToken(jti='{self.jti}', type='{self.token_type}', user_id={self.user_id})>"