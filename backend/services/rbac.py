"""
Role-Based Access Control (RBAC) service layer.
Provides enterprise-grade authorization logic for scalable permission management.
"""
import json
from typing import List, Optional, Set, Dict, Any, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import logging

from models.user import User
from models.role import Role, Permission, UserSession, SecurityEvent, BlacklistedToken, user_roles, role_permissions
from schemas.rbac import AuthorizationResult, ResourceType, ActionType, SeverityLevel
from services.security import SecurityUtils

logger = logging.getLogger(__name__)

class RBACService:
    """
    Enterprise RBAC service providing comprehensive authorization management.
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    # ==========================================
    # USER AUTHORIZATION METHODS
    # ==========================================
    
    async def check_permission(self, user_id: int, resource: ResourceType, action: ActionType, 
                             resource_id: Optional[int] = None) -> AuthorizationResult:
        """
        Check if user has permission to perform action on resource.
        
        Args:
            user_id: ID of user requesting access
            resource: Type of resource being accessed
            action: Action being performed
            resource_id: Specific resource ID (for ownership checks)
            
        Returns:
            AuthorizationResult with authorization decision and details
        """
        try:
            # Get user with roles and permissions
            user_permissions = await self.get_user_permissions(user_id)
            
            # Check for direct permission match
            required_permission = f"{resource.value}:{action.value}"
            
            if required_permission in user_permissions:
                return AuthorizationResult(authorized=True)
            
            # Check for wildcard permissions
            wildcard_permissions = [
                f"{resource.value}:*",  # All actions on this resource
                f"*:{action.value}",    # This action on all resources  
                "*:*"                   # Super admin permission
            ]
            
            for wildcard in wildcard_permissions:
                if wildcard in user_permissions:
                    return AuthorizationResult(authorized=True)
            
            # Check resource ownership (if applicable)
            if resource_id and await self.check_resource_ownership(user_id, resource, resource_id):
                # Owner has implicit read/update permissions
                if action in [ActionType.READ, ActionType.UPDATE]:
                    return AuthorizationResult(
                        authorized=True,
                        reason="Resource ownership"
                    )
            
            # Authorization denied
            return AuthorizationResult(
                authorized=False,
                reason="Insufficient permissions",
                required_permissions=[required_permission]
            )
            
        except Exception as e:
            logger.error(f"Error checking permission for user {user_id}: {e}")
            return AuthorizationResult(
                authorized=False,
                reason="Authorization check failed"
            )
    
    async def get_user_permissions(self, user_id: int) -> Set[str]:
        """
        Get all permissions for a user across all their roles.
        
        Returns:
            Set of permission strings in format "resource:action"
        """
        # Query user with roles and permissions
        result = await self.db.execute(
            select(User)
            .options(
                selectinload(User.roles)
                .selectinload(Role.permissions)
            )
            .where(and_(User.id == user_id, User.is_active == True))
        )
        
        user = result.scalar_one_or_none()
        if not user:
            return set()
        
        permissions = set()
        
        for role in user.roles:
            if role.is_active:
                for permission in role.permissions:
                    if permission.is_active:
                        perm_string = f"{permission.resource}:{permission.action}"
                        permissions.add(perm_string)
        
        return permissions
    
    async def check_resource_ownership(self, user_id: int, resource: ResourceType, resource_id: int) -> bool:
        """
        Check if user owns the specified resource.
        """
        # For now, users own their own profile
        if resource == ResourceType.USER and resource_id == user_id:
            return True
        
        # Photo ownership check
        if resource == ResourceType.PHOTO:
            from models.photo import Photo
            photo = await self.db.get(Photo, resource_id)
            return photo and photo.owner_id == user_id
        
        # Album ownership check
        if resource == ResourceType.ALBUM:
            from models.photo import Album
            album = await self.db.get(Album, resource_id)
            return album and album.owner_id == user_id
        
        return False
    
    async def check_photo_access(self, user_id: int, photo_id: int, action: ActionType = ActionType.READ) -> AuthorizationResult:
        """
        Comprehensive photo access checking including sharing permissions.
        
        Args:
            user_id: ID of user requesting access
            photo_id: ID of photo being accessed
            action: Action being performed (read, update, delete, etc.)
            
        Returns:
            AuthorizationResult with detailed access decision
        """
        try:
            from models.photo import Photo, PhotoShare, ShareType
            
            # Get photo with relationships
            result = await self.db.execute(
                select(Photo)
                .where(and_(Photo.id == photo_id, Photo.deleted_at.is_(None)))
            )
            photo = result.scalar_one_or_none()
            
            if not photo:
                return AuthorizationResult(
                    authorized=False,
                    reason="Photo not found or deleted"
                )
            
            # Owner always has full access (unless explicitly revoked by admin)
            if photo.owner_id == user_id:
                return AuthorizationResult(
                    authorized=True,
                    reason="Photo owner"
                )
            
            # Check global admin permissions
            global_permission = await self.check_permission(user_id, ResourceType.PHOTO, action)
            if global_permission.authorized:
                return global_permission
            
            # For non-owners, check photo sharing rules
            if action == ActionType.READ:
                # Public photos are readable by all authenticated users
                if photo.share_type == ShareType.PUBLIC:
                    return AuthorizationResult(
                        authorized=True,
                        reason="Public photo"
                    )
                
                # Check for specific photo shares
                share_result = await self.db.execute(
                    select(PhotoShare)
                    .where(and_(
                        PhotoShare.photo_id == photo_id,
                        PhotoShare.shared_with_user_id == user_id,
                        PhotoShare.can_view == True,
                        or_(
                            PhotoShare.expires_at.is_(None),
                            PhotoShare.expires_at > datetime.now(timezone.utc)
                        )
                    ))
                )
                photo_share = share_result.scalar_one_or_none()
                
                if photo_share and not photo_share.is_expired and not photo_share.is_view_limit_exceeded:
                    return AuthorizationResult(
                        authorized=True,
                        reason="Photo shared with user"
                    )
            
            # For other actions, check specific share permissions
            elif action in [ActionType.UPDATE, ActionType.DELETE]:
                share_result = await self.db.execute(
                    select(PhotoShare)
                    .where(and_(
                        PhotoShare.photo_id == photo_id,
                        PhotoShare.shared_with_user_id == user_id
                    ))
                )
                photo_share = share_result.scalar_one_or_none()
                
                if photo_share:
                    # Check if share allows the requested action
                    if action == ActionType.UPDATE and hasattr(photo_share, 'can_edit'):
                        # This would require adding can_edit field to PhotoShare model
                        pass
                    elif action == ActionType.DELETE and hasattr(photo_share, 'can_delete'):
                        # This would require adding can_delete field to PhotoShare model
                        pass
            
            return AuthorizationResult(
                authorized=False,
                reason="No access permissions for this photo"
            )
            
        except Exception as e:
            logger.error(f"Error checking photo access for user {user_id}, photo {photo_id}: {e}")
            return AuthorizationResult(
                authorized=False,
                reason="Photo access check failed"
            )
    
    async def check_album_access(self, user_id: int, album_id: int, action: ActionType = ActionType.READ) -> AuthorizationResult:
        """
        Comprehensive album access checking including sharing permissions.
        
        Args:
            user_id: ID of user requesting access
            album_id: ID of album being accessed
            action: Action being performed
            
        Returns:
            AuthorizationResult with detailed access decision
        """
        try:
            from models.photo import Album, AlbumShare, AlbumType
            
            # Get album
            result = await self.db.execute(
                select(Album)
                .where(and_(Album.id == album_id, Album.deleted_at.is_(None)))
            )
            album = result.scalar_one_or_none()
            
            if not album:
                return AuthorizationResult(
                    authorized=False,
                    reason="Album not found or deleted"
                )
            
            # Owner always has full access
            if album.owner_id == user_id:
                return AuthorizationResult(
                    authorized=True,
                    reason="Album owner"
                )
            
            # Check global admin permissions
            global_permission = await self.check_permission(user_id, ResourceType.ALBUM, action)
            if global_permission.authorized:
                return global_permission
            
            # For non-owners, check album sharing rules
            if action == ActionType.READ:
                # Public albums are readable by all authenticated users
                if album.is_public:
                    return AuthorizationResult(
                        authorized=True,
                        reason="Public album"
                    )
                
                # Check for specific album shares
                share_result = await self.db.execute(
                    select(AlbumShare)
                    .where(and_(
                        AlbumShare.album_id == album_id,
                        AlbumShare.shared_with_user_id == user_id,
                        AlbumShare.can_view == True,
                        or_(
                            AlbumShare.expires_at.is_(None),
                            AlbumShare.expires_at > datetime.now(timezone.utc)
                        )
                    ))
                )
                album_share = share_result.scalar_one_or_none()
                
                if album_share:
                    return AuthorizationResult(
                        authorized=True,
                        reason="Album shared with user"
                    )
            
            # For other actions, check specific share permissions
            elif action in [ActionType.UPDATE, ActionType.DELETE]:
                share_result = await self.db.execute(
                    select(AlbumShare)
                    .where(and_(
                        AlbumShare.album_id == album_id,
                        AlbumShare.shared_with_user_id == user_id
                    ))
                )
                album_share = share_result.scalar_one_or_none()
                
                if album_share:
                    if action == ActionType.UPDATE and album_share.can_edit_album:
                        return AuthorizationResult(
                            authorized=True,
                            reason="Album edit permission granted"
                        )
            
            return AuthorizationResult(
                authorized=False,
                reason="No access permissions for this album"
            )
            
        except Exception as e:
            logger.error(f"Error checking album access for user {user_id}, album {album_id}: {e}")
            return AuthorizationResult(
                authorized=False,
                reason="Album access check failed"
            )
    
    # ==========================================
    # ROLE MANAGEMENT METHODS
    # ==========================================
    
    async def assign_role_to_user(self, user_id: int, role_id: int, assigned_by: int) -> bool:
        """
        Assign role to user with audit logging.
        """
        try:
            # Verify user and role exist and are active
            user = await self.db.get(User, user_id)
            role = await self.db.get(Role, role_id)
            
            if not user or not user.is_active:
                await self._log_security_event(
                    "role_assignment_failed",
                    SeverityLevel.WARNING,
                    f"Attempted to assign role to non-existent or inactive user {user_id}",
                    {"user_id": user_id, "role_id": role_id, "assigned_by": assigned_by}
                )
                return False
            
            if not role or not role.is_active:
                await self._log_security_event(
                    "role_assignment_failed", 
                    SeverityLevel.WARNING,
                    f"Attempted to assign non-existent or inactive role {role_id}",
                    {"user_id": user_id, "role_id": role_id, "assigned_by": assigned_by}
                )
                return False
            
            # Check if role already assigned
            existing = await self.db.execute(
                select(user_roles)
                .where(and_(
                    user_roles.c.user_id == user_id,
                    user_roles.c.role_id == role_id
                ))
            )
            
            if existing.first():
                return True  # Already assigned
            
            # Assign role
            await self.db.execute(
                user_roles.insert().values(
                    user_id=user_id,
                    role_id=role_id,
                    assigned_by_user_id=assigned_by
                )
            )
            await self.db.commit()
            
            await self._log_security_event(
                "role_assigned",
                SeverityLevel.INFO,
                f"Role '{role.name}' assigned to user {user.email}",
                {
                    "user_id": user_id,
                    "user_email": user.email,
                    "role_id": role_id,
                    "role_name": role.name,
                    "assigned_by": assigned_by
                }
            )
            
            return True
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error assigning role {role_id} to user {user_id}: {e}")
            return False
    
    async def remove_role_from_user(self, user_id: int, role_id: int, removed_by: int) -> bool:
        """
        Remove role from user with audit logging.
        """
        try:
            # Verify assignment exists
            result = await self.db.execute(
                select(user_roles)
                .where(and_(
                    user_roles.c.user_id == user_id,
                    user_roles.c.role_id == role_id
                ))
            )
            
            if not result.first():
                return False  # Role not assigned
            
            # Get user and role for logging
            user = await self.db.get(User, user_id)
            role = await self.db.get(Role, role_id)
            
            # Remove role assignment
            await self.db.execute(
                user_roles.delete().where(and_(
                    user_roles.c.user_id == user_id,
                    user_roles.c.role_id == role_id
                ))
            )
            await self.db.commit()
            
            await self._log_security_event(
                "role_removed",
                SeverityLevel.INFO,
                f"Role '{role.name}' removed from user {user.email}",
                {
                    "user_id": user_id,
                    "user_email": user.email,
                    "role_id": role_id,
                    "role_name": role.name,
                    "removed_by": removed_by
                }
            )
            
            return True
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error removing role {role_id} from user {user_id}: {e}")
            return False
    
    async def get_user_roles(self, user_id: int) -> List[Role]:
        """
        Get all active roles assigned to a user.
        """
        result = await self.db.execute(
            select(Role)
            .join(user_roles)
            .where(and_(
                user_roles.c.user_id == user_id,
                Role.is_active == True
            ))
        )
        
        return result.scalars().all()
    
    # ==========================================
    # SESSION MANAGEMENT METHODS
    # ==========================================
    
    async def create_user_session(self, user_id: int, session_token: str, refresh_token_jti: str,
                                ip_address: str, user_agent: str, expires_at: datetime) -> UserSession:
        """
        Create new user session with security tracking.
        """
        session = UserSession(
            user_id=user_id,
            session_token=session_token,
            refresh_token_jti=refresh_token_jti,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at
        )
        
        # Check for suspicious activity
        session.is_suspicious = await self._detect_suspicious_login(user_id, ip_address, user_agent)
        
        self.db.add(session)
        await self.db.commit()
        await self.db.refresh(session)
        
        await self._log_security_event(
            "user_session_created",
            SeverityLevel.INFO,
            f"New session created for user {user_id}",
            {
                "user_id": user_id,
                "session_id": session.id,
                "ip_address": ip_address,
                "is_suspicious": session.is_suspicious
            }
        )
        
        return session
    
    async def terminate_session(self, session_id: int, reason: str = "manual_logout") -> bool:
        """
        Terminate user session and blacklist associated tokens.
        """
        try:
            session = await self.db.get(UserSession, session_id)
            if not session or not session.is_active:
                return False
            
            # Mark session as inactive
            session.is_active = False
            session.logout_at = datetime.now(timezone.utc)
            
            # Blacklist refresh token if exists
            if session.refresh_token_jti:
                await self.blacklist_token(
                    session.refresh_token_jti,
                    "refresh",
                    session.user_id,
                    reason
                )
            
            await self.db.commit()
            
            await self._log_security_event(
                "user_session_terminated",
                SeverityLevel.INFO,
                f"Session {session_id} terminated: {reason}",
                {
                    "user_id": session.user_id,
                    "session_id": session_id,
                    "reason": reason
                }
            )
            
            return True
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error terminating session {session_id}: {e}")
            return False
    
    async def get_active_sessions(self, user_id: int) -> List[UserSession]:
        """
        Get all active sessions for a user.
        """
        result = await self.db.execute(
            select(UserSession)
            .where(and_(
                UserSession.user_id == user_id,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.now(timezone.utc)
            ))
        )
        
        return result.scalars().all()
    
    # ==========================================
    # TOKEN BLACKLISTING METHODS
    # ==========================================
    
    async def blacklist_token(self, jti: str, token_type: str, user_id: int, 
                            reason: str = "manual_logout") -> BlacklistedToken:
        """
        Add token to blacklist to prevent further use.
        """
        # Calculate expiration based on token type
        if token_type == "access":
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)  # Max access token life
        else:  # refresh
            expires_at = datetime.now(timezone.utc) + timedelta(days=7)   # Max refresh token life
        
        blacklisted_token = BlacklistedToken(
            jti=jti,
            token_type=token_type,
            user_id=user_id,
            reason=reason,
            expires_at=expires_at
        )
        
        self.db.add(blacklisted_token)
        await self.db.commit()
        await self.db.refresh(blacklisted_token)
        
        await self._log_security_event(
            "token_blacklisted",
            SeverityLevel.INFO,
            f"{token_type.title()} token blacklisted: {reason}",
            {
                "user_id": user_id,
                "token_type": token_type,
                "reason": reason,
                "jti": jti[:8] + "..."  # Partial JTI for logging
            }
        )
        
        return blacklisted_token
    
    async def is_token_blacklisted(self, jti: str) -> bool:
        """
        Check if token is blacklisted.
        """
        result = await self.db.execute(
            select(BlacklistedToken)
            .where(and_(
                BlacklistedToken.jti == jti,
                BlacklistedToken.expires_at > datetime.now(timezone.utc)
            ))
        )
        
        return result.scalar_one_or_none() is not None
    
    # ==========================================
    # SECURITY EVENT METHODS
    # ==========================================
    
    async def log_security_event(self, event_type: str, severity: SeverityLevel, message: str,
                                details: Dict[str, Any], user_id: Optional[int] = None,
                                user_email: Optional[str] = None, ip_address: Optional[str] = None,
                                user_agent: Optional[str] = None, endpoint: Optional[str] = None,
                                http_method: Optional[str] = None) -> SecurityEvent:
        """
        Log security event with structured data.
        """
        return await self._log_security_event(
            event_type, severity, message, details, user_id, user_email,
            ip_address, user_agent, endpoint, http_method
        )
    
    async def _log_security_event(self, event_type: str, severity: SeverityLevel, message: str,
                                 details: Dict[str, Any], user_id: Optional[int] = None,
                                 user_email: Optional[str] = None, ip_address: Optional[str] = None,
                                 user_agent: Optional[str] = None, endpoint: Optional[str] = None,
                                 http_method: Optional[str] = None) -> SecurityEvent:
        """
        Internal method to log security events.
        """
        event = SecurityEvent(
            event_type=event_type,
            severity=severity.value,
            message=message,
            details=json.dumps(details) if details else None,
            user_id=user_id,
            user_email=user_email,
            ip_address=ip_address,
            user_agent=user_agent,
            endpoint=endpoint,
            http_method=http_method
        )
        
        self.db.add(event)
        await self.db.commit()
        await self.db.refresh(event)
        
        # Also log to application logger for immediate monitoring
        log_level = getattr(logger, severity.value.lower())
        log_level(f"SECURITY_EVENT: {event_type} - {message} - {details}")
        
        return event
    
    # ==========================================
    # SECURITY ANALYSIS METHODS
    # ==========================================
    
    async def _detect_suspicious_login(self, user_id: int, ip_address: str, user_agent: str) -> bool:
        """
        Detect suspicious login patterns.
        """
        # Check for multiple IPs in short time
        recent_sessions = await self.db.execute(
            select(UserSession.ip_address)
            .where(and_(
                UserSession.user_id == user_id,
                UserSession.login_at > datetime.now(timezone.utc) - timedelta(hours=1)
            ))
            .distinct()
        )
        
        unique_ips = {ip for ip, in recent_sessions}
        
        # Suspicious if more than 3 different IPs in 1 hour
        if len(unique_ips) > 3:
            return True
        
        # Check for unusual user agent
        common_agents = await self.db.execute(
            select(func.count(UserSession.id))
            .where(and_(
                UserSession.user_id == user_id,
                UserSession.user_agent == user_agent
            ))
        )
        
        agent_count = common_agents.scalar()
        
        # Suspicious if first time seeing this user agent
        if agent_count == 0:
            return True
        
        return False
    
    async def cleanup_expired_data(self):
        """
        Clean up expired sessions, blacklisted tokens, and old security events.
        """
        now = datetime.now(timezone.utc)
        
        # Clean up expired sessions
        await self.db.execute(
            UserSession.__table__.update()
            .where(UserSession.expires_at < now)
            .values(is_active=False)
        )
        
        # Delete expired blacklisted tokens
        await self.db.execute(
            BlacklistedToken.__table__.delete()
            .where(BlacklistedToken.expires_at < now)
        )
        
        # Archive old security events (keep last 90 days)
        cutoff_date = now - timedelta(days=90)
        result = await self.db.execute(
            select(func.count(SecurityEvent.id))
            .where(SecurityEvent.created_at < cutoff_date)
        )
        old_events_count = result.scalar()
        
        if old_events_count > 0:
            await self.db.execute(
                SecurityEvent.__table__.delete()
                .where(SecurityEvent.created_at < cutoff_date)
            )
            
            logger.info(f"Archived {old_events_count} old security events")
        
        await self.db.commit()
        logger.info("Completed RBAC data cleanup")

# Default roles and permissions setup
DEFAULT_PERMISSIONS = [
    # User permissions
    ("user:read", "user", "read", "View user profiles"),
    ("user:update", "user", "update", "Update own user profile"),
    ("user:delete", "user", "delete", "Delete own user account"),
    
    # Photo permissions
    ("photo:create", "photo", "create", "Upload photos"),
    ("photo:read", "photo", "read", "View photos"),
    ("photo:update", "photo", "update", "Edit photo metadata"),
    ("photo:delete", "photo", "delete", "Delete photos"),
    
    # Album permissions
    ("album:create", "album", "create", "Create photo albums"),
    ("album:read", "album", "read", "View photo albums"),
    ("album:update", "album", "update", "Edit album details"),
    ("album:delete", "album", "delete", "Delete photo albums"),
    
    # Admin permissions
    ("admin:manage", "admin", "manage", "Full administrative access"),
    ("user:manage", "user", "manage", "Manage all user accounts"),
    ("photo:manage", "photo", "manage", "Manage all photos"),
    ("album:manage", "album", "manage", "Manage all albums"),
]

DEFAULT_ROLES = [
    ("USER", "Standard User", "Default role for regular users", False),
    ("MODERATOR", "Content Moderator", "Can moderate user-generated content", False),
    ("ADMIN", "Administrator", "Full system administration access", True),
    ("SUPERADMIN", "Super Administrator", "Unrestricted system access", True),
]

async def initialize_rbac_system(db: AsyncSession):
    """
    Initialize RBAC system with default roles and permissions.
    Call this during application startup.
    """
    try:
        rbac = RBACService(db)
        
        # Create default permissions
        for perm_data in DEFAULT_PERMISSIONS:
            name, resource, action, description = perm_data
            
            # Check if permission exists
            result = await db.execute(
                select(Permission).where(Permission.name == name)
            )
            
            if not result.scalar_one_or_none():
                permission = Permission(
                    name=name,
                    resource=resource,
                    action=action,
                    description=description
                )
                db.add(permission)
        
        # Create default roles
        for role_data in DEFAULT_ROLES:
            name, display_name, description, is_system = role_data
            
            # Check if role exists
            result = await db.execute(
                select(Role).where(Role.name == name)
            )
            
            if not result.scalar_one_or_none():
                role = Role(
                    name=name,
                    display_name=display_name,
                    description=description,
                    is_system_role=is_system
                )
                db.add(role)
        
        await db.commit()
        logger.info("RBAC system initialized with default roles and permissions")
        
    except Exception as e:
        await db.rollback()
        logger.error(f"Error initializing RBAC system: {e}")
        raise