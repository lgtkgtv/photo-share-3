"""
Photo sharing database models with comprehensive security and relationship management.
Implements secure photo storage, album organization, and fine-grained sharing controls.
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Table, Enum as SQLEnum, DECIMAL, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.types import JSON
from enum import Enum
import uuid
from datetime import datetime, timezone
from services.db import Base

# Association table for many-to-many relationship between photos and albums
photo_albums = Table(
    'photo_albums',
    Base.metadata,
    Column('photo_id', Integer, ForeignKey('photos.id'), primary_key=True),
    Column('album_id', Integer, ForeignKey('albums.id'), primary_key=True),
    Column('added_at', DateTime(timezone=True), server_default=func.now()),
    Column('added_by', Integer, ForeignKey('users.id'), nullable=True)
)

# Enums for photo-related choices
class PhotoStatus(Enum):
    """Photo processing and availability status."""
    UPLOADING = "uploading"
    PROCESSING = "processing"
    READY = "ready"
    FAILED = "failed"
    DELETED = "deleted"

class ShareType(Enum):
    """Photo sharing types."""
    PRIVATE = "private"
    SHARED_WITH_USERS = "shared_with_users"
    SHARED_WITH_LINK = "shared_with_link"
    PUBLIC = "public"

class AlbumType(Enum):
    """Album types for organization."""
    PERSONAL = "personal"
    SHARED = "shared"
    PUBLIC = "public"

class Photo(Base):
    """
    Photo model with comprehensive metadata and security features.
    Stores photo information, processing status, and access controls.
    """
    __tablename__ = "photos"
    
    # Primary identification
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4, index=True)
    
    # Ownership and access
    owner_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    
    # File information
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)  # User's original filename
    file_path = Column(String(500), nullable=False)  # Secure storage path
    file_size = Column(Integer, nullable=False)  # Size in bytes
    file_hash = Column(String(64), nullable=False, index=True)  # SHA-256 hash for deduplication
    mime_type = Column(String(100), nullable=False)
    
    # Image metadata
    width = Column(Integer, nullable=True)
    height = Column(Integer, nullable=True)
    aspect_ratio = Column(DECIMAL(5, 4), nullable=True)  # width/height
    
    # Photo metadata
    title = Column(String(200), nullable=True)
    description = Column(Text, nullable=True)
    tags = Column(JSON, nullable=True)  # JSON array of tags (compatible with SQLite and PostgreSQL)
    
    # EXIF and technical data
    exif_data = Column(JSON, nullable=True)  # Structured EXIF data (compatible with SQLite and PostgreSQL)
    camera_make = Column(String(100), nullable=True)
    camera_model = Column(String(100), nullable=True)
    taken_at = Column(DateTime(timezone=True), nullable=True)  # When photo was taken
    location = Column(JSON, nullable=True)  # GPS coordinates if available (compatible with SQLite and PostgreSQL)
    
    # Processing and thumbnails
    status = Column(SQLEnum(PhotoStatus), default=PhotoStatus.UPLOADING, nullable=False, index=True)
    processing_log = Column(Text, nullable=True)  # Processing errors/info
    
    # Thumbnail and processed versions
    thumbnail_path = Column(String(500), nullable=True)
    medium_path = Column(String(500), nullable=True)
    large_path = Column(String(500), nullable=True)
    
    # Sharing and visibility
    share_type = Column(SQLEnum(ShareType), default=ShareType.PRIVATE, nullable=False, index=True)
    share_token = Column(String(64), nullable=True, unique=True, index=True)  # For link sharing
    share_expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Content moderation
    content_warning = Column(Boolean, default=False, nullable=False)
    moderation_status = Column(String(50), default='pending', index=True)
    moderation_log = Column(JSON, nullable=True)  # Compatible with SQLite and PostgreSQL
    
    # Statistics and engagement
    view_count = Column(Integer, default=0, nullable=False)
    download_count = Column(Integer, default=0, nullable=False)
    last_viewed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    deleted_at = Column(DateTime(timezone=True), nullable=True, index=True)  # Soft delete
    
    # Relationships
    owner = relationship("User", back_populates="photos")
    albums = relationship("Album", secondary=photo_albums, back_populates="photos")
    shares = relationship("PhotoShare", back_populates="photo", cascade="all, delete-orphan")
    comments = relationship("PhotoComment", back_populates="photo", cascade="all, delete-orphan")
    likes = relationship("PhotoLike", back_populates="photo", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Photo(id={self.id}, filename='{self.filename}', owner_id={self.owner_id})>"
    
    @property
    def is_deleted(self):
        """Check if photo is soft-deleted."""
        return self.deleted_at is not None
    
    @property
    def is_public(self):
        """Check if photo is publicly accessible."""
        return self.share_type == ShareType.PUBLIC
    
    @property
    def is_shared(self):
        """Check if photo is shared in any way."""
        return self.share_type != ShareType.PRIVATE

class Album(Base):
    """
    Album model for organizing photos with sharing capabilities.
    """
    __tablename__ = "albums"
    
    # Primary identification
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4, index=True)
    
    # Basic information
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    
    # Ownership and access
    owner_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    album_type = Column(SQLEnum(AlbumType), default=AlbumType.PERSONAL, nullable=False, index=True)
    
    # Sharing settings
    is_public = Column(Boolean, default=False, nullable=False, index=True)
    share_token = Column(String(64), nullable=True, unique=True, index=True)
    
    # Album metadata
    cover_photo_id = Column(Integer, ForeignKey('photos.id'), nullable=True)
    photo_count = Column(Integer, default=0, nullable=False)
    total_size = Column(Integer, default=0, nullable=False)  # Total size in bytes
    
    # Organization
    sort_order = Column(String(50), default='created_desc')  # How photos are sorted
    tags = Column(JSON, nullable=True)  # Album tags (compatible with SQLite and PostgreSQL)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    deleted_at = Column(DateTime(timezone=True), nullable=True, index=True)
    
    # Relationships
    owner = relationship("User", back_populates="albums")
    photos = relationship("Photo", secondary=photo_albums, back_populates="albums")
    cover_photo = relationship("Photo", foreign_keys=[cover_photo_id])
    shares = relationship("AlbumShare", back_populates="album", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Album(id={self.id}, name='{self.name}', owner_id={self.owner_id})>"
    
    @property
    def is_deleted(self):
        """Check if album is soft-deleted."""
        return self.deleted_at is not None

class PhotoShare(Base):
    """
    Photo sharing model for granular access control.
    Tracks who has access to specific photos and how.
    """
    __tablename__ = "photo_shares"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # What is being shared
    photo_id = Column(Integer, ForeignKey('photos.id'), nullable=False, index=True)
    
    # Who has access
    shared_with_user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)  # Specific user
    shared_with_email = Column(String(255), nullable=True, index=True)  # Email-based sharing for unregistered users
    shared_with_role = Column(String(50), nullable=True)  # Role-based sharing
    shared_with_group = Column(String(100), nullable=True)  # Group-based sharing
    
    # Sharing metadata
    shared_by_user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    share_token = Column(String(64), nullable=True, unique=True, index=True)  # For link sharing
    
    # Access permissions
    can_view = Column(Boolean, default=True, nullable=False)
    can_download = Column(Boolean, default=False, nullable=False)
    can_share = Column(Boolean, default=False, nullable=False)
    can_comment = Column(Boolean, default=False, nullable=False)
    
    # Access restrictions
    expires_at = Column(DateTime(timezone=True), nullable=True)
    max_views = Column(Integer, nullable=True)
    current_views = Column(Integer, default=0, nullable=False)
    
    # Tracking
    last_accessed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    photo = relationship("Photo", back_populates="shares")
    shared_with_user = relationship("User", foreign_keys=[shared_with_user_id])
    shared_by_user = relationship("User", foreign_keys=[shared_by_user_id])
    
    def __repr__(self):
        return f"<PhotoShare(photo_id={self.photo_id}, shared_with_user_id={self.shared_with_user_id})>"
    
    @property
    def is_expired(self):
        """Check if share has expired."""
        if self.expires_at:
            return datetime.now(timezone.utc) > self.expires_at
        return False
    
    @property
    def is_view_limit_exceeded(self):
        """Check if view limit has been exceeded."""
        if self.max_views:
            return self.current_views >= self.max_views
        return False

class AlbumShare(Base):
    """
    Album sharing model for sharing entire albums.
    """
    __tablename__ = "album_shares"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # What is being shared
    album_id = Column(Integer, ForeignKey('albums.id'), nullable=False, index=True)
    
    # Who has access
    shared_with_user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    shared_by_user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    
    # Access permissions
    can_view = Column(Boolean, default=True, nullable=False)
    can_add_photos = Column(Boolean, default=False, nullable=False)
    can_remove_photos = Column(Boolean, default=False, nullable=False)
    can_edit_album = Column(Boolean, default=False, nullable=False)
    
    # Access restrictions
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    album = relationship("Album", back_populates="shares")
    shared_with_user = relationship("User", foreign_keys=[shared_with_user_id])
    shared_by_user = relationship("User", foreign_keys=[shared_by_user_id])
    
    def __repr__(self):
        return f"<AlbumShare(album_id={self.album_id}, shared_with_user_id={self.shared_with_user_id})>"

class PhotoComment(Base):
    """
    Photo comments with moderation and threading support.
    """
    __tablename__ = "photo_comments"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Content
    photo_id = Column(Integer, ForeignKey('photos.id'), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    content = Column(Text, nullable=False)
    
    # Threading support
    parent_comment_id = Column(Integer, ForeignKey('photo_comments.id'), nullable=True)
    reply_count = Column(Integer, default=0, nullable=False)
    
    # Moderation
    is_deleted = Column(Boolean, default=False, nullable=False)
    is_flagged = Column(Boolean, default=False, nullable=False)
    moderation_status = Column(String(50), default='approved', index=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    photo = relationship("Photo", back_populates="comments")
    user = relationship("User")
    parent_comment = relationship("PhotoComment", remote_side=[id])
    replies = relationship("PhotoComment", remote_side=[parent_comment_id])
    
    def __repr__(self):
        return f"<PhotoComment(id={self.id}, photo_id={self.photo_id}, user_id={self.user_id})>"

class PhotoLike(Base):
    """
    Photo likes/reactions system.
    """
    __tablename__ = "photo_likes"
    
    id = Column(Integer, primary_key=True, index=True)
    
    photo_id = Column(Integer, ForeignKey('photos.id'), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    
    # Reaction type (like, love, etc.)
    reaction_type = Column(String(20), default='like', nullable=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    photo = relationship("Photo", back_populates="likes")
    user = relationship("User")
    
    # Unique constraint to prevent duplicate likes
    __table_args__ = (
        Index('idx_unique_photo_user_like', 'photo_id', 'user_id', unique=True),
    )
    
    def __repr__(self):
        return f"<PhotoLike(photo_id={self.photo_id}, user_id={self.user_id})>"

class StorageQuota(Base):
    """
    User storage quota tracking and management.
    """
    __tablename__ = "storage_quotas"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True, nullable=False, index=True)
    
    # Quota limits (in bytes)
    quota_limit = Column(Integer, default=1073741824, nullable=False)  # 1GB default
    used_storage = Column(Integer, default=0, nullable=False)
    
    # File count limits
    max_files = Column(Integer, default=10000, nullable=False)
    file_count = Column(Integer, default=0, nullable=False)
    
    # Quota metadata
    quota_type = Column(String(50), default='free', nullable=False)  # free, premium, enterprise
    last_calculated_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    user = relationship("User", back_populates="storage_quota")
    
    def __repr__(self):
        return f"<StorageQuota(user_id={self.user_id}, used={self.used_storage}, limit={self.quota_limit})>"
    
    @property
    def usage_percentage(self):
        """Calculate storage usage as percentage."""
        if self.quota_limit == 0:
            return 100.0
        return (self.used_storage / self.quota_limit) * 100.0
    
    @property
    def is_over_quota(self):
        """Check if user is over their storage quota."""
        return self.used_storage > self.quota_limit
    
    @property
    def available_storage(self):
        """Calculate available storage in bytes."""
        return max(0, self.quota_limit - self.used_storage)

class UploadSession(Base):
    """
    Track multi-part upload sessions for large files.
    """
    __tablename__ = "upload_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4, index=True)
    
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    
    # Upload metadata
    filename = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=False)
    mime_type = Column(String(100), nullable=False)
    
    # Upload progress
    bytes_uploaded = Column(Integer, default=0, nullable=False)
    chunks_uploaded = Column(Integer, default=0, nullable=False)
    total_chunks = Column(Integer, nullable=False)
    
    # Session state
    status = Column(String(50), default='active', nullable=False, index=True)
    temp_file_path = Column(String(500), nullable=True)
    
    # Session expiry
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User")
    
    def __repr__(self):
        return f"<UploadSession(id={self.id}, user_id={self.user_id}, status='{self.status}')>"
    
    @property
    def upload_percentage(self):
        """Calculate upload progress as percentage."""
        if self.file_size == 0:
            return 0.0
        return (self.bytes_uploaded / self.file_size) * 100.0
    
    @property
    def is_expired(self):
        """Check if upload session has expired."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc) > self.expires_at