"""
Pydantic schemas for photo operations with comprehensive security validation.
Provides secure data validation, sanitization, and serialization for photo APIs.
"""
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum
import re

from models.photo import PhotoStatus, ShareType, AlbumType

# Validation constants
ALLOWED_IMAGE_TYPES = {'image/jpeg', 'image/png', 'image/webp', 'image/gif'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB default
MAX_FILENAME_LENGTH = 255
MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 2000
MAX_TAGS_COUNT = 20
MAX_TAG_LENGTH = 50

class PhotoStatusEnum(str, Enum):
    """Photo status enum for API."""
    UPLOADING = "uploading"
    PROCESSING = "processing"
    READY = "ready"
    FAILED = "failed"
    DELETED = "deleted"

class ShareTypeEnum(str, Enum):
    """Share type enum for API."""
    PRIVATE = "private"
    SHARED_WITH_USERS = "shared_with_users"
    SHARED_WITH_LINK = "shared_with_link"
    PUBLIC = "public"

class AlbumTypeEnum(str, Enum):
    """Album type enum for API."""
    PERSONAL = "personal"
    SHARED = "shared"
    PUBLIC = "public"

# Base schemas for reuse
class PhotoMetadataBase(BaseModel):
    """Base schema for photo metadata."""
    title: Optional[str] = Field(None, max_length=MAX_TITLE_LENGTH)
    description: Optional[str] = Field(None, max_length=MAX_DESCRIPTION_LENGTH)
    tags: Optional[List[str]] = Field(None, max_length=MAX_TAGS_COUNT)
    
    @field_validator('title')
    def validate_title(cls, v):
        """Validate and sanitize photo title."""
        if v:
            # Strip whitespace and basic sanitization
            v = v.strip()
            # Remove potentially harmful characters including path traversal
            v = re.sub(r'[<>"\']', '', v)  # XSS prevention
            v = re.sub(r'\.\.\/|\.\.\\', '', v)  # Path traversal prevention
            v = re.sub(r'[;|&$()]', '', v)  # Command injection prevention
            if len(v) == 0:
                return None
        return v
    
    @field_validator('description')
    def validate_description(cls, v):
        """Validate and sanitize photo description."""
        if v:
            v = v.strip()
            # Basic XSS prevention
            v = re.sub(r'[<>]', '', v)
            if len(v) == 0:
                return None
        return v
    
    @field_validator('tags')
    def validate_tags(cls, v):
        """Validate and sanitize photo tags."""
        if v:
            sanitized_tags = []
            for tag in v:
                if isinstance(tag, str):
                    # Clean up tag
                    clean_tag = re.sub(r'[^a-zA-Z0-9\-_\s]', '', tag.strip().lower())
                    if clean_tag and len(clean_tag) <= MAX_TAG_LENGTH:
                        sanitized_tags.append(clean_tag)
            
            # Remove duplicates while preserving order
            return list(dict.fromkeys(sanitized_tags))
        return v

# Photo upload schemas
class PhotoUploadRequest(PhotoMetadataBase):
    """Schema for photo upload requests."""
    album_id: Optional[int] = Field(None, gt=0)
    share_type: ShareTypeEnum = ShareTypeEnum.PRIVATE
    
    # File upload validation (handled separately in multipart)
    # These are for metadata that comes with the upload
    preserve_exif: bool = Field(default=False)
    auto_orient: bool = Field(default=True)
    generate_thumbnails: bool = Field(default=True)

class PhotoUploadResponse(BaseModel):
    """Schema for photo upload responses."""
    id: int
    uuid: str
    filename: str
    status: PhotoStatusEnum
    upload_url: Optional[str] = None  # For resumable uploads
    processing_id: Optional[str] = None
    message: str
    
    class Config:
        from_attributes = True

class PhotoMetadataUpdate(PhotoMetadataBase):
    """Schema for updating photo metadata."""
    share_type: Optional[ShareTypeEnum] = None
    
    @model_validator(mode='before')
    def validate_update_fields(cls, values):
        """Ensure at least one field is being updated."""
        update_fields = {k: v for k, v in values.items() if v is not None}
        if not update_fields:
            raise ValueError("At least one field must be provided for update")
        return values

# Photo response schemas
class PhotoThumbnail(BaseModel):
    """Schema for photo thumbnail information."""
    url: str
    width: int
    height: int
    size: str  # 'small', 'medium', 'large'

class PhotoExifData(BaseModel):
    """Schema for EXIF data (sanitized)."""
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    focal_length: Optional[str] = None
    aperture: Optional[str] = None
    shutter_speed: Optional[str] = None
    iso: Optional[int] = None
    taken_at: Optional[datetime] = None
    # Location data only if user explicitly allows it
    location: Optional[Dict[str, float]] = None

class PhotoDetail(PhotoMetadataBase):
    """Detailed photo information schema."""
    id: int
    uuid: str
    filename: str
    original_filename: str
    file_size: int
    mime_type: str
    width: Optional[int]
    height: Optional[int]
    aspect_ratio: Optional[float]
    
    # URLs for different sizes
    url: str
    thumbnails: List[PhotoThumbnail]
    
    # Status and sharing
    status: PhotoStatusEnum
    share_type: ShareTypeEnum
    share_token: Optional[str] = None
    
    # Metadata
    exif_data: Optional[PhotoExifData] = None
    
    # Statistics
    view_count: int = 0
    download_count: int = 0
    like_count: int = 0
    comment_count: int = 0
    
    # Ownership and timestamps
    owner_id: int
    created_at: datetime
    updated_at: Optional[datetime]
    
    # User-specific fields (populated based on viewing user)
    is_liked: Optional[bool] = None
    can_edit: Optional[bool] = None
    can_delete: Optional[bool] = None
    can_share: Optional[bool] = None
    
    class Config:
        from_attributes = True

class PhotoSummary(BaseModel):
    """Summary photo information for lists."""
    id: int
    uuid: str
    filename: str
    title: Optional[str]
    
    # Thumbnail for display
    thumbnail_url: str
    width: Optional[int]
    height: Optional[int]
    
    # Basic info
    status: PhotoStatusEnum
    share_type: ShareTypeEnum
    owner_id: int
    created_at: datetime
    
    # Quick stats
    view_count: int = 0
    like_count: int = 0
    comment_count: int = 0
    
    class Config:
        from_attributes = True

# Album schemas
class AlbumCreate(BaseModel):
    """Schema for creating albums."""
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    album_type: AlbumTypeEnum = AlbumTypeEnum.PERSONAL
    is_public: bool = False
    tags: Optional[List[str]] = Field(None, max_length=MAX_TAGS_COUNT)
    
    @field_validator('name')
    def validate_album_name(cls, v):
        """Validate and sanitize album name."""
        v = v.strip()
        # Remove harmful characters
        v = re.sub(r'[<>"/\\|?*]', '', v)
        if len(v) == 0:
            raise ValueError("Album name cannot be empty")
        return v

class AlbumUpdate(BaseModel):
    """Schema for updating albums."""
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    is_public: Optional[bool] = None
    cover_photo_id: Optional[int] = Field(None, gt=0)
    tags: Optional[List[str]] = Field(None, max_length=MAX_TAGS_COUNT)

class AlbumDetail(BaseModel):
    """Detailed album information."""
    id: int
    uuid: str
    name: str
    description: Optional[str]
    album_type: AlbumTypeEnum
    is_public: bool
    
    # Statistics
    photo_count: int
    total_size: int
    
    # Cover photo
    cover_photo: Optional[PhotoSummary] = None
    
    # Recent photos for preview
    recent_photos: List[PhotoSummary] = []
    
    # Ownership and sharing
    owner_id: int
    share_token: Optional[str] = None
    
    # Timestamps
    created_at: datetime
    updated_at: Optional[datetime]
    
    # User permissions
    can_edit: Optional[bool] = None
    can_delete: Optional[bool] = None
    can_add_photos: Optional[bool] = None
    
    class Config:
        from_attributes = True

class AlbumSummary(BaseModel):
    """Summary album information for lists."""
    id: int
    uuid: str
    name: str
    description: Optional[str]
    album_type: AlbumTypeEnum
    is_public: bool
    photo_count: int
    cover_photo_url: Optional[str] = None
    owner_id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

# Sharing schemas
class PhotoShareCreate(BaseModel):
    """Schema for creating photo shares."""
    photo_id: int = Field(..., gt=0)
    shared_with_user_id: Optional[int] = Field(None, gt=0)
    shared_with_email: Optional[str] = None  # For sharing with unregistered users
    
    # Permissions
    can_view: bool = True
    can_download: bool = False
    can_share: bool = False
    can_comment: bool = False
    
    # Access restrictions
    expires_in_days: Optional[int] = Field(None, gt=0, le=365)
    max_views: Optional[int] = Field(None, gt=0, le=10000)
    
    # Message to recipient
    message: Optional[str] = Field(None, max_length=500)
    
    @model_validator(mode='before')
    def validate_share_target(cls, values):
        """Ensure either user_id or email is provided."""
        user_id = values.get('shared_with_user_id')
        email = values.get('shared_with_email')
        
        if not user_id and not email:
            raise ValueError("Either shared_with_user_id or shared_with_email must be provided")
        if user_id and email:
            raise ValueError("Cannot specify both user_id and email")
        
        return values

class PhotoShareResponse(BaseModel):
    """Schema for photo share responses."""
    id: int
    photo_id: int
    share_token: Optional[str] = None
    shared_with_user_id: Optional[int] = None
    shared_with_email: Optional[str] = None
    
    # Permissions
    can_view: bool
    can_download: bool
    can_share: bool
    can_comment: bool
    
    # Status
    expires_at: Optional[datetime] = None
    max_views: Optional[int] = None
    current_views: int = 0
    last_accessed_at: Optional[datetime] = None
    created_at: datetime
    
    class Config:
        from_attributes = True

# Upload session schemas (for large file uploads)
class UploadSessionCreate(BaseModel):
    """Schema for creating upload sessions."""
    filename: str = Field(..., min_length=1, max_length=MAX_FILENAME_LENGTH)
    file_size: int = Field(..., gt=0, le=MAX_FILE_SIZE)
    mime_type: str = Field(..., pattern=r'^image/(jpeg|png|webp|gif)$')
    chunk_size: int = Field(default=5*1024*1024, gt=0, le=10*1024*1024)  # 5MB default chunks
    
    @field_validator('filename')
    def validate_filename(cls, v):
        """Validate and sanitize filename."""
        # Remove path components
        v = v.split('/')[-1].split('\\')[-1]
        # Remove potentially harmful characters
        v = re.sub(r'[<>:"/\\|?*]', '', v)
        if not v:
            raise ValueError("Invalid filename")
        return v
    
    @field_validator('mime_type')
    def validate_mime_type(cls, v):
        """Validate mime type."""
        if v not in ALLOWED_IMAGE_TYPES:
            raise ValueError(f"Unsupported file type. Allowed: {', '.join(ALLOWED_IMAGE_TYPES)}")
        return v

class UploadSessionResponse(BaseModel):
    """Schema for upload session responses."""
    session_id: str
    upload_url: str
    chunk_size: int
    total_chunks: int
    expires_at: datetime
    
class UploadChunkRequest(BaseModel):
    """Schema for upload chunk requests."""
    session_id: str
    chunk_number: int = Field(..., ge=1)
    chunk_hash: str = Field(..., min_length=64, max_length=64)  # SHA-256 hash

class UploadChunkResponse(BaseModel):
    """Schema for upload chunk responses."""
    chunk_number: int
    bytes_uploaded: int
    total_bytes: int
    upload_percentage: float
    next_chunk_url: Optional[str] = None
    complete: bool = False

# Storage quota schemas
class StorageQuotaInfo(BaseModel):
    """Schema for storage quota information."""
    quota_limit: int
    used_storage: int
    available_storage: int
    usage_percentage: float
    file_count: int
    max_files: int
    quota_type: str
    last_calculated_at: datetime
    
    class Config:
        from_attributes = True

# Batch operation schemas
class BatchPhotoOperation(BaseModel):
    """Schema for batch photo operations."""
    photo_ids: List[int] = Field(..., min_length=1, max_length=100)
    operation: str = Field(..., pattern=r'^(delete|move_to_album|update_share_type|add_tags|remove_tags)$')
    parameters: Optional[Dict[str, Any]] = None
    
    @field_validator('photo_ids')
    def validate_photo_ids(cls, v):
        """Validate photo IDs."""
        if len(set(v)) != len(v):
            raise ValueError("Duplicate photo IDs not allowed")
        return v

class BatchOperationResult(BaseModel):
    """Schema for batch operation results."""
    operation: str
    total_requested: int
    successful: int
    failed: int
    errors: List[Dict[str, Any]] = []
    processed_ids: List[int] = []

# Search and filtering schemas
class PhotoSearchRequest(BaseModel):
    """Schema for photo search requests."""
    query: Optional[str] = Field(None, max_length=200)
    tags: Optional[List[str]] = Field(None, max_length=10)
    album_id: Optional[int] = Field(None, gt=0)
    owner_id: Optional[int] = Field(None, gt=0)
    share_type: Optional[ShareTypeEnum] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    
    # Pagination
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
    
    # Sorting
    sort_by: str = Field(default='created_at', pattern=r'^(created_at|updated_at|title|view_count|like_count)$')
    sort_order: str = Field(default='desc', pattern=r'^(asc|desc)$')
    
    @field_validator('query')
    def validate_search_query(cls, v):
        """Validate and sanitize search query."""
        if v:
            # Basic sanitization to prevent injection
            v = re.sub(r'[<>"\']', '', v.strip())
            if len(v) == 0:
                return None
        return v

class PhotoSearchResponse(BaseModel):
    """Schema for photo search responses."""
    photos: List[PhotoSummary]
    total_count: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_previous: bool

# Analytics schemas
class PhotoAnalytics(BaseModel):
    """Schema for photo analytics."""
    photo_id: int
    views_today: int
    views_this_week: int
    views_this_month: int
    downloads_today: int
    downloads_this_week: int
    downloads_this_month: int
    top_referrers: List[Dict[str, Any]] = []
    geographic_distribution: List[Dict[str, Any]] = []