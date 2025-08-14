"""
Secure photo upload and management API endpoints.
Implements enterprise-grade photo sharing with comprehensive security controls.
"""
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Request, Query
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, desc, asc
from typing import List, Optional, Dict, Any
import json
from datetime import datetime, timezone, timedelta
import logging
import os
from pathlib import Path

from services.db import get_db
from services.authorization import require_auth_and_permission, require_self_or_admin
from services.auth import get_current_user
from services.rbac import RBACService
from services.file_storage import storage, FileValidationError, StorageError
from services.security import SecurityUtils
from services.photo_rate_limiter import get_photo_rate_limiter
from schemas.rbac import ResourceType, ActionType
from schemas.photo import (
    PhotoUploadRequest, PhotoUploadResponse, PhotoDetail, PhotoSummary,
    PhotoMetadataUpdate, PhotoSearchRequest, PhotoSearchResponse,
    AlbumCreate, AlbumUpdate, AlbumDetail, AlbumSummary,
    PhotoShareCreate, PhotoShareResponse, StorageQuotaInfo,
    BatchPhotoOperation, BatchOperationResult, UploadSessionCreate,
    UploadSessionResponse, UploadChunkRequest, UploadChunkResponse
)
from models.user import User
from models.photo import (
    Photo, Album, PhotoShare, StorageQuota, UploadSession,
    PhotoStatus, ShareType, AlbumType, photo_albums
)
from dao.user_dao import UserDAO

router = APIRouter()
logger = logging.getLogger(__name__)

# ==========================================
# PHOTO UPLOAD ENDPOINTS
# ==========================================

@router.post("/upload", response_model=PhotoUploadResponse)
async def upload_photo(
    request: Request,
    file: UploadFile = File(...),
    metadata: str = Form("{}"),  # JSON string with photo metadata
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth_and_permission(ResourceType.PHOTO, ActionType.CREATE))
):
    """
    Upload a single photo with comprehensive security validation.
    
    Security features:
    - File type and content validation
    - Size limits and quota checking
    - Malware scanning
    - Rate limiting
    - Audit logging
    """
    client_ip = SecurityUtils.get_client_ip(request)
    
    # Check upload rate limits
    photo_rate_limiter = get_photo_rate_limiter()
    rate_limit_result = await photo_rate_limiter.check_upload_rate_limit(client_ip, current_user.id)
    
    if not rate_limit_result.allowed:
        SecurityUtils.log_security_event(
            "upload_rate_limited",
            {
                "user_id": current_user.id,
                "client_ip": client_ip,
                "remaining": rate_limit_result.remaining,
                "retry_after": rate_limit_result.retry_after
            },
            user_email=current_user.email,
            client_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Upload rate limit exceeded. Try again in {rate_limit_result.retry_after} seconds.",
            headers={"Retry-After": str(rate_limit_result.retry_after)}
        )
    
    try:
        # Parse metadata
        try:
            photo_metadata = json.loads(metadata)
            upload_request = PhotoUploadRequest(**photo_metadata)
        except (json.JSONDecodeError, ValueError) as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid metadata format: {str(e)}"
            )
        
        # Check storage quota
        quota_info = await check_user_quota(db, current_user.id, file.size)
        if quota_info['over_quota']:
            if quota_info.get('rate_limited', False):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Quota check rate limit exceeded"
                )
            else:
                SecurityUtils.log_security_event(
                    "upload_quota_exceeded",
                    {
                        "user_id": current_user.id,
                        "requested_size": file.size,
                        "available_space": quota_info['available_storage']
                    },
                    user_email=current_user.email,
                    client_ip=client_ip
                )
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="Storage quota exceeded"
                )
        
        # Validate file
        if not file.filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Filename is required"
            )
        
        # Store file with security validation
        storage_result = storage.store_uploaded_file(
            file.file,
            file.filename,
            current_user.id,
            max_file_size=quota_info.get('max_file_size', 50*1024*1024),
            preserve_exif=upload_request.preserve_exif,
            auto_orient=upload_request.auto_orient
        )
        
        # Handle duplicate files
        if storage_result.get('duplicate'):
            return PhotoUploadResponse(
                id=storage_result['existing_file_id'],
                uuid="",
                filename=file.filename,
                status='ready',
                message="File already exists"
            )
        
        # Create photo record in database
        photo = Photo(
            owner_id=current_user.id,
            filename=storage_result['filename'],
            original_filename=file.filename,
            file_path=storage_result['file_path'],
            file_size=storage_result['metadata']['file_size'],
            file_hash=storage_result['metadata']['file_hash'],
            mime_type=storage_result['metadata']['mime_type'],
            width=storage_result['metadata']['image_metadata'].get('width'),
            height=storage_result['metadata']['image_metadata'].get('height'),
            aspect_ratio=storage_result['metadata']['image_metadata'].get('aspect_ratio'),
            thumbnail_path=storage_result['thumbnails'].get('small'),
            medium_path=storage_result['thumbnails'].get('medium'),
            large_path=storage_result['thumbnails'].get('large'),
            title=upload_request.title,
            description=upload_request.description,
            tags=upload_request.tags,
            share_type=ShareType(upload_request.share_type.value),
            status=PhotoStatus.READY,
            exif_data=storage_result['metadata']['image_metadata'].get('exif')
        )
        
        db.add(photo)
        await db.commit()
        await db.refresh(photo)
        
        # Update storage quota
        await update_user_quota(db, current_user.id, storage_result['metadata']['file_size'])
        
        # Add to album if specified
        if upload_request.album_id:
            album = await db.get(Album, upload_request.album_id)
            if album and album.owner_id == current_user.id:
                # Add photo to album
                await db.execute(
                    photo_albums.insert().values(
                        photo_id=photo.id,
                        album_id=album.id,
                        added_by=current_user.id
                    )
                )
                await db.commit()
        
        # Log successful upload
        SecurityUtils.log_security_event(
            "photo_upload_success",
            {
                "photo_id": photo.id,
                "photo_uuid": str(photo.uuid),
                "file_size": photo.file_size,
                "mime_type": photo.mime_type,
                "album_id": upload_request.album_id
            },
            user_email=current_user.email,
            client_ip=client_ip
        )
        
        return PhotoUploadResponse(
            id=photo.id,
            uuid=str(photo.uuid),
            filename=photo.filename,
            status=photo.status.value,
            message="Photo uploaded successfully"
        )
        
    except FileValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File validation failed: {str(e)}"
        )
    except StorageError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Storage error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Photo upload error: {e}")
        SecurityUtils.log_security_event(
            "photo_upload_error",
            {
                "user_id": current_user.id,
                "filename": file.filename,
                "error": str(e)
            },
            user_email=current_user.email,
            client_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Upload failed"
        )

@router.post("/upload/batch", response_model=List[PhotoUploadResponse])
async def upload_photos_batch(
    request: Request,
    files: List[UploadFile] = File(...),
    metadata: str = Form("[]"),  # JSON array with metadata for each file
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth_and_permission(ResourceType.PHOTO, ActionType.CREATE))
):
    """
    Upload multiple photos in a batch with security validation.
    Limited to 10 files per batch to prevent resource exhaustion.
    """
    client_ip = SecurityUtils.get_client_ip(request)
    
    # Limit batch size
    max_batch_size = 10
    if len(files) > max_batch_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size limited to {max_batch_size} files"
        )
    
    # Check batch upload rate limits
    photo_rate_limiter = get_photo_rate_limiter()
    rate_limit_result = await photo_rate_limiter.check_batch_upload_rate_limit(
        client_ip, current_user.id, len(files)
    )
    
    if not rate_limit_result.allowed:
        SecurityUtils.log_security_event(
            "batch_upload_rate_limited",
            {
                "user_id": current_user.id,
                "client_ip": client_ip,
                "batch_size": len(files),
                "remaining": rate_limit_result.remaining,
                "retry_after": rate_limit_result.retry_after
            },
            user_email=current_user.email,
            client_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Batch upload rate limit exceeded. Try again in {rate_limit_result.retry_after} seconds.",
            headers={"Retry-After": str(rate_limit_result.retry_after)}
        )
    
    try:
        # Parse metadata
        metadata_list = json.loads(metadata)
        if len(metadata_list) != len(files):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Metadata count must match file count"
            )
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid metadata format"
        )
    
    results = []
    total_size = sum(file.size for file in files)
    
    # Check total batch size against quota
    quota_info = await check_user_quota(db, current_user.id, total_size)
    if quota_info['over_quota']:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Batch exceeds storage quota"
        )
    
    # Process each file
    for i, (file, file_metadata) in enumerate(zip(files, metadata_list)):
        try:
            # Simulate individual upload for each file
            # In production, you might optimize this further
            upload_request = PhotoUploadRequest(**file_metadata)
            
            # Individual file upload logic (simplified)
            # This would use the same logic as single upload
            result = PhotoUploadResponse(
                id=i,  # Placeholder
                uuid=f"batch-{i}",
                filename=file.filename,
                status='uploading',
                message=f"Processing file {i+1} of {len(files)}"
            )
            results.append(result)
            
        except Exception as e:
            # Log individual file failure but continue with batch
            logger.error(f"Batch upload file {i} failed: {e}")
            results.append(PhotoUploadResponse(
                id=-1,
                uuid="",
                filename=file.filename,
                status='failed',
                message=str(e)
            ))
    
    SecurityUtils.log_security_event(
        "batch_photo_upload",
        {
            "user_id": current_user.id,
            "file_count": len(files),
            "total_size": total_size,
            "successful": len([r for r in results if r.status != 'failed'])
        },
        user_email=current_user.email,
        client_ip=client_ip
    )
    
    return results

# ==========================================
# PHOTO MANAGEMENT ENDPOINTS
# ==========================================

@router.get("/{photo_id}", response_model=PhotoDetail)
async def get_photo(
    photo_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth_and_permission(
        ResourceType.PHOTO, ActionType.READ, 
        allow_owner=True, resource_id_param="photo_id"
    ))
):
    """
    Get detailed photo information with permission checking.
    """
    client_ip = SecurityUtils.get_client_ip(request)
    
    # Get photo with owner information
    result = await db.execute(
        select(Photo).where(
            and_(Photo.id == photo_id, Photo.deleted_at.is_(None))
        )
    )
    photo = result.scalar_one_or_none()
    
    if not photo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Photo not found"
        )
    
    # Check access permissions
    rbac = RBACService(db)
    has_access = await check_photo_access(rbac, current_user.id, photo)
    
    if not has_access:
        SecurityUtils.log_security_event(
            "unauthorized_photo_access_attempt",
            {
                "photo_id": photo_id,
                "photo_owner_id": photo.owner_id,
                "requesting_user_id": current_user.id
            },
            user_email=current_user.email,
            client_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Log photo view
    await log_photo_view(db, photo.id, current_user.id, client_ip)
    
    # Build response with user-specific permissions
    photo_detail = await build_photo_detail(db, photo, current_user.id)
    
    return photo_detail

@router.put("/{photo_id}/metadata", response_model=PhotoDetail)
async def update_photo_metadata(
    photo_id: int,
    update_data: PhotoMetadataUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth_and_permission(
        ResourceType.PHOTO, ActionType.UPDATE,
        allow_owner=True, resource_id_param="photo_id"
    ))
):
    """
    Update photo metadata with security validation.
    """
    client_ip = SecurityUtils.get_client_ip(request)
    
    # Get photo
    result = await db.execute(
        select(Photo).where(
            and_(Photo.id == photo_id, Photo.deleted_at.is_(None))
        )
    )
    photo = result.scalar_one_or_none()
    
    if not photo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Photo not found"
        )
    
    # Check ownership or admin permissions
    if photo.owner_id != current_user.id:
        rbac = RBACService(db)
        auth_result = await rbac.check_permission(
            current_user.id, ResourceType.PHOTO, ActionType.UPDATE
        )
        if not auth_result.authorized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied"
            )
    
    # Track changes for audit log
    changes = {}
    
    # Update fields
    if update_data.title is not None and update_data.title != photo.title:
        changes['title'] = {'old': photo.title, 'new': update_data.title}
        photo.title = update_data.title
    
    if update_data.description is not None and update_data.description != photo.description:
        changes['description'] = {'old': photo.description, 'new': update_data.description}
        photo.description = update_data.description
    
    if update_data.tags is not None and update_data.tags != photo.tags:
        changes['tags'] = {'old': photo.tags, 'new': update_data.tags}
        photo.tags = update_data.tags
    
    if update_data.share_type is not None:
        new_share_type = ShareType(update_data.share_type.value)
        if new_share_type != photo.share_type:
            changes['share_type'] = {'old': photo.share_type.value, 'new': new_share_type.value}
            photo.share_type = new_share_type
    
    photo.updated_at = datetime.now(timezone.utc)
    await db.commit()
    
    # Log changes
    if changes:
        SecurityUtils.log_security_event(
            "photo_metadata_updated",
            {
                "photo_id": photo.id,
                "photo_uuid": str(photo.uuid),
                "changes": changes
            },
            user_email=current_user.email,
            client_ip=client_ip
        )
    
    # Return updated photo
    photo_detail = await build_photo_detail(db, photo, current_user.id)
    return photo_detail

@router.delete("/{photo_id}")
async def delete_photo(
    photo_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth_and_permission(
        ResourceType.PHOTO, ActionType.DELETE,
        allow_owner=True, resource_id_param="photo_id"
    ))
):
    """
    Soft delete photo with security validation.
    """
    client_ip = SecurityUtils.get_client_ip(request)
    
    # Get photo
    result = await db.execute(
        select(Photo).where(
            and_(Photo.id == photo_id, Photo.deleted_at.is_(None))
        )
    )
    photo = result.scalar_one_or_none()
    
    if not photo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Photo not found"
        )
    
    # Check ownership or admin permissions
    if photo.owner_id != current_user.id:
        rbac = RBACService(db)
        auth_result = await rbac.check_permission(
            current_user.id, ResourceType.PHOTO, ActionType.DELETE
        )
        if not auth_result.authorized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied"
            )
    
    # Soft delete
    photo.deleted_at = datetime.now(timezone.utc)
    photo.status = PhotoStatus.DELETED
    await db.commit()
    
    # Update storage quota
    await update_user_quota(db, current_user.id, -photo.file_size)
    
    # Log deletion
    SecurityUtils.log_security_event(
        "photo_deleted",
        {
            "photo_id": photo.id,
            "photo_uuid": str(photo.uuid),
            "file_size": photo.file_size,
            "soft_delete": True
        },
        user_email=current_user.email,
        client_ip=client_ip
    )
    
    return {"message": "Photo deleted successfully"}

# ==========================================
# PHOTO SHARING ENDPOINTS
# ==========================================

@router.post("/{photo_id}/share", response_model=PhotoShareResponse)
async def create_photo_share(
    photo_id: int,
    share_data: PhotoShareCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth_and_permission(
        ResourceType.PHOTO, ActionType.UPDATE,
        allow_owner=True, resource_id_param="photo_id"
    ))
):
    """
    Create a new photo share with granular permissions.
    Only photo owners can create shares.
    """
    client_ip = SecurityUtils.get_client_ip(request)
    
    # Check sharing rate limits
    photo_rate_limiter = get_photo_rate_limiter()
    rate_limit_result = await photo_rate_limiter.check_sharing_rate_limit(current_user.id)
    
    if not rate_limit_result.allowed:
        SecurityUtils.log_security_event(
            "photo_sharing_rate_limited",
            {
                "user_id": current_user.id,
                "client_ip": client_ip,
                "photo_id": photo_id,
                "remaining": rate_limit_result.remaining,
                "retry_after": rate_limit_result.retry_after
            },
            user_email=current_user.email,
            client_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Photo sharing rate limit exceeded. Try again in {rate_limit_result.retry_after} seconds.",
            headers={"Retry-After": str(rate_limit_result.retry_after)}
        )
    
    # Get photo and verify ownership
    result = await db.execute(
        select(Photo).where(
            and_(Photo.id == photo_id, Photo.deleted_at.is_(None))
        )
    )
    photo = result.scalar_one_or_none()
    
    if not photo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Photo not found"
        )
    
    if photo.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only photo owner can create shares"
        )
    
    # Validate share target
    shared_with_user = None
    if share_data.shared_with_user_id:
        shared_with_user = await db.get(User, share_data.shared_with_user_id)
        if not shared_with_user or not shared_with_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid user to share with"
            )
    
    # Check for existing share
    if share_data.shared_with_user_id:
        existing_result = await db.execute(
            select(PhotoShare).where(and_(
                PhotoShare.photo_id == photo_id,
                PhotoShare.shared_with_user_id == share_data.shared_with_user_id
            ))
        )
        if existing_result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Photo already shared with this user"
            )
    
    # Calculate expiration date
    expires_at = None
    if share_data.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=share_data.expires_in_days)
    
    # Generate share token for link sharing
    share_token = None
    if not share_data.shared_with_user_id:
        share_token = SecurityUtils.generate_secure_token(32)
    
    # Create photo share
    photo_share = PhotoShare(
        photo_id=photo_id,
        shared_with_user_id=share_data.shared_with_user_id,
        shared_with_email=share_data.shared_with_email,
        shared_by_user_id=current_user.id,
        share_token=share_token,
        can_view=share_data.can_view,
        can_download=share_data.can_download,
        can_share=share_data.can_share,
        can_comment=share_data.can_comment,
        expires_at=expires_at,
        max_views=share_data.max_views
    )
    
    db.add(photo_share)
    await db.commit()
    await db.refresh(photo_share)
    
    # Log share creation
    SecurityUtils.log_security_event(
        "photo_share_created",
        {
            "photo_id": photo_id,
            "photo_uuid": str(photo.uuid),
            "share_id": photo_share.id,
            "shared_with_user_id": share_data.shared_with_user_id,
            "shared_with_email": share_data.shared_with_email,
            "permissions": {
                "can_view": share_data.can_view,
                "can_download": share_data.can_download,
                "can_share": share_data.can_share,
                "can_comment": share_data.can_comment
            },
            "expires_at": expires_at.isoformat() if expires_at else None
        },
        user_email=current_user.email,
        client_ip=client_ip
    )
    
    return PhotoShareResponse(
        id=photo_share.id,
        photo_id=photo_id,
        share_token=share_token,
        shared_with_user_id=share_data.shared_with_user_id,
        shared_with_email=share_data.shared_with_email,
        can_view=photo_share.can_view,
        can_download=photo_share.can_download,
        can_share=photo_share.can_share,
        can_comment=photo_share.can_comment,
        expires_at=photo_share.expires_at,
        max_views=photo_share.max_views,
        current_views=photo_share.current_views,
        created_at=photo_share.created_at
    )

@router.get("/{photo_id}/shares", response_model=List[PhotoShareResponse])
async def list_photo_shares(
    photo_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth_and_permission(
        ResourceType.PHOTO, ActionType.READ,
        allow_owner=True, resource_id_param="photo_id"
    ))
):
    """
    List all shares for a photo.
    Only photo owners can view shares.
    """
    client_ip = SecurityUtils.get_client_ip(request)
    
    # Get photo and verify ownership
    result = await db.execute(
        select(Photo).where(
            and_(Photo.id == photo_id, Photo.deleted_at.is_(None))
        )
    )
    photo = result.scalar_one_or_none()
    
    if not photo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Photo not found"
        )
    
    if photo.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only photo owner can view shares"
        )
    
    # Get all shares for the photo
    shares_result = await db.execute(
        select(PhotoShare).where(PhotoShare.photo_id == photo_id)
        .order_by(desc(PhotoShare.created_at))
    )
    shares = shares_result.scalars().all()
    
    # Convert to response format
    share_responses = []
    for share in shares:
        share_responses.append(PhotoShareResponse(
            id=share.id,
            photo_id=share.photo_id,
            share_token=share.share_token,
            shared_with_user_id=share.shared_with_user_id,
            shared_with_email=share.shared_with_email,
            can_view=share.can_view,
            can_download=share.can_download,
            can_share=share.can_share,
            can_comment=share.can_comment,
            expires_at=share.expires_at,
            max_views=share.max_views,
            current_views=share.current_views,
            last_accessed_at=share.last_accessed_at,
            created_at=share.created_at
        ))
    
    return share_responses

@router.delete("/{photo_id}/shares/{share_id}")
async def revoke_photo_share(
    photo_id: int,
    share_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth_and_permission(
        ResourceType.PHOTO, ActionType.UPDATE,
        allow_owner=True, resource_id_param="photo_id"
    ))
):
    """
    Revoke a photo share.
    Only photo owners can revoke shares.
    """
    client_ip = SecurityUtils.get_client_ip(request)
    
    # Get photo and verify ownership
    result = await db.execute(
        select(Photo).where(
            and_(Photo.id == photo_id, Photo.deleted_at.is_(None))
        )
    )
    photo = result.scalar_one_or_none()
    
    if not photo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Photo not found"
        )
    
    if photo.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only photo owner can revoke shares"
        )
    
    # Get the share
    share = await db.get(PhotoShare, share_id)
    if not share or share.photo_id != photo_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Share not found"
        )
    
    # Delete the share
    await db.delete(share)
    await db.commit()
    
    # Log share revocation
    SecurityUtils.log_security_event(
        "photo_share_revoked",
        {
            "photo_id": photo_id,
            "photo_uuid": str(photo.uuid),
            "share_id": share_id,
            "shared_with_user_id": share.shared_with_user_id,
            "shared_with_email": share.shared_with_email
        },
        user_email=current_user.email,
        client_ip=client_ip
    )
    
    return {"message": "Photo share revoked successfully"}

@router.get("/shared/{token}", response_model=PhotoDetail)
async def access_shared_photo(
    token: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Access a photo via share token.
    Can be accessed by anonymous users if token is valid.
    """
    client_ip = SecurityUtils.get_client_ip(request)
    
    # Get share by token
    share_result = await db.execute(
        select(PhotoShare)
        .where(PhotoShare.share_token == token)
    )
    photo_share = share_result.scalar_one_or_none()
    
    if not photo_share:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid share token"
        )
    
    # Check if share is expired
    if photo_share.is_expired:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Share has expired"
        )
    
    # Check view limit
    if photo_share.is_view_limit_exceeded:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Share view limit exceeded"
        )
    
    # Get the photo
    result = await db.execute(
        select(Photo).where(
            and_(Photo.id == photo_share.photo_id, Photo.deleted_at.is_(None))
        )
    )
    photo = result.scalar_one_or_none()
    
    if not photo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Photo not found"
        )
    
    # Update view count for share
    photo_share.current_views += 1
    photo_share.last_accessed_at = datetime.now(timezone.utc)
    
    # Update photo view count
    photo.view_count = (photo.view_count or 0) + 1
    photo.last_viewed_at = datetime.now(timezone.utc)
    
    await db.commit()
    
    # Log shared photo access
    SecurityUtils.log_security_event(
        "shared_photo_accessed",
        {
            "photo_id": photo.id,
            "photo_uuid": str(photo.uuid),
            "share_id": photo_share.id,
            "share_token": token[:8] + "...",  # Partial token for logging
            "viewer_user_id": current_user.id if current_user else None,
            "current_views": photo_share.current_views
        },
        user_email=current_user.email if current_user else None,
        client_ip=client_ip
    )
    
    # Build photo detail response
    viewing_user_id = current_user.id if current_user else None
    photo_detail = await build_photo_detail(db, photo, viewing_user_id)
    
    # Override permissions for shared access
    photo_detail.can_edit = False
    photo_detail.can_delete = False
    photo_detail.can_share = photo_share.can_share
    
    return photo_detail

# ==========================================
# PHOTO SEARCH AND LISTING
# ==========================================

@router.get("/", response_model=PhotoSearchResponse)
async def search_photos(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth_and_permission(ResourceType.PHOTO, ActionType.READ)),
    query: Optional[str] = Query(None, max_length=200),
    tags: Optional[str] = Query(None),  # Comma-separated tags
    album_id: Optional[int] = Query(None, gt=0),
    owner_id: Optional[int] = Query(None, gt=0),
    share_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort_by: str = Query("created_at", regex=r"^(created_at|updated_at|title|view_count)$"),
    sort_order: str = Query("desc", regex=r"^(asc|desc)$")
):
    """
    Search and list photos with security filtering.
    Users can only see photos they have access to.
    """
    client_ip = SecurityUtils.get_client_ip(request)
    
    # Build base query
    query_builder = select(Photo).where(Photo.deleted_at.is_(None))
    
    # Apply ownership filter - users can only see their own photos or public/shared photos
    if owner_id:
        if owner_id != current_user.id:
            # Check if user has permission to view other users' photos
            rbac = RBACService(db)
            auth_result = await rbac.check_permission(
                current_user.id, ResourceType.PHOTO, ActionType.READ
            )
            if not auth_result.authorized:
                # Can only see public photos from other users
                query_builder = query_builder.where(
                    and_(
                        Photo.owner_id == owner_id,
                        Photo.share_type == ShareType.PUBLIC
                    )
                )
            else:
                query_builder = query_builder.where(Photo.owner_id == owner_id)
        else:
            query_builder = query_builder.where(Photo.owner_id == current_user.id)
    else:
        # Default: show user's own photos and public photos
        query_builder = query_builder.where(
            or_(
                Photo.owner_id == current_user.id,
                Photo.share_type == ShareType.PUBLIC
            )
        )
    
    # Apply additional filters
    if query:
        search_term = f"%{query}%"
        query_builder = query_builder.where(
            or_(
                Photo.title.ilike(search_term),
                Photo.description.ilike(search_term),
                Photo.original_filename.ilike(search_term)
            )
        )
    
    if tags:
        tag_list = [tag.strip().lower() for tag in tags.split(",") if tag.strip()]
        if tag_list:
            # PostgreSQL JSON contains check
            for tag in tag_list:
                query_builder = query_builder.where(
                    Photo.tags.contains([tag])
                )
    
    if share_type:
        try:
            query_builder = query_builder.where(
                Photo.share_type == ShareType(share_type)
            )
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid share_type"
            )
    
    # Album filter
    if album_id:
        query_builder = query_builder.join(photo_albums).where(
            photo_albums.c.album_id == album_id
        )
    
    # Apply sorting
    sort_column = getattr(Photo, sort_by)
    if sort_order == "desc":
        query_builder = query_builder.order_by(desc(sort_column))
    else:
        query_builder = query_builder.order_by(asc(sort_column))
    
    # Get total count
    count_query = select(func.count()).select_from(query_builder.subquery())
    total_result = await db.execute(count_query)
    total_count = total_result.scalar()
    
    # Apply pagination
    offset = (page - 1) * page_size
    query_builder = query_builder.offset(offset).limit(page_size)
    
    # Execute query
    result = await db.execute(query_builder)
    photos = result.scalars().all()
    
    # Convert to response format
    photo_summaries = []
    for photo in photos:
        summary = PhotoSummary(
            id=photo.id,
            uuid=str(photo.uuid),
            filename=photo.filename,
            title=photo.title,
            thumbnail_url=storage.get_file_url(photo.thumbnail_path, 'small'),
            width=photo.width,
            height=photo.height,
            status=photo.status.value,
            share_type=photo.share_type.value,
            owner_id=photo.owner_id,
            created_at=photo.created_at,
            view_count=photo.view_count or 0,
            like_count=0,  # Would be calculated from likes table
            comment_count=0  # Would be calculated from comments table
        )
        photo_summaries.append(summary)
    
    # Calculate pagination info
    total_pages = (total_count + page_size - 1) // page_size
    
    # Log search activity
    SecurityUtils.log_security_event(
        "photo_search",
        {
            "query_params": {
                "query": query,
                "tags": tags,
                "album_id": album_id,
                "owner_id": owner_id
            },
            "results_count": len(photos),
            "total_count": total_count
        },
        user_email=current_user.email,
        client_ip=client_ip
    )
    
    return PhotoSearchResponse(
        photos=photo_summaries,
        total_count=total_count,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        has_next=page < total_pages,
        has_previous=page > 1
    )

# ==========================================
# STORAGE QUOTA MANAGEMENT
# ==========================================

@router.get("/quota", response_model=StorageQuotaInfo)
async def get_storage_quota(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_auth_and_permission(ResourceType.USER, ActionType.READ))
):
    """Get current user's storage quota information."""
    quota = await get_or_create_quota(db, current_user.id)
    
    return StorageQuotaInfo(
        quota_limit=quota.quota_limit,
        used_storage=quota.used_storage,
        available_storage=quota.available_storage,
        usage_percentage=quota.usage_percentage,
        file_count=quota.file_count,
        max_files=quota.max_files,
        quota_type=quota.quota_type,
        last_calculated_at=quota.last_calculated_at
    )

# ==========================================
# HELPER FUNCTIONS
# ==========================================

async def check_user_quota(db: AsyncSession, user_id: int, additional_size: int) -> Dict[str, Any]:
    """Check if user has enough quota for additional storage."""
    # Rate limit quota checks to prevent abuse
    photo_rate_limiter = get_photo_rate_limiter()
    rate_limit_result = await photo_rate_limiter.check_quota_usage_rate_limit(user_id)
    
    if not rate_limit_result.allowed:
        return {
            'over_quota': True,
            'available_storage': 0,
            'usage_percentage': 100.0,
            'max_file_size': 0,
            'rate_limited': True
        }
    
    quota = await get_or_create_quota(db, user_id)
    
    return {
        'over_quota': (quota.used_storage + additional_size) > quota.quota_limit,
        'available_storage': quota.available_storage,
        'usage_percentage': quota.usage_percentage,
        'max_file_size': min(50 * 1024 * 1024, quota.available_storage),  # 50MB or available space
        'rate_limited': False
    }

async def get_or_create_quota(db: AsyncSession, user_id: int) -> StorageQuota:
    """Get or create storage quota for user."""
    result = await db.execute(
        select(StorageQuota).where(StorageQuota.user_id == user_id)
    )
    quota = result.scalar_one_or_none()
    
    if not quota:
        quota = StorageQuota(user_id=user_id)
        db.add(quota)
        await db.commit()
        await db.refresh(quota)
    
    return quota

async def update_user_quota(db: AsyncSession, user_id: int, size_delta: int):
    """Update user's storage quota usage."""
    quota = await get_or_create_quota(db, user_id)
    quota.used_storage = max(0, quota.used_storage + size_delta)
    quota.last_calculated_at = datetime.now(timezone.utc)
    await db.commit()

async def check_photo_access(rbac: RBACService, user_id: int, photo: Photo) -> bool:
    """Check if user has access to view photo."""
    auth_result = await rbac.check_photo_access(user_id, photo.id, ActionType.READ)
    return auth_result.authorized

async def log_photo_view(db: AsyncSession, photo_id: int, user_id: int, client_ip: str):
    """Log photo view for analytics."""
    # Update view count
    result = await db.execute(
        select(Photo).where(Photo.id == photo_id)
    )
    photo = result.scalar_one_or_none()
    
    if photo:
        photo.view_count = (photo.view_count or 0) + 1
        photo.last_viewed_at = datetime.now(timezone.utc)
        await db.commit()

async def build_photo_detail(db: AsyncSession, photo: Photo, viewing_user_id: int) -> PhotoDetail:
    """Build detailed photo response with user-specific permissions."""
    
    # Generate URLs for different sizes
    photo_url = storage.get_file_url(photo.file_path)
    
    thumbnails = []
    if photo.thumbnail_path:
        thumbnails.append({
            'url': storage.get_file_url(photo.thumbnail_path, 'small'),
            'width': 150,
            'height': 150,
            'size': 'small'
        })
    
    if photo.medium_path:
        thumbnails.append({
            'url': storage.get_file_url(photo.medium_path, 'medium'),
            'width': 500,
            'height': 500,
            'size': 'medium'
        })
    
    if photo.large_path:
        thumbnails.append({
            'url': storage.get_file_url(photo.large_path, 'large'),
            'width': 1200,
            'height': 1200,
            'size': 'large'
        })
    
    # Build EXIF data response
    exif_data = None
    if photo.exif_data:
        exif_data = {
            'camera_make': photo.camera_make,
            'camera_model': photo.camera_model,
            'taken_at': photo.taken_at,
            # Add other EXIF fields as needed
        }
    
    # Check user permissions
    can_edit = photo.owner_id == viewing_user_id
    can_delete = photo.owner_id == viewing_user_id
    can_share = photo.owner_id == viewing_user_id
    
    return PhotoDetail(
        id=photo.id,
        uuid=str(photo.uuid),
        filename=photo.filename,
        original_filename=photo.original_filename,
        file_size=photo.file_size,
        mime_type=photo.mime_type,
        width=photo.width,
        height=photo.height,
        aspect_ratio=photo.aspect_ratio,
        url=photo_url,
        thumbnails=thumbnails,
        status=photo.status.value,
        share_type=photo.share_type.value,
        title=photo.title,
        description=photo.description,
        tags=photo.tags or [],
        exif_data=exif_data,
        view_count=photo.view_count or 0,
        download_count=photo.download_count or 0,
        owner_id=photo.owner_id,
        created_at=photo.created_at,
        updated_at=photo.updated_at,
        can_edit=can_edit,
        can_delete=can_delete,
        can_share=can_share
    )