"""
Secure file storage system with comprehensive validation and threat prevention.
Implements secure file upload, storage, and retrieval with multiple backend support.
"""
import os
import hashlib
import uuid
import shutil
import mimetypes
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, BinaryIO
from datetime import datetime, timezone
import logging
from PIL import Image, ExifTags, ImageOps
from PIL.ExifTags import TAGS
import magic
import tempfile
import json

from services.security import SecurityUtils

logger = logging.getLogger(__name__)

# Security constants
ALLOWED_MIME_TYPES = {
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
    'image/webp': ['.webp'],
    'image/gif': ['.gif']
}

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MIN_FILE_SIZE = 1024  # 1KB
MAX_IMAGE_DIMENSION = 10000  # 10000px max width/height
MIN_IMAGE_DIMENSION = 1  # 1px min width/height

# Thumbnail sizes
THUMBNAIL_SIZES = {
    'small': (150, 150),
    'medium': (500, 500),
    'large': (1200, 1200)
}

class FileValidationError(Exception):
    """Custom exception for file validation errors."""
    pass

class StorageError(Exception):
    """Custom exception for storage operations."""
    pass

class FileValidator:
    """
    Comprehensive file validation with security checks.
    """
    
    def __init__(self):
        self.magic_mime = magic.Magic(mime=True)
    
    def validate_file(self, file_path: str, original_filename: str, 
                     max_size: int = MAX_FILE_SIZE) -> Dict[str, Any]:
        """
        Comprehensive file validation with security checks.
        
        Args:
            file_path: Path to uploaded file
            original_filename: Original filename from user
            max_size: Maximum allowed file size in bytes
            
        Returns:
            Dict with validation results and file metadata
            
        Raises:
            FileValidationError: If file fails validation
        """
        try:
            # Basic file checks
            if not os.path.exists(file_path):
                raise FileValidationError("File does not exist")
            
            file_size = os.path.getsize(file_path)
            if file_size < MIN_FILE_SIZE:
                raise FileValidationError("File too small")
            
            if file_size > max_size:
                raise FileValidationError(f"File too large. Maximum size: {max_size} bytes")
            
            # MIME type validation using python-magic (more secure than file extension)
            detected_mime = self.magic_mime.from_file(file_path)
            if detected_mime not in ALLOWED_MIME_TYPES:
                raise FileValidationError(f"Unsupported file type: {detected_mime}")
            
            # Extension validation
            file_ext = Path(original_filename).suffix.lower()
            allowed_extensions = ALLOWED_MIME_TYPES[detected_mime]
            if file_ext not in allowed_extensions:
                raise FileValidationError(
                    f"File extension {file_ext} doesn't match MIME type {detected_mime}"
                )
            
            # Image-specific validation
            image_metadata = self._validate_image_content(file_path)
            
            # Security scans
            self._security_scan_file(file_path, file_size)
            
            # Generate file hash for deduplication
            file_hash = self._calculate_file_hash(file_path)
            
            return {
                'valid': True,
                'file_size': file_size,
                'mime_type': detected_mime,
                'file_hash': file_hash,
                'image_metadata': image_metadata,
                'security_scan': 'passed'
            }
            
        except FileValidationError:
            raise
        except Exception as e:
            logger.error(f"File validation error: {e}")
            raise FileValidationError(f"Validation failed: {str(e)}")
    
    def _validate_image_content(self, file_path: str) -> Dict[str, Any]:
        """
        Validate image content and extract metadata.
        """
        try:
            with Image.open(file_path) as img:
                # Verify it's a valid image
                img.verify()
                
            # Re-open for metadata extraction (verify() closes the image)
            with Image.open(file_path) as img:
                width, height = img.size
                
                # Dimension checks
                if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
                    raise FileValidationError(f"Image too large. Max dimensions: {MAX_IMAGE_DIMENSION}px")
                
                if width < MIN_IMAGE_DIMENSION or height < MIN_IMAGE_DIMENSION:
                    raise FileValidationError(f"Image too small. Min dimensions: {MIN_IMAGE_DIMENSION}px")
                
                # Extract basic metadata
                metadata = {
                    'width': width,
                    'height': height,
                    'aspect_ratio': round(width / height, 4),
                    'format': img.format,
                    'mode': img.mode
                }
                
                # Extract EXIF data if available
                exif_data = self._extract_exif_data(img)
                if exif_data:
                    metadata['exif'] = exif_data
                
                return metadata
                
        except FileValidationError:
            raise
        except Exception as e:
            raise FileValidationError(f"Invalid image file: {str(e)}")
    
    def _extract_exif_data(self, img: Image.Image) -> Optional[Dict[str, Any]]:
        """
        Extract and sanitize EXIF data from image.
        """
        try:
            exif_dict = img._getexif()
            if not exif_dict:
                return None
            
            sanitized_exif = {}
            
            # Safe EXIF tags to extract (excluding potentially sensitive location data)
            safe_tags = {
                'Make', 'Model', 'Software', 'DateTime', 'DateTimeOriginal',
                'ExposureTime', 'FNumber', 'ISO', 'FocalLength', 'Flash',
                'WhiteBalance', 'ExposureMode', 'MeteringMode'
            }
            
            for tag_id, value in exif_dict.items():
                tag_name = TAGS.get(tag_id, tag_id)
                
                # Only include safe tags
                if tag_name in safe_tags:
                    # Convert datetime objects to strings
                    if isinstance(value, datetime):
                        value = value.isoformat()
                    elif hasattr(value, 'isoformat'):
                        value = value.isoformat()
                    
                    # Ensure value is JSON serializable
                    try:
                        json.dumps(value)
                        sanitized_exif[tag_name] = value
                    except (TypeError, ValueError):
                        # Skip non-serializable values
                        continue
            
            return sanitized_exif if sanitized_exif else None
            
        except Exception as e:
            logger.warning(f"EXIF extraction failed: {e}")
            return None
    
    def _security_scan_file(self, file_path: str, file_size: int):
        """
        Perform security scans on uploaded file.
        """
        # Basic virus scan patterns (in production, integrate with proper AV)
        suspicious_patterns = [
            b'<script',
            b'javascript:',
            b'<?php',
            b'<html',
            b'<iframe',
            b'eval(',
            b'exec(',
            b'system(',
            b'shell_exec(',
        ]
        
        # Read first few KB for pattern matching
        scan_size = min(8192, file_size)
        
        with open(file_path, 'rb') as f:
            content_sample = f.read(scan_size)
            
            # Convert to lowercase for case-insensitive matching
            content_lower = content_sample.lower()
            
            for pattern in suspicious_patterns:
                if pattern in content_lower:
                    SecurityUtils.log_security_event(
                        "malicious_file_upload_attempt",
                        {
                            "pattern_detected": pattern.decode('utf-8', errors='ignore'),
                            "file_size": file_size,
                            "file_path": file_path
                        }
                    )
                    raise FileValidationError("Potentially malicious file content detected")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of file for deduplication.
        """
        hasher = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        
        return hasher.hexdigest()

class ImageProcessor:
    """
    Image processing pipeline for thumbnails and optimization.
    """
    
    def __init__(self):
        self.thumbnail_sizes = THUMBNAIL_SIZES
    
    def process_image(self, input_path: str, output_dir: str, 
                     filename_base: str, preserve_exif: bool = False,
                     auto_orient: bool = True) -> Dict[str, str]:
        """
        Process image: generate thumbnails, optimize, and handle orientation.
        
        Args:
            input_path: Path to original image
            output_dir: Directory for processed images
            filename_base: Base filename for processed images
            preserve_exif: Whether to preserve EXIF data
            auto_orient: Whether to auto-orient based on EXIF
            
        Returns:
            Dict mapping size names to file paths
        """
        processed_files = {}
        
        try:
            with Image.open(input_path) as img:
                # Auto-orient if requested
                if auto_orient:
                    img = ImageOps.exif_transpose(img)
                
                # Convert RGBA to RGB if saving as JPEG
                if img.mode in ('RGBA', 'LA', 'P') and input_path.lower().endswith('.jpg'):
                    # Create white background for transparency
                    rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                    rgb_img.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                    img = rgb_img
                
                # Generate thumbnails
                for size_name, (width, height) in self.thumbnail_sizes.items():
                    thumbnail = self._create_thumbnail(img, width, height)
                    
                    # Generate output filename
                    ext = '.jpg'  # Always save thumbnails as JPEG for consistency
                    thumbnail_filename = f"{filename_base}_{size_name}{ext}"
                    thumbnail_path = os.path.join(output_dir, thumbnail_filename)
                    
                    # Save thumbnail
                    save_kwargs = {
                        'format': 'JPEG',
                        'quality': 85,
                        'optimize': True
                    }
                    
                    # Include EXIF if preserving
                    if preserve_exif and hasattr(img, '_getexif') and img._getexif():
                        save_kwargs['exif'] = img.info.get('exif', b'')
                    
                    thumbnail.save(thumbnail_path, **save_kwargs)
                    processed_files[size_name] = thumbnail_path
                
                return processed_files
                
        except Exception as e:
            logger.error(f"Image processing failed: {e}")
            # Cleanup any partially created files
            for path in processed_files.values():
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except Exception as e:
                        logger.warning(f"Failed to cleanup processed file {path}: {e}")
            raise StorageError(f"Image processing failed: {str(e)}")
    
    def _create_thumbnail(self, img: Image.Image, max_width: int, max_height: int) -> Image.Image:
        """
        Create thumbnail with proper aspect ratio preservation.
        """
        # Use thumbnail method which preserves aspect ratio
        img_copy = img.copy()
        img_copy.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
        
        # Ensure minimum quality
        if img_copy.size[0] < 50 or img_copy.size[1] < 50:
            # Don't create thumbnails that are too small
            raise ValueError("Thumbnail would be too small")
        
        return img_copy

class SecureFileStorage:
    """
    Secure file storage with multiple backend support.
    """
    
    def __init__(self, base_storage_path: str = None):
        """
        Initialize secure file storage.
        
        Args:
            base_storage_path: Base directory for file storage
        """
        self.base_path = Path(base_storage_path or os.getenv('UPLOAD_STORAGE_PATH', './uploads'))
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        self.photos_path = self.base_path / 'photos'
        self.thumbnails_path = self.base_path / 'thumbnails'
        self.temp_path = self.base_path / 'temp'
        
        for path in [self.photos_path, self.thumbnails_path, self.temp_path]:
            path.mkdir(parents=True, exist_ok=True)
        
        self.validator = FileValidator()
        self.processor = ImageProcessor()
        
        # Import advanced processor here to avoid circular imports
        try:
            from services.advanced_image_processor import get_advanced_image_processor
            self.advanced_processor = get_advanced_image_processor()
        except ImportError:
            self.advanced_processor = None
    
    def store_uploaded_file(self, uploaded_file: BinaryIO, original_filename: str,
                          user_id: int, **options) -> Dict[str, Any]:
        """
        Store uploaded file with comprehensive security checks.
        
        Args:
            uploaded_file: Uploaded file object
            original_filename: Original filename from user
            user_id: ID of uploading user
            **options: Additional processing options
            
        Returns:
            Dict with storage information and file metadata
        """
        temp_file_path = None
        
        try:
            # Create temporary file for validation
            temp_file_path = self._create_temp_file(uploaded_file)
            
            # Validate file
            validation_result = self.validator.validate_file(
                temp_file_path, original_filename, options.get('max_file_size', MAX_FILE_SIZE)
            )
            
            # Check for duplicate files
            file_hash = validation_result['file_hash']
            existing_file = self._check_duplicate_file(file_hash, user_id)
            if existing_file and not options.get('allow_duplicates', False):
                return {
                    'duplicate': True,
                    'existing_file_id': existing_file['id'],
                    'message': 'File already exists'
                }
            
            # Generate secure filename and path
            file_uuid = str(uuid.uuid4())
            file_ext = Path(original_filename).suffix.lower()
            secure_filename = f"{file_uuid}{file_ext}"
            
            # Create year/month directory structure
            now = datetime.now(timezone.utc)
            storage_dir = self.photos_path / str(user_id) / str(now.year) / f"{now.month:02d}"
            storage_dir.mkdir(parents=True, exist_ok=True)
            
            final_file_path = storage_dir / secure_filename
            
            # Move file to final location
            shutil.move(temp_file_path, final_file_path)
            temp_file_path = None  # Prevent cleanup of moved file
            
            # Set secure file permissions
            os.chmod(final_file_path, 0o640)  # Owner read/write, group read only
            
            # Process image (generate thumbnails)
            thumbnail_dir = self.thumbnails_path / str(user_id) / str(now.year) / f"{now.month:02d}"
            thumbnail_dir.mkdir(parents=True, exist_ok=True)
            
            # Use advanced processor if available and requested
            use_advanced = options.get('use_advanced_processing', True)
            if self.advanced_processor and use_advanced:
                try:
                    processing_options = {
                        'preserve_exif': options.get('preserve_exif', False),
                        'auto_orient': options.get('auto_orient', True),
                        'auto_enhance': options.get('auto_enhance', False),
                        'smart_crop': options.get('smart_crop', False),
                        'generate_webp': options.get('generate_webp', True),
                        'generate_progressive': options.get('generate_progressive', True),
                        'apply_unsharp_mask': options.get('apply_unsharp_mask', True)
                    }
                    
                    advanced_result = self.advanced_processor.process_image_advanced(
                        str(final_file_path),
                        str(thumbnail_dir),
                        file_uuid,
                        processing_options
                    )
                    
                    # Convert advanced processor output to legacy format
                    processed_files = {}
                    for size_name, file_info in advanced_result['files'].items():
                        if isinstance(file_info, dict) and 'path' in file_info:
                            processed_files[size_name] = file_info['path']
                        else:
                            processed_files[size_name] = file_info
                    
                    # Store advanced processing metadata
                    validation_result['advanced_processing'] = advanced_result['metadata']
                    
                except Exception as e:
                    logger.warning(f"Advanced processing failed, falling back to basic: {e}")
                    # Fall back to basic processing
                    processed_files = self.processor.process_image(
                        str(final_file_path),
                        str(thumbnail_dir),
                        file_uuid,
                        preserve_exif=options.get('preserve_exif', False),
                        auto_orient=options.get('auto_orient', True)
                    )
            else:
                # Use basic processor
                processed_files = self.processor.process_image(
                    str(final_file_path),
                    str(thumbnail_dir),
                    file_uuid,
                    preserve_exif=options.get('preserve_exif', False),
                    auto_orient=options.get('auto_orient', True)
                )
            
            # Log successful upload
            SecurityUtils.log_security_event(
                "file_upload_success",
                {
                    "user_id": user_id,
                    "filename": secure_filename,
                    "original_filename": original_filename,
                    "file_size": validation_result['file_size'],
                    "mime_type": validation_result['mime_type']
                },
                user_email=None,  # Would be populated by calling code
                client_ip=None    # Would be populated by calling code
            )
            
            return {
                'success': True,
                'file_path': str(final_file_path.relative_to(self.base_path)),
                'filename': secure_filename,
                'thumbnails': {
                    size: str(Path(path).relative_to(self.base_path))
                    for size, path in processed_files.items()
                },
                'metadata': {
                    'file_size': validation_result['file_size'],
                    'mime_type': validation_result['mime_type'],
                    'file_hash': validation_result['file_hash'],
                    'image_metadata': validation_result['image_metadata']
                }
            }
            
        except (FileValidationError, StorageError) as e:
            # Log security event for validation failures
            SecurityUtils.log_security_event(
                "file_upload_validation_failed",
                {
                    "user_id": user_id,
                    "original_filename": original_filename,
                    "error": str(e)
                }
            )
            raise
        except Exception as e:
            logger.error(f"File storage error: {e}")
            raise StorageError(f"Storage failed: {str(e)}")
        finally:
            # Cleanup temporary file if it still exists
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except Exception as cleanup_error:
                    logger.warning(f"Failed to cleanup temp file: {cleanup_error}")
    
    def _create_temp_file(self, uploaded_file: BinaryIO) -> str:
        """
        Create temporary file from uploaded file object.
        """
        with tempfile.NamedTemporaryFile(
            dir=self.temp_path, 
            delete=False, 
            prefix='upload_', 
            suffix='.tmp'
        ) as temp_file:
            
            # Read and write in chunks to handle large files
            while chunk := uploaded_file.read(8192):
                temp_file.write(chunk)
            
            temp_file_path = temp_file.name
        
        # Reset uploaded file pointer for potential reuse
        uploaded_file.seek(0)
        
        return temp_file_path
    
    def _check_duplicate_file(self, file_hash: str, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Check if file with same hash already exists for user.
        In production, this would query the database.
        """
        # This is a placeholder - in real implementation, query the database
        # for existing photos with the same hash for this user
        return None
    
    def delete_file(self, file_path: str, thumbnails: Dict[str, str] = None) -> bool:
        """
        Securely delete file and associated thumbnails.
        
        Args:
            file_path: Path to main file
            thumbnails: Dict of thumbnail paths
            
        Returns:
            bool: True if deletion successful
        """
        try:
            full_file_path = self.base_path / file_path
            
            # Delete main file
            if full_file_path.exists():
                os.remove(full_file_path)
            
            # Delete thumbnails
            if thumbnails:
                for thumbnail_path in thumbnails.values():
                    full_thumbnail_path = self.base_path / thumbnail_path
                    if full_thumbnail_path.exists():
                        os.remove(full_thumbnail_path)
            
            return True
            
        except Exception as e:
            logger.error(f"File deletion error: {e}")
            return False
    
    def get_file_url(self, file_path: str, size: Optional[str] = None) -> str:
        """
        Generate secure URL for file access.
        
        Args:
            file_path: Path to file
            size: Optional thumbnail size
            
        Returns:
            str: Secure URL for file access
        """
        # In production, this might generate signed URLs or use a CDN
        base_url = os.getenv('MEDIA_URL', '/media')
        
        if size and size in THUMBNAIL_SIZES:
            # Generate thumbnail URL
            path_parts = Path(file_path).parts
            filename_without_ext = Path(file_path).stem
            ext = '.jpg'  # Thumbnails are always JPEG
            thumbnail_filename = f"{filename_without_ext}_{size}{ext}"
            thumbnail_path = Path('thumbnails') / Path(*path_parts[1:]).parent / thumbnail_filename
            return f"{base_url}/{thumbnail_path}"
        else:
            return f"{base_url}/{file_path}"
    
    def cleanup_temp_files(self, max_age_hours: int = 24):
        """
        Clean up old temporary files.
        
        Args:
            max_age_hours: Maximum age of temp files in hours
        """
        try:
            cutoff_time = datetime.now().timestamp() - (max_age_hours * 3600)
            
            for temp_file in self.temp_path.glob('*'):
                if temp_file.is_file() and temp_file.stat().st_mtime < cutoff_time:
                    temp_file.unlink()
                    
            logger.info(f"Cleaned up temporary files older than {max_age_hours} hours")
            
        except Exception as e:
            logger.error(f"Temp file cleanup error: {e}")
    
    def optimize_existing_photo(self, photo_file_path: str, optimization_level: str = 'balanced') -> Dict[str, Any]:
        """
        Optimize an existing photo file.
        
        Args:
            photo_file_path: Path to photo file relative to base_path
            optimization_level: 'aggressive', 'balanced', or 'conservative'
            
        Returns:
            Dict with optimization results
        """
        if not self.advanced_processor:
            return {'success': False, 'error': 'Advanced processor not available'}
        
        try:
            full_path = self.base_path / photo_file_path
            if not full_path.exists():
                return {'success': False, 'error': 'File not found'}
            
            # Create temporary file for optimization
            temp_path = full_path.with_suffix(f'.optimizing{full_path.suffix}')
            
            # Perform optimization
            result = self.advanced_processor.optimize_existing_image(
                str(full_path), str(temp_path), optimization_level
            )
            
            if result.get('success', False):
                # Replace original with optimized version
                temp_path.replace(full_path)
                
                SecurityUtils.log_security_event(
                    "photo_optimization_completed",
                    {
                        "file_path": photo_file_path,
                        "optimization_level": optimization_level,
                        "compression_ratio": result.get('compression_ratio', 0),
                        "size_reduction": result.get('original_size', 0) - result.get('optimized_size', 0)
                    }
                )
            else:
                # Clean up temp file if optimization failed
                if temp_path.exists():
                    temp_path.unlink()
            
            return result
            
        except Exception as e:
            logger.error(f"Photo optimization error: {e}")
            return {'success': False, 'error': str(e)}
    
    def batch_optimize_photos(self, photo_paths: List[str], optimization_level: str = 'balanced') -> Dict[str, Any]:
        """
        Optimize multiple photos in batch.
        
        Args:
            photo_paths: List of photo file paths relative to base_path
            optimization_level: Optimization level to apply
            
        Returns:
            Dict with batch optimization results
        """
        results = {
            'successful': 0,
            'failed': 0,
            'total_size_saved': 0,
            'individual_results': {}
        }
        
        for photo_path in photo_paths:
            try:
                result = self.optimize_existing_photo(photo_path, optimization_level)
                results['individual_results'][photo_path] = result
                
                if result.get('success', False):
                    results['successful'] += 1
                    size_saved = result.get('original_size', 0) - result.get('optimized_size', 0)
                    results['total_size_saved'] += size_saved
                else:
                    results['failed'] += 1
                    
            except Exception as e:
                results['failed'] += 1
                results['individual_results'][photo_path] = {
                    'success': False,
                    'error': str(e)
                }
        
        SecurityUtils.log_security_event(
            "batch_photo_optimization_completed",
            {
                "total_photos": len(photo_paths),
                "successful": results['successful'],
                "failed": results['failed'],
                "total_size_saved": results['total_size_saved'],
                "optimization_level": optimization_level
            }
        )
        
        return results

# Global storage instance
storage = SecureFileStorage()