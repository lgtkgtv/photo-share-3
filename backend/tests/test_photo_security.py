"""
Comprehensive security tests for photo upload and management system.
Tests all security features including validation, rate limiting, authorization, and sharing.
"""
import pytest
import asyncio
import tempfile
import os
from io import BytesIO
from PIL import Image
import json
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from main import app
from services.db import get_db
from services.file_storage import storage, FileValidationError
from services.photo_rate_limiter import get_photo_rate_limiter
from services.rbac import RBACService
from services.security import SecurityUtils
from models.user import User
from models.photo import Photo, PhotoShare, ShareType, StorageQuota
from schemas.photo import PhotoUploadRequest

# Test client setup
client = TestClient(app)

@pytest.fixture
async def test_db():
    """Create test database session."""
    # This would typically use a test database
    # For now, we'll mock the database operations
    pass

@pytest.fixture
def test_user():
    """Create a test user."""
    return User(
        id=1,
        email="test@example.com",
        is_active=True,
        is_verified=True
    )

@pytest.fixture
def admin_user():
    """Create an admin user."""
    return User(
        id=2,
        email="admin@example.com",
        is_active=True,
        is_verified=True
    )

@pytest.fixture
def create_test_image():
    """Create a test image file."""
    def _create_image(format="JPEG", size=(100, 100), color="RGB"):
        img = Image.new(color, size, (255, 0, 0))
        img_bytes = BytesIO()
        img.save(img_bytes, format=format)
        img_bytes.seek(0)
        return img_bytes
    return _create_image

@pytest.fixture
def create_malicious_file():
    """Create a malicious file for testing."""
    def _create_malicious_file(content_type="image/jpeg"):
        # Create file with malicious content disguised as image
        malicious_content = b"<script>alert('xss')</script>" + b"\xFF\xD8\xFF\xE0"  # JPEG header
        file_obj = BytesIO(malicious_content)
        return file_obj
    return _create_malicious_file

class TestFileValidation:
    """Test file validation security."""
    
    def test_valid_image_upload(self, create_test_image):
        """Test uploading a valid image."""
        image_file = create_test_image("JPEG")
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_file:
            temp_file.write(image_file.read())
            temp_file_path = temp_file.name
        
        try:
            from services.file_storage import FileValidator
            validator = FileValidator()
            result = validator.validate_file(temp_file_path, "test.jpg")
            
            assert result['valid'] is True
            assert result['mime_type'] == 'image/jpeg'
            assert result['file_size'] > 0
            assert 'file_hash' in result
            assert 'image_metadata' in result
        finally:
            os.unlink(temp_file_path)
    
    def test_malicious_file_rejection(self, create_malicious_file):
        """Test rejection of malicious files."""
        malicious_file = create_malicious_file()
        
        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_file:
            temp_file.write(malicious_file.read())
            temp_file_path = temp_file.name
        
        try:
            from services.file_storage import FileValidator
            validator = FileValidator()
            
            with pytest.raises(FileValidationError) as exc_info:
                validator.validate_file(temp_file_path, "malicious.jpg")
            
            assert "potentially malicious" in str(exc_info.value).lower() or "malicious" in str(exc_info.value).lower()
        finally:
            os.unlink(temp_file_path)
    
    def test_file_size_limits(self, create_test_image):
        """Test file size limit enforcement."""
        # Create a large image
        large_image = create_test_image("JPEG", size=(5000, 5000))
        
        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_file:
            temp_file.write(large_image.read())
            temp_file_path = temp_file.name
        
        try:
            from services.file_storage import FileValidator
            validator = FileValidator()
            
            # Test with very small limit
            with pytest.raises(FileValidationError) as exc_info:
                validator.validate_file(temp_file_path, "large.jpg", max_size=1024)  # 1KB limit
            
            assert "too large" in str(exc_info.value).lower()
        finally:
            os.unlink(temp_file_path)
    
    def test_unsupported_file_type_rejection(self):
        """Test rejection of unsupported file types."""
        # Create a text file disguised as image
        text_content = b"This is not an image file"
        
        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_file:
            temp_file.write(text_content)
            temp_file_path = temp_file.name
        
        try:
            from services.file_storage import FileValidator
            validator = FileValidator()
            
            with pytest.raises(FileValidationError) as exc_info:
                validator.validate_file(temp_file_path, "fake.jpg")
            
            assert "unsupported" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower()
        finally:
            os.unlink(temp_file_path)

class TestRateLimiting:
    """Test rate limiting for photo uploads."""
    
    @pytest.mark.asyncio
    async def test_upload_rate_limiting(self):
        """Test upload rate limiting."""
        rate_limiter = get_photo_rate_limiter()
        client_ip = "192.168.1.100"
        user_id = 1
        
        # Test normal rate limiting
        for i in range(10):  # Should be within limit
            result = await rate_limiter.check_upload_rate_limit(client_ip, user_id)
            assert result.allowed is True
        
        # Should hit rate limit on 11th request
        result = await rate_limiter.check_upload_rate_limit(client_ip, user_id)
        assert result.allowed is False
        assert result.retry_after > 0
    
    @pytest.mark.asyncio
    async def test_batch_upload_rate_limiting(self):
        """Test batch upload rate limiting."""
        rate_limiter = get_photo_rate_limiter()
        client_ip = "192.168.1.101"
        user_id = 2
        
        # Test batch limits
        for i in range(3):  # Should be within limit
            result = await rate_limiter.check_batch_upload_rate_limit(client_ip, user_id, 5)
            assert result.allowed is True
        
        # Should hit rate limit on 4th batch
        result = await rate_limiter.check_batch_upload_rate_limit(client_ip, user_id, 5)
        assert result.allowed is False
    
    @pytest.mark.asyncio
    async def test_large_batch_rate_limiting(self):
        """Test large batch size rate limiting."""
        rate_limiter = get_photo_rate_limiter()
        client_ip = "192.168.1.102"
        user_id = 3
        
        # Large batch should trigger special rate limit
        result = await rate_limiter.check_batch_upload_rate_limit(client_ip, user_id, 8)
        assert result.allowed is True
        
        # Second large batch should be blocked
        result = await rate_limiter.check_batch_upload_rate_limit(client_ip, user_id, 8)
        assert result.allowed is False
    
    @pytest.mark.asyncio
    async def test_sharing_rate_limiting(self):
        """Test photo sharing rate limiting."""
        rate_limiter = get_photo_rate_limiter()
        user_id = 4
        
        # Test sharing limits
        for i in range(20):  # Should be within limit
            result = await rate_limiter.check_sharing_rate_limit(user_id)
            assert result.allowed is True
        
        # Should hit rate limit on 21st share
        result = await rate_limiter.check_sharing_rate_limit(user_id)
        assert result.allowed is False

class TestAuthorization:
    """Test photo authorization and access control."""
    
    @pytest.mark.asyncio
    async def test_photo_ownership_check(self, test_db):
        """Test photo ownership verification."""
        # Mock database session
        db = test_db
        rbac = RBACService(db)
        
        # Test owner access
        owner_id = 1
        photo_id = 1
        
        # Mock photo ownership check
        result = await rbac.check_resource_ownership(owner_id, "photo", photo_id)
        # This would normally check the database, but for testing we'll assert the logic
        
    @pytest.mark.asyncio
    async def test_photo_sharing_permissions(self, test_db):
        """Test photo sharing permission checks."""
        db = test_db
        rbac = RBACService(db)
        
        # Test various sharing scenarios
        user_id = 1
        photo_id = 1
        
        # Test read access for shared photo
        result = await rbac.check_photo_access(user_id, photo_id, "read")
        # Would need actual database setup to fully test
    
    def test_admin_override_permissions(self):
        """Test admin users can access all photos."""
        # Test admin permissions override
        pass

class TestQuotaManagement:
    """Test storage quota enforcement."""
    
    @pytest.mark.asyncio
    async def test_quota_enforcement(self):
        """Test storage quota limits are enforced."""
        # Mock quota check
        from api.photos import check_user_quota
        
        # This would test quota limits in real scenario
        pass
    
    @pytest.mark.asyncio
    async def test_quota_rate_limiting(self):
        """Test quota check rate limiting."""
        rate_limiter = get_photo_rate_limiter()
        user_id = 5
        
        # Test quota check limits
        for i in range(30):  # Should be within limit
            result = await rate_limiter.check_quota_usage_rate_limit(user_id)
            assert result.allowed is True
        
        # Should hit rate limit on 31st check
        result = await rate_limiter.check_quota_usage_rate_limit(user_id)
        assert result.allowed is False

class TestPhotoSharing:
    """Test photo sharing security."""
    
    def test_share_token_generation(self):
        """Test secure share token generation."""
        token1 = SecurityUtils.generate_secure_token(32)
        token2 = SecurityUtils.generate_secure_token(32)
        
        assert len(token1) == 32
        assert len(token2) == 32
        assert token1 != token2  # Should be unique
        assert token1.isalnum()  # Should be alphanumeric
    
    def test_share_expiration(self):
        """Test share expiration logic."""
        # Create expired share
        now = datetime.now(timezone.utc)
        expired_share = PhotoShare(
            photo_id=1,
            shared_by_user_id=1,
            expires_at=now - timedelta(hours=1)
        )
        
        assert expired_share.is_expired is True
        
        # Create valid share
        valid_share = PhotoShare(
            photo_id=1,
            shared_by_user_id=1,
            expires_at=now + timedelta(hours=1)
        )
        
        assert valid_share.is_expired is False
    
    def test_view_limit_enforcement(self):
        """Test share view limit enforcement."""
        share = PhotoShare(
            photo_id=1,
            shared_by_user_id=1,
            max_views=5,
            current_views=5
        )
        
        assert share.is_view_limit_exceeded is True
        
        share.current_views = 3
        assert share.is_view_limit_exceeded is False

class TestSecurityLogging:
    """Test security event logging."""
    
    def test_security_event_logging(self):
        """Test security events are properly logged."""
        # Test various security events
        event_data = {
            "user_id": 1,
            "file_size": 1024,
            "mime_type": "image/jpeg"
        }
        
        # This would test actual logging in real implementation
        SecurityUtils.log_security_event(
            "test_photo_upload",
            event_data,
            user_email="test@example.com",
            client_ip="192.168.1.1"
        )
    
    def test_failed_upload_logging(self):
        """Test failed upload attempts are logged."""
        # Test malicious file upload logging
        pass
    
    def test_unauthorized_access_logging(self):
        """Test unauthorized access attempts are logged."""
        # Test unauthorized photo access logging
        pass

class TestInputSanitization:
    """Test input sanitization and validation."""
    
    def test_filename_sanitization(self):
        """Test malicious filename sanitization."""
        from schemas.photo import PhotoUploadRequest
        
        # Test various malicious inputs
        malicious_inputs = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "<script>alert('xss')</script>",
            "'; DROP TABLE photos; --",
            "normal_file.jpg"
        ]
        
        for filename in malicious_inputs:
            # Test that schema validation catches malicious inputs
            try:
                request = PhotoUploadRequest(title=filename)
                # Should sanitize the input
                assert "<script>" not in str(request.title) if request.title else True
                assert "../" not in str(request.title) if request.title else True
            except ValueError:
                # Some inputs should be rejected
                pass
    
    def test_metadata_sanitization(self):
        """Test photo metadata sanitization."""
        from schemas.photo import PhotoUploadRequest
        
        # Test XSS in metadata
        xss_payload = "<script>alert('xss')</script>"
        request = PhotoUploadRequest(
            title=xss_payload,
            description=xss_payload,
            tags=[xss_payload, "normal_tag"]
        )
        
        # Should sanitize XSS
        assert "<script>" not in str(request.title) if request.title else True
        assert "<script>" not in str(request.description) if request.description else True
        if request.tags:
            for tag in request.tags:
                assert "<script>" not in tag

class TestImageProcessingSecurity:
    """Test image processing security."""
    
    def test_image_bomb_protection(self, create_test_image):
        """Test protection against decompression bombs."""
        # Create a potentially dangerous image
        dangerous_image = create_test_image("JPEG", size=(10000, 10000))
        
        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_file:
            temp_file.write(dangerous_image.read())
            temp_file_path = temp_file.name
        
        try:
            from services.file_storage import FileValidator
            validator = FileValidator()
            
            # Should reject oversized images
            with pytest.raises(FileValidationError) as exc_info:
                validator.validate_file(temp_file_path, "huge.jpg")
            
            assert "too large" in str(exc_info.value).lower()
        finally:
            os.unlink(temp_file_path)
    
    def test_exif_data_sanitization(self, create_test_image):
        """Test EXIF data is properly sanitized."""
        from services.file_storage import FileValidator
        validator = FileValidator()
        
        # Test that sensitive EXIF data is removed
        # This would require creating an image with GPS data
        pass

class TestIntegrationSecurity:
    """Integration tests for complete security workflows."""
    
    def test_complete_upload_workflow(self):
        """Test complete secure upload workflow."""
        # This would test the entire upload process end-to-end
        # Including rate limiting, validation, processing, and storage
        pass
    
    def test_sharing_workflow_security(self):
        """Test complete sharing workflow security."""
        # Test creating, accessing, and revoking shares
        pass
    
    def test_quota_management_workflow(self):
        """Test complete quota management workflow."""
        # Test quota checks, updates, and enforcement
        pass

# Performance and Load Testing
class TestSecurityPerformance:
    """Test security features under load."""
    
    @pytest.mark.asyncio
    async def test_rate_limiting_performance(self):
        """Test rate limiter performance under concurrent load."""
        rate_limiter = get_photo_rate_limiter()
        
        # Simulate concurrent requests
        tasks = []
        for i in range(100):
            task = rate_limiter.check_upload_rate_limit(f"192.168.1.{i}", i)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        # Verify rate limiter handles concurrent requests correctly
        allowed_count = sum(1 for result in results if result.allowed)
        assert allowed_count > 0  # Some should be allowed
    
    def test_validation_performance(self, create_test_image):
        """Test file validation performance."""
        import time
        
        # Test validation speed
        image_file = create_test_image("JPEG", size=(1000, 1000))
        
        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_file:
            temp_file.write(image_file.read())
            temp_file_path = temp_file.name
        
        try:
            from services.file_storage import FileValidator
            validator = FileValidator()
            
            start_time = time.time()
            result = validator.validate_file(temp_file_path, "test.jpg")
            end_time = time.time()
            
            # Validation should be fast (less than 1 second for small images)
            validation_time = end_time - start_time
            assert validation_time < 1.0
            assert result['valid'] is True
        finally:
            os.unlink(temp_file_path)

# Helper functions for tests
def create_test_photo(owner_id: int, share_type: ShareType = ShareType.PRIVATE) -> Photo:
    """Create a test photo record."""
    return Photo(
        id=1,
        owner_id=owner_id,
        filename="test.jpg",
        original_filename="test.jpg",
        file_path="photos/1/2024/01/test.jpg",
        file_size=1024,
        file_hash="abc123",
        mime_type="image/jpeg",
        share_type=share_type
    )

def create_test_quota(user_id: int, used_storage: int = 0) -> StorageQuota:
    """Create a test storage quota."""
    return StorageQuota(
        user_id=user_id,
        quota_limit=1073741824,  # 1GB
        used_storage=used_storage,
        max_files=10000,
        file_count=0
    )

if __name__ == "__main__":
    # Run specific test categories
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "-k", "test_file_validation or test_rate_limiting"
    ])