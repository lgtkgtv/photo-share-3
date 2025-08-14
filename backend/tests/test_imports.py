"""
Test that all modules can be imported correctly.
This helps identify import issues in CI/CD environment.
"""
import pytest

class TestImports:
    """Test module imports for CI/CD compatibility."""
    
    def test_main_app_import(self):
        """Test importing the main FastAPI app."""
        try:
            from main import app
            assert app is not None
            print("✅ main.app imported successfully")
        except ImportError as e:
            pytest.fail(f"Failed to import main.app: {e}")
    
    def test_database_imports(self):
        """Test importing database modules."""
        try:
            from services.db import get_db, engine, Base
            assert get_db is not None
            assert engine is not None
            assert Base is not None
            print("✅ Database modules imported successfully")
        except ImportError as e:
            pytest.fail(f"Failed to import database modules: {e}")
    
    def test_file_storage_imports(self):
        """Test importing file storage modules."""
        try:
            from services.file_storage import storage, FileValidationError, FileValidator
            assert storage is not None
            assert FileValidationError is not None
            assert FileValidator is not None
            print("✅ File storage modules imported successfully")
        except ImportError as e:
            pytest.fail(f"Failed to import file storage modules: {e}")
    
    def test_security_imports(self):
        """Test importing security modules."""
        try:
            from services.security import SecurityUtils
            from services.rbac import RBACService
            assert SecurityUtils is not None
            assert RBACService is not None
            print("✅ Security modules imported successfully")
        except ImportError as e:
            pytest.fail(f"Failed to import security modules: {e}")
    
    def test_rate_limiter_imports(self):
        """Test importing rate limiter modules."""
        try:
            from services.photo_rate_limiter import get_photo_rate_limiter, PhotoRateLimiter
            assert get_photo_rate_limiter is not None
            assert PhotoRateLimiter is not None
            print("✅ Rate limiter modules imported successfully")
        except ImportError as e:
            pytest.fail(f"Failed to import rate limiter modules: {e}")
    
    def test_model_imports(self):
        """Test importing model modules."""
        try:
            from models.user import User
            from models.photo import Photo, PhotoShare, ShareType, StorageQuota
            assert User is not None
            assert Photo is not None
            assert PhotoShare is not None
            assert ShareType is not None
            assert StorageQuota is not None
            print("✅ Model modules imported successfully")
        except ImportError as e:
            pytest.fail(f"Failed to import model modules: {e}")
    
    def test_schema_imports(self):
        """Test importing schema modules."""
        try:
            from schemas.photo import PhotoUploadRequest
            from schemas.user import UserCreate, UserOut
            assert PhotoUploadRequest is not None
            assert UserCreate is not None
            assert UserOut is not None
            print("✅ Schema modules imported successfully")
        except ImportError as e:
            pytest.fail(f"Failed to import schema modules: {e}")
    
    def test_external_dependencies(self):
        """Test that external dependencies are available."""
        try:
            from fastapi.testclient import TestClient
            from fastapi import HTTPException, status
            from sqlalchemy.ext.asyncio import AsyncSession
            from PIL import Image
            import tempfile
            import os
            from io import BytesIO
            import json
            from datetime import datetime, timezone, timedelta
            
            # Verify all are not None
            assert TestClient is not None
            assert HTTPException is not None
            assert status is not None
            assert AsyncSession is not None
            assert Image is not None
            
            print("✅ External dependencies imported successfully")
        except ImportError as e:
            pytest.fail(f"Failed to import external dependencies: {e}")