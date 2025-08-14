"""
Basic database connection and initialization tests.
"""
import pytest
import asyncio
from sqlalchemy import text
from services.db import engine, get_db, DATABASE_URL
from models.user import User
from models.email_verification import EmailVerification

class TestDatabaseConnection:
    """Test database connectivity and basic operations."""
    
    def test_database_url_format(self):
        """Test that database URL is properly formatted."""
        assert DATABASE_URL is not None
        assert "postgresql+asyncpg://" in DATABASE_URL
        assert "@" in DATABASE_URL
        assert "/" in DATABASE_URL
        print(f"Database URL format valid: {DATABASE_URL}")
    
    @pytest.mark.asyncio
    async def test_database_connection(self):
        """Test that we can connect to the database."""
        try:
            async with engine.begin() as conn:
                # Simple query to test connection
                result = await conn.execute(text("SELECT 1 as test_value"))
                row = result.fetchone()
                assert row[0] == 1
                print("✅ Database connection successful")
        except Exception as e:
            pytest.fail(f"Database connection failed: {e}")
    
    @pytest.mark.asyncio
    async def test_get_db_session(self):
        """Test that database session dependency works."""
        try:
            async for db in get_db():
                # Test that we get a valid session
                assert db is not None
                print("✅ Database session creation successful")
                break  # Only test the first session
        except Exception as e:
            pytest.fail(f"Database session creation failed: {e}")
    
    @pytest.mark.asyncio
    async def test_models_import(self):
        """Test that all models can be imported without errors."""
        try:
            # Import models to ensure they're valid
            from models.user import User
            from models.email_verification import EmailVerification
            from models.role import Role
            from models.photo import Photo
            
            # Check that models have required attributes
            assert hasattr(User, '__tablename__')
            assert hasattr(EmailVerification, '__tablename__')
            assert hasattr(Role, '__tablename__')
            assert hasattr(Photo, '__tablename__')
            
            print("✅ All models imported successfully")
        except Exception as e:
            pytest.fail(f"Model import failed: {e}")

class TestDatabaseEnvironment:
    """Test database environment configuration."""
    
    def test_environment_variables(self):
        """Test that required environment variables are set."""
        import os
        
        # Check database environment variables
        assert os.getenv('POSTGRES_DB') is not None, "POSTGRES_DB not set"
        assert os.getenv('POSTGRES_USER') is not None, "POSTGRES_USER not set"
        assert os.getenv('POSTGRES_PASSWORD') is not None, "POSTGRES_PASSWORD not set"
        assert os.getenv('DB_HOST') is not None, "DB_HOST not set"
        assert os.getenv('DB_PORT') is not None, "DB_PORT not set"
        
        print("✅ All required environment variables are set")
    
    def test_database_credentials(self):
        """Test that database credentials are properly configured."""
        import os
        
        # For CI, these should be the test values
        if os.getenv('ENVIRONMENT') == 'test':
            assert os.getenv('POSTGRES_DB') == 'test_photoapp'
            assert os.getenv('POSTGRES_USER') == 'test_user'
            assert os.getenv('POSTGRES_PASSWORD') == 'test_password'
            assert os.getenv('DB_HOST') == 'localhost'
            assert os.getenv('DB_PORT') == '5432'
            print("✅ Test database credentials are correctly configured")