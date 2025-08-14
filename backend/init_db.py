import asyncio
import os
from services.db import engine, Base, DATABASE_URL
from models import user, email_verification, role, photo  # important: force-load all models

async def init_models():
    """Initialize database models and tables."""
    print(f"Initializing database with URL: {DATABASE_URL}")
    print(f"Environment: {os.getenv('ENVIRONMENT', 'development')}")
    
    try:
        async with engine.begin() as conn:
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)
            print("✅ Database tables created successfully!")
            
            # Print table names for verification
            table_names = list(Base.metadata.tables.keys())
            print(f"📋 Created tables: {table_names}")
            
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(init_models())

