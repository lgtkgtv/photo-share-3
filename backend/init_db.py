import asyncio
from services.db import engine, Base
from models import user, email_verification  # important: force-load all models

async def init_models():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

if __name__ == "__main__":
    asyncio.run(init_models())

