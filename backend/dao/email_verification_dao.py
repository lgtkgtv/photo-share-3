from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from models.email_verification import EmailVerification
from datetime import datetime, timedelta
import secrets

class EmailVerificationDAO:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_verification(self, email: str, expiry_minutes: int = 15):
        secret = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(minutes=expiry_minutes)
        record = EmailVerification(email=email, secret=secret, expires_at=expires_at)
        self.db.add(record)
        await self.db.commit()
        await self.db.refresh(record)
        return record

    async def verify_secret(self, secret: str):
        result = await self.db.execute(
            select(EmailVerification).where(EmailVerification.secret == secret)
        )
        return result.scalars().first()

    async def delete_by_id(self, id: int):
        record = await self.db.get(EmailVerification, id)
        if record:
            await self.db.delete(record)
            await self.db.commit()
