from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from services.db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Security tracking
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    account_locked_until = Column(DateTime(timezone=True), nullable=True)
    
    # Profile information
    first_name = Column(String(50), nullable=True)
    last_name = Column(String(50), nullable=True)
    
    # RBAC relationships - using string references to avoid circular imports
    roles = relationship(
        "Role", 
        secondary="user_roles", 
        back_populates="users",
        primaryjoin="User.id == user_roles.c.user_id",
        secondaryjoin="Role.id == user_roles.c.role_id"
    )
    sessions = relationship("UserSession", back_populates="user")
    
    # Photo relationships - using string references to avoid circular imports
    photos = relationship("Photo", back_populates="owner")
    albums = relationship("Album", back_populates="owner") 
    storage_quota = relationship("StorageQuota", back_populates="user", uselist=False)
    
    def __repr__(self):
        return f"<User(email='{self.email}', active={self.is_active}, verified={self.is_verified})>"
