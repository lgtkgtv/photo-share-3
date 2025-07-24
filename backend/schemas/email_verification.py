from pydantic import BaseModel, EmailStr

class VerificationRequest(BaseModel):
    email: EmailStr

class VerificationResponse(BaseModel):
    message: str
