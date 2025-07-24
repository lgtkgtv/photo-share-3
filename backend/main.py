from fastapi import FastAPI
from api import user, email_verification

app = FastAPI()

app.include_router(user.router, prefix="/api/users", tags=["users"])
app.include_router(email_verification.router, prefix="/api/users", tags=["email-verification"])

@app.get("/")
def root():
    return {"message": "Photo Sharing App backend is running."}
