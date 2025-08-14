from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from contextlib import asynccontextmanager
import asyncio
import logging
from api import user, email_verification
from middleware.security import (
    SecurityHeadersMiddleware,
    RateLimitMiddleware,
    RequestValidationMiddleware,
    CSRFProtectionMiddleware,
    SecurityLoggingMiddleware
)
from services.rate_limiter import cleanup_rate_limiter
from services.security import security_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Background tasks for security maintenance
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management for security background tasks."""
    # Start background tasks
    cleanup_task = asyncio.create_task(cleanup_rate_limiter())
    
    logger.info("Starting Photo Sharing App with enterprise security")
    logger.info(f"Security features enabled:")
    logger.info(f"  - Rate limiting: Enabled")
    logger.info(f"  - Security headers: {security_config.enable_security_headers}")
    logger.info(f"  - CSRF protection: {security_config.enable_csrf_protection}")
    logger.info(f"  - JWT algorithm: {security_config.jwt_algorithm}")
    logger.info(f"  - Token expiration: {security_config.jwt_access_token_expire_minutes} minutes")
    
    yield
    
    # Cleanup on shutdown
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        logger.info("Background security tasks stopped")
    
    logger.info("Photo Sharing App shutdown complete")

app = FastAPI(
    title="Photo Sharing App API",
    description="Enterprise-grade photo sharing application with advanced security",
    version="1.0.0",
    lifespan=lifespan
)

# Add security middleware (order matters - last added is executed first)
app.add_middleware(SecurityLoggingMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CSRFProtectionMiddleware)
app.add_middleware(RequestValidationMiddleware)
app.add_middleware(RateLimitMiddleware)

# Include API routers
app.include_router(user.router, prefix="/api/users", tags=["users"])
app.include_router(email_verification.router, prefix="/api/users", tags=["email-verification"])

@app.get("/")
def root():
    """Root endpoint with basic application information."""
    return {
        "message": "Photo Sharing App API",
        "version": "1.0.0",
        "security": "Enterprise-grade protection enabled",
        "docs": "/docs",
        "status": "operational"
    }

@app.get("/health")
def health_check():
    """Health check endpoint for load balancers and monitoring."""
    return {
        "status": "healthy",
        "timestamp": "2024-01-01T00:00:00Z",
        "version": "1.0.0",
        "security_config": {
            "rate_limiting": "enabled",
            "security_headers": security_config.enable_security_headers,
            "csrf_protection": security_config.enable_csrf_protection
        }
    }

@app.get("/health/ready")
async def readiness_check():
    """Readiness probe for Kubernetes and production deployments."""
    try:
        from services.db import get_db
        
        # Test database connection
        async for db in get_db():
            await db.execute("SELECT 1")
            break
        
        return {
            "status": "ready",
            "timestamp": "2024-01-01T00:00:00Z",
            "checks": {
                "database": "healthy",
                "security": "enabled"
            }
        }
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "timestamp": "2024-01-01T00:00:00Z",
                "error": "Database connection failed"
            }
        )

@app.get("/health/live")
def liveness_check():
    """Liveness probe for container orchestration."""
    return {
        "status": "alive",
        "timestamp": "2024-01-01T00:00:00Z"
    }

# Error handlers for security-related errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors with security logging."""
    from services.security import SecurityUtils
    
    SecurityUtils.log_security_event(
        "request_validation_error",
        {
            "path": request.url.path,
            "method": request.method,
            "errors": exc.errors()
        },
        client_ip=SecurityUtils.get_client_ip(request)
    )
    
    return JSONResponse(
        status_code=422,
        content={"error": "Invalid request format", "details": "Please check your request data"}
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions with security logging."""
    from services.security import SecurityUtils
    
    # Log security-relevant errors
    if exc.status_code in [400, 401, 403, 404, 429]:
        SecurityUtils.log_security_event(
            "http_exception",
            {
                "status_code": exc.status_code,
                "path": request.url.path,
                "method": request.method
            },
            client_ip=SecurityUtils.get_client_ip(request)
        )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail if hasattr(exc, 'detail') else "Request failed"}
    )

@app.exception_handler(500)
async def internal_server_error_handler(request: Request, exc: Exception):
    """Handle internal server errors with security logging."""
    from services.security import SecurityUtils
    
    SecurityUtils.log_security_event(
        "internal_server_error",
        {
            "path": request.url.path,
            "method": request.method,
            "error_type": type(exc).__name__
        },
        client_ip=SecurityUtils.get_client_ip(request)
    )
    
    logger.error(f"Internal server error: {exc}")
    
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"}
    )
