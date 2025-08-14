"""
Security middleware for enterprise-grade API protection.
Implements rate limiting, CSRF protection, security headers, and request validation.
"""
import time
import json
from typing import Callable, Optional
from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import logging

from services.security import security_config, SecurityUtils
from services.rate_limiter import get_rate_limiter, RateLimitResult

logger = logging.getLogger(__name__)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds security headers to all responses.
    Implements OWASP security header recommendations.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.security_headers = {
            # Prevent XSS attacks
            "X-XSS-Protection": "1; mode=block",
            
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            
            # Prevent clickjacking
            "X-Frame-Options": "DENY",
            
            # Strict transport security (HTTPS only)
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            
            # Content Security Policy
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' https:; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            ),
            
            # Referrer Policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Permissions Policy
            "Permissions-Policy": (
                "accelerometer=(), "
                "camera=(), "
                "geolocation=(), "
                "gyroscope=(), "
                "magnetometer=(), "
                "microphone=(), "
                "payment=(), "
                "usb=()"
            )
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        if security_config.enable_security_headers:
            # Add security headers
            for header, value in self.security_headers.items():
                response.headers[header] = value
            
            # Remove server header to avoid version disclosure
            if "Server" in response.headers:
                del response.headers["Server"]
                
        return response

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware with different limits for different endpoints.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.rate_limiter = get_rate_limiter()
        
        # Define rate limits for different endpoint patterns
        self.endpoint_limits = {
            "/api/users/login": {"requests": 5, "window": 3600},  # 5 login attempts per hour
            "/api/users/register": {"requests": 3, "window": 3600},  # 3 registrations per hour
            "/api/users/request-verification": {"requests": 3, "window": 3600},  # 3 verification requests per hour
            "default": {"requests": security_config.rate_limit_requests_per_minute, "window": 60}
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get client identifier
        client_ip = SecurityUtils.get_client_ip(request)
        path = request.url.path
        method = request.method
        
        # Check if client is locked out
        is_locked, lockout_until = await self.rate_limiter.is_locked_out(client_ip)
        if is_locked:
            SecurityUtils.log_security_event(
                "blocked_request_lockout",
                {
                    "path": path,
                    "method": method,
                    "lockout_until": lockout_until.isoformat()
                },
                client_ip=client_ip
            )
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Too many failed attempts",
                    "message": "Your IP has been temporarily blocked due to suspicious activity",
                    "retry_after": int((lockout_until - SecurityUtils.get_utc_now()).total_seconds())
                },
                headers={"Retry-After": str(int((lockout_until - SecurityUtils.get_utc_now()).total_seconds()))}
            )
        
        # Determine rate limit for this endpoint
        limit_config = self.endpoint_limits.get(path, self.endpoint_limits["default"])
        
        # Create rate limit key
        rate_limit_key = f"rate_limit:{client_ip}:{path}"
        
        # Check rate limit
        rate_result = await self.rate_limiter.check_rate_limit(
            rate_limit_key,
            window_seconds=limit_config["window"],
            max_requests=limit_config["requests"]
        )
        
        if not rate_result.allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later.",
                    "retry_after": rate_result.retry_after
                },
                headers={
                    "X-RateLimit-Limit": str(limit_config["requests"]),
                    "X-RateLimit-Remaining": str(rate_result.remaining),
                    "X-RateLimit-Reset": str(int(rate_result.reset_time.timestamp())),
                    "Retry-After": str(rate_result.retry_after or limit_config["window"])
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to successful responses
        response.headers["X-RateLimit-Limit"] = str(limit_config["requests"])
        response.headers["X-RateLimit-Remaining"] = str(rate_result.remaining)
        response.headers["X-RateLimit-Reset"] = str(int(rate_result.reset_time.timestamp()))
        
        return response

class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Request validation and sanitization middleware.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.max_request_size = 10 * 1024 * 1024  # 10MB
        self.suspicious_patterns = [
            # SQL injection patterns
            r"(?i)(union|select|insert|delete|update|drop|create|alter|exec|script)",
            # XSS patterns
            r"(?i)(<script|javascript:|data:|vbscript:)",
            # Path traversal
            r"(\.\.\/|\.\.\\|\.\.\/\.\.\/)",
            # Command injection
            r"(?i)(;|\||&&|\$\(|`)"
        ]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = SecurityUtils.get_client_ip(request)
        
        # Check request size
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_request_size:
            SecurityUtils.log_security_event(
                "oversized_request",
                {
                    "content_length": content_length,
                    "max_allowed": self.max_request_size,
                    "path": request.url.path
                },
                client_ip=client_ip
            )
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={"error": "Request too large"}
            )
        
        # Validate User-Agent (block empty or suspicious user agents)
        user_agent = request.headers.get("user-agent", "")
        if not user_agent or len(user_agent) < 3:
            SecurityUtils.log_security_event(
                "suspicious_user_agent",
                {"user_agent": user_agent, "path": request.url.path},
                client_ip=client_ip
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Invalid request"}
            )
        
        # Check for suspicious patterns in URL and query parameters
        full_url = str(request.url)
        for pattern in self.suspicious_patterns:
            import re
            if re.search(pattern, full_url):
                SecurityUtils.log_security_event(
                    "suspicious_request_pattern",
                    {
                        "pattern": pattern,
                        "url": full_url,
                        "user_agent": user_agent
                    },
                    client_ip=client_ip
                )
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "Invalid request"}
                )
        
        return await call_next(request)

class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    CSRF protection middleware for state-changing operations.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.protected_methods = {"POST", "PUT", "PATCH", "DELETE"}
        self.exempt_paths = {
            "/api/users/login",  # Login endpoint uses other protection
            "/docs",
            "/redoc",
            "/openapi.json"
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not security_config.enable_csrf_protection:
            return await call_next(request)
        
        path = request.url.path
        method = request.method
        
        # Check if this request needs CSRF protection
        if method in self.protected_methods and path not in self.exempt_paths:
            # Check for CSRF token in header
            csrf_token = request.headers.get("X-CSRF-Token")
            
            if not csrf_token:
                SecurityUtils.log_security_event(
                    "csrf_token_missing",
                    {"path": path, "method": method},
                    client_ip=SecurityUtils.get_client_ip(request)
                )
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"error": "CSRF token required"}
                )
            
            # In a full implementation, validate the CSRF token here
            # For now, we just check its presence
            
        return await call_next(request)

class SecurityLoggingMiddleware(BaseHTTPMiddleware):
    """
    Security-focused request/response logging middleware.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.sensitive_headers = {"authorization", "cookie", "x-api-key"}
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        client_ip = SecurityUtils.get_client_ip(request)
        
        # Log request details
        headers_to_log = {
            k: "[REDACTED]" if k.lower() in self.sensitive_headers else v
            for k, v in request.headers.items()
        }
        
        process_time = time.time() - start_time
        response = await call_next(request)
        
        # Log security-relevant responses
        if response.status_code >= 400:
            SecurityUtils.log_security_event(
                "http_error_response",
                {
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "process_time": round(process_time, 3),
                    "user_agent": request.headers.get("user-agent", "")
                },
                client_ip=client_ip
            )
        
        # Add security headers to response
        response.headers["X-Process-Time"] = str(round(process_time, 3))
        
        return response