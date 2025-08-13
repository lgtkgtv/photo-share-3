"""
Photo-specific rate limiting for upload operations.
Extends the general rate limiter with photo upload restrictions.
"""
from typing import Optional
from services.rate_limiter import get_rate_limiter, RateLimitResult
from services.security import SecurityUtils

class PhotoRateLimiter:
    """
    Photo-specific rate limiting with upload quotas and restrictions.
    """
    
    def __init__(self):
        self.rate_limiter = get_rate_limiter()
    
    async def check_upload_rate_limit(self, client_ip: str, user_id: Optional[int] = None) -> RateLimitResult:
        """
        Check photo upload rate limits - more restrictive than general API calls.
        
        Args:
            client_ip: Client IP address
            user_id: User ID for user-specific limits
        
        Returns:
            RateLimitResult with allow/deny decision
        """
        # IP-based upload limits: 10 uploads per 5 minutes
        ip_result = await self.rate_limiter.check_rate_limit(
            f"upload_ip:{client_ip}",
            window_seconds=300,  # 5 minutes
            max_requests=10
        )
        
        if not ip_result.allowed:
            SecurityUtils.log_security_event(
                "photo_upload_rate_limit_exceeded",
                {
                    "client_ip": client_ip,
                    "user_id": user_id,
                    "limit_type": "ip_based",
                    "window_seconds": 300,
                    "max_requests": 10
                },
                client_ip=client_ip
            )
            return ip_result
        
        # User-based upload limits: 50 uploads per hour
        if user_id:
            user_result = await self.rate_limiter.check_rate_limit(
                f"upload_user:{user_id}",
                window_seconds=3600,  # 1 hour
                max_requests=50
            )
            
            if not user_result.allowed:
                SecurityUtils.log_security_event(
                    "photo_upload_rate_limit_exceeded",
                    {
                        "client_ip": client_ip,
                        "user_id": user_id,
                        "limit_type": "user_based",
                        "window_seconds": 3600,
                        "max_requests": 50
                    },
                    client_ip=client_ip
                )
                return user_result
        
        return ip_result  # Return the most restrictive result
    
    async def check_batch_upload_rate_limit(self, client_ip: str, user_id: Optional[int] = None, 
                                          batch_size: int = 1) -> RateLimitResult:
        """
        Check batch upload rate limits - even more restrictive.
        
        Args:
            client_ip: Client IP address
            user_id: User ID for user-specific limits
            batch_size: Number of files in batch
        
        Returns:
            RateLimitResult with allow/deny decision
        """
        # IP-based batch limits: 3 batch operations per 10 minutes
        ip_result = await self.rate_limiter.check_rate_limit(
            f"batch_upload_ip:{client_ip}",
            window_seconds=600,  # 10 minutes
            max_requests=3
        )
        
        if not ip_result.allowed:
            SecurityUtils.log_security_event(
                "batch_upload_rate_limit_exceeded",
                {
                    "client_ip": client_ip,
                    "user_id": user_id,
                    "batch_size": batch_size,
                    "limit_type": "ip_batch",
                    "window_seconds": 600,
                    "max_requests": 3
                },
                client_ip=client_ip
            )
            return ip_result
        
        # User-based batch limits: 10 batch operations per hour
        if user_id:
            user_result = await self.rate_limiter.check_rate_limit(
                f"batch_upload_user:{user_id}",
                window_seconds=3600,  # 1 hour
                max_requests=10
            )
            
            if not user_result.allowed:
                SecurityUtils.log_security_event(
                    "batch_upload_rate_limit_exceeded",
                    {
                        "client_ip": client_ip,
                        "user_id": user_id,
                        "batch_size": batch_size,
                        "limit_type": "user_batch",
                        "window_seconds": 3600,
                        "max_requests": 10
                    },
                    client_ip=client_ip
                )
                return user_result
        
        # Additional check for large batch sizes
        if batch_size > 5:
            large_batch_result = await self.rate_limiter.check_rate_limit(
                f"large_batch_user:{user_id or client_ip}",
                window_seconds=1800,  # 30 minutes
                max_requests=1  # Only 1 large batch per 30 minutes
            )
            
            if not large_batch_result.allowed:
                SecurityUtils.log_security_event(
                    "large_batch_upload_rate_limit_exceeded",
                    {
                        "client_ip": client_ip,
                        "user_id": user_id,
                        "batch_size": batch_size,
                        "limit_type": "large_batch",
                        "window_seconds": 1800,
                        "max_requests": 1
                    },
                    client_ip=client_ip
                )
                return large_batch_result
        
        return ip_result
    
    async def check_quota_usage_rate_limit(self, user_id: int) -> RateLimitResult:
        """
        Rate limit quota usage checks to prevent abuse.
        
        Args:
            user_id: User ID
            
        Returns:
            RateLimitResult with allow/deny decision
        """
        result = await self.rate_limiter.check_rate_limit(
            f"quota_check_user:{user_id}",
            window_seconds=60,  # 1 minute
            max_requests=30  # 30 quota checks per minute should be plenty
        )
        
        if not result.allowed:
            SecurityUtils.log_security_event(
                "quota_check_rate_limit_exceeded",
                {
                    "user_id": user_id,
                    "window_seconds": 60,
                    "max_requests": 30
                }
            )
        
        return result
    
    async def check_sharing_rate_limit(self, user_id: int) -> RateLimitResult:
        """
        Rate limit photo sharing operations to prevent spam.
        
        Args:
            user_id: User ID
            
        Returns:
            RateLimitResult with allow/deny decision
        """
        result = await self.rate_limiter.check_rate_limit(
            f"photo_share_user:{user_id}",
            window_seconds=300,  # 5 minutes
            max_requests=20  # 20 share operations per 5 minutes
        )
        
        if not result.allowed:
            SecurityUtils.log_security_event(
                "photo_sharing_rate_limit_exceeded",
                {
                    "user_id": user_id,
                    "window_seconds": 300,
                    "max_requests": 20
                }
            )
        
        return result

# Global photo rate limiter instance
photo_rate_limiter = PhotoRateLimiter()

def get_photo_rate_limiter() -> PhotoRateLimiter:
    """Get the global photo rate limiter instance."""
    return photo_rate_limiter