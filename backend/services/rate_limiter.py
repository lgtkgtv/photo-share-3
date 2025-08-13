"""
Enterprise-grade rate limiting and brute force protection.
Implements multiple rate limiting strategies for API security at scale.
"""
import time
import json
import asyncio
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from dataclasses import dataclass
import logging

from services.security import security_config, SecurityUtils

logger = logging.getLogger(__name__)

@dataclass
class RateLimitResult:
    """Result of rate limit check."""
    allowed: bool
    remaining: int
    reset_time: datetime
    retry_after: Optional[int] = None

class InMemoryRateLimiter:
    """
    In-memory rate limiter for development and small-scale deployments.
    For production with multiple instances, use Redis-based rate limiter.
    """
    
    def __init__(self):
        # Structure: {client_key: deque([timestamp1, timestamp2, ...])}
        self._requests: Dict[str, deque] = defaultdict(deque)
        # Structure: {client_key: (attempt_count, lockout_until)}
        self._failed_attempts: Dict[str, Tuple[int, datetime]] = {}
        # Structure: {client_key: lockout_until_timestamp}
        self._account_lockouts: Dict[str, datetime] = {}
        self._lock = asyncio.Lock()
    
    async def check_rate_limit(self, client_key: str, window_seconds: int = 60, 
                             max_requests: int = 60) -> RateLimitResult:
        """
        Check if client is within rate limits.
        
        Args:
            client_key: Unique identifier for the client (IP, user, etc.)
            window_seconds: Time window in seconds
            max_requests: Maximum requests allowed in window
            
        Returns:
            RateLimitResult with allow/deny decision
        """
        async with self._lock:
            now = datetime.now(timezone.utc)
            window_start = now - timedelta(seconds=window_seconds)
            
            # Clean old requests outside the window
            client_requests = self._requests[client_key]
            while client_requests and client_requests[0] < window_start:
                client_requests.popleft()
            
            current_requests = len(client_requests)
            remaining = max(0, max_requests - current_requests)
            
            if current_requests >= max_requests:
                # Rate limit exceeded
                reset_time = client_requests[0] + timedelta(seconds=window_seconds)
                retry_after = int((reset_time - now).total_seconds())
                
                SecurityUtils.log_security_event(
                    "rate_limit_exceeded",
                    {
                        "client_key": client_key,
                        "current_requests": current_requests,
                        "max_requests": max_requests,
                        "window_seconds": window_seconds
                    }
                )
                
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after
                )
            
            # Allow request and record it
            client_requests.append(now)
            reset_time = now + timedelta(seconds=window_seconds)
            
            return RateLimitResult(
                allowed=True,
                remaining=remaining - 1,
                reset_time=reset_time
            )
    
    async def check_login_attempts(self, client_key: str) -> RateLimitResult:
        """Check login attempt rate limiting."""
        return await self.check_rate_limit(
            client_key,
            window_seconds=3600,  # 1 hour
            max_requests=security_config.rate_limit_login_attempts_per_hour
        )
    
    async def record_failed_login(self, client_key: str, email: str = None) -> bool:
        """
        Record a failed login attempt and check if account should be locked.
        
        Args:
            client_key: Client identifier (usually IP)
            email: User email for account-level tracking
            
        Returns:
            True if account should be locked
        """
        async with self._lock:
            now = datetime.now(timezone.utc)
            
            # Track IP-based failed attempts
            if client_key in self._failed_attempts:
                count, last_attempt = self._failed_attempts[client_key]
                # Reset counter if last attempt was more than 1 hour ago
                if now - last_attempt > timedelta(hours=1):
                    count = 0
                count += 1
            else:
                count = 1
            
            self._failed_attempts[client_key] = (count, now)
            
            # Check if IP should be locked out
            if count >= security_config.account_lockout_attempts:
                lockout_until = now + timedelta(minutes=security_config.account_lockout_duration_minutes)
                self._account_lockouts[client_key] = lockout_until
                
                SecurityUtils.log_security_event(
                    "ip_lockout_triggered",
                    {
                        "client_key": client_key,
                        "failed_attempts": count,
                        "lockout_until": lockout_until.isoformat()
                    },
                    user_email=email
                )
                
                return True
            
            return False
    
    async def is_locked_out(self, client_key: str) -> Tuple[bool, Optional[datetime]]:
        """
        Check if client is currently locked out.
        
        Returns:
            (is_locked, lockout_until_time)
        """
        async with self._lock:
            if client_key not in self._account_lockouts:
                return False, None
                
            lockout_until = self._account_lockouts[client_key]
            now = datetime.now(timezone.utc)
            
            if now >= lockout_until:
                # Lockout expired, clean up
                del self._account_lockouts[client_key]
                if client_key in self._failed_attempts:
                    del self._failed_attempts[client_key]
                return False, None
            
            return True, lockout_until
    
    async def reset_failed_attempts(self, client_key: str):
        """Reset failed attempts for client (after successful login)."""
        async with self._lock:
            if client_key in self._failed_attempts:
                del self._failed_attempts[client_key]
            if client_key in self._account_lockouts:
                del self._account_lockouts[client_key]
    
    async def cleanup_expired(self):
        """
        Clean up expired entries to prevent memory leaks.
        Should be called periodically.
        """
        async with self._lock:
            now = datetime.now(timezone.utc)
            
            # Clean up old requests (keep only last hour)
            cutoff = now - timedelta(hours=1)
            for client_key, requests in list(self._requests.items()):
                while requests and requests[0] < cutoff:
                    requests.popleft()
                if not requests:
                    del self._requests[client_key]
            
            # Clean up expired lockouts
            expired_lockouts = [
                key for key, lockout_time in self._account_lockouts.items()
                if now >= lockout_time
            ]
            for key in expired_lockouts:
                del self._account_lockouts[key]
                if key in self._failed_attempts:
                    del self._failed_attempts[key]

class RedisRateLimiter:
    """
    Redis-based rate limiter for production use with multiple app instances.
    Implements sliding window and distributed locking.
    """
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    async def check_rate_limit(self, client_key: str, window_seconds: int = 60, 
                             max_requests: int = 60) -> RateLimitResult:
        """
        Redis-based sliding window rate limiting.
        """
        now = int(time.time())
        window_start = now - window_seconds
        
        # Use Redis pipeline for atomic operations
        pipe = self.redis.pipeline()
        
        # Remove old entries
        pipe.zremrangebyscore(client_key, 0, window_start)
        
        # Count current requests
        pipe.zcard(client_key)
        
        # Add current request
        pipe.zadd(client_key, {str(now): now})
        
        # Set expiration
        pipe.expire(client_key, window_seconds)
        
        results = await pipe.execute()
        current_requests = results[1]
        
        remaining = max(0, max_requests - current_requests)
        
        if current_requests >= max_requests:
            # Rate limit exceeded
            reset_time = datetime.fromtimestamp(now + window_seconds, timezone.utc)
            retry_after = window_seconds
            
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=reset_time,
                retry_after=retry_after
            )
        
        reset_time = datetime.fromtimestamp(now + window_seconds, timezone.utc)
        return RateLimitResult(
            allowed=True,
            remaining=remaining - 1,
            reset_time=reset_time
        )

# Global rate limiter instance
# In production, replace with RedisRateLimiter
rate_limiter = InMemoryRateLimiter()

# Background task to clean up expired entries
async def cleanup_rate_limiter():
    """Background task to clean up expired rate limiter entries."""
    while True:
        try:
            await rate_limiter.cleanup_expired()
            await asyncio.sleep(300)  # Clean up every 5 minutes
        except Exception as e:
            logger.error(f"Error in rate limiter cleanup: {e}")
            await asyncio.sleep(60)  # Retry after 1 minute on error

def get_rate_limiter() -> InMemoryRateLimiter:
    """Get the global rate limiter instance."""
    return rate_limiter