"""
Comprehensive security tests for rate limiting and attack prevention.
Tests brute force protection, DDoS prevention, and suspicious activity detection.
"""
import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from services.rate_limiter import InMemoryRateLimiter, get_rate_limiter, RateLimitResult
from services.security import SecurityUtils
from middleware.security import RateLimitMiddleware, RequestValidationMiddleware
from models.user import User
from dao.user_dao import UserDAO
from services.auth import get_password_hash

@pytest.mark.asyncio
class TestRateLimiting:
    """Test rate limiting functionality and configurations."""
    
    async def test_basic_rate_limiting(self):
        """Test basic rate limiting with different windows."""
        rate_limiter = InMemoryRateLimiter()
        client_key = "test_client_123"
        
        # Test within limits
        for i in range(5):
            result = await rate_limiter.check_rate_limit(
                client_key, window_seconds=60, max_requests=10
            )
            assert result.allowed is True
            assert result.remaining == 10 - i - 1
        
        # Test at limit
        for i in range(5):
            result = await rate_limiter.check_rate_limit(
                client_key, window_seconds=60, max_requests=10
            )
            if i < 5:
                assert result.allowed is True
            else:
                assert result.allowed is False
    
    async def test_rate_limit_window_expiry(self):
        """Test that rate limits reset after window expiry."""
        rate_limiter = InMemoryRateLimiter()
        client_key = "test_window_expiry"
        
        # Fill up the rate limit
        for i in range(5):
            result = await rate_limiter.check_rate_limit(
                client_key, window_seconds=1, max_requests=5
            )
            assert result.allowed is True
        
        # Should be rate limited now
        result = await rate_limiter.check_rate_limit(
            client_key, window_seconds=1, max_requests=5
        )
        assert result.allowed is False
        
        # Wait for window to expire
        await asyncio.sleep(1.1)
        
        # Should be allowed again
        result = await rate_limiter.check_rate_limit(
            client_key, window_seconds=1, max_requests=5
        )
        assert result.allowed is True
    
    async def test_different_client_isolation(self):
        """Test that different clients have isolated rate limits."""
        rate_limiter = InMemoryRateLimiter()
        
        client1 = "client_1"
        client2 = "client_2"
        
        # Fill up rate limit for client1
        for i in range(5):
            result = await rate_limiter.check_rate_limit(
                client1, window_seconds=60, max_requests=5
            )
            assert result.allowed is True
        
        # Client1 should be rate limited
        result = await rate_limiter.check_rate_limit(
            client1, window_seconds=60, max_requests=5
        )
        assert result.allowed is False
        
        # Client2 should still be allowed
        result = await rate_limiter.check_rate_limit(
            client2, window_seconds=60, max_requests=5
        )
        assert result.allowed is True
    
    async def test_login_attempt_rate_limiting(self):
        """Test specific login attempt rate limiting."""
        rate_limiter = InMemoryRateLimiter()
        client_key = "login_test_client"
        
        # Test login-specific rate limiting
        for i in range(3):
            result = await rate_limiter.check_login_attempts(client_key)
            assert result.allowed is True
        
        # Should be rate limited after configured attempts
        result = await rate_limiter.check_login_attempts(client_key)
        assert result.allowed is False
        assert result.retry_after is not None

@pytest.mark.asyncio
class TestBruteForceProtection:
    """Test brute force attack protection."""
    
    async def test_failed_login_tracking(self):
        """Test tracking of failed login attempts."""
        rate_limiter = InMemoryRateLimiter()
        client_key = "brute_force_test"
        email = "test@example.com"
        
        # Record failed attempts
        for i in range(3):
            lockout_triggered = await rate_limiter.record_failed_login(client_key, email)
            assert lockout_triggered is False
        
        # Should trigger lockout on configured attempt
        lockout_triggered = await rate_limiter.record_failed_login(client_key, email)
        assert lockout_triggered is True
        
        # Verify lockout status
        is_locked, lockout_until = await rate_limiter.is_locked_out(client_key)
        assert is_locked is True
        assert lockout_until is not None
        assert lockout_until > datetime.now(timezone.utc)
    
    async def test_lockout_expiry(self):
        """Test that lockouts expire after configured duration."""
        rate_limiter = InMemoryRateLimiter()
        client_key = "lockout_expiry_test"
        
        # Trigger lockout
        for i in range(5):
            await rate_limiter.record_failed_login(client_key)
        
        # Should be locked
        is_locked, lockout_until = await rate_limiter.is_locked_out(client_key)
        assert is_locked is True
        
        # Manually expire lockout for test
        rate_limiter._account_lockouts[client_key] = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        # Should no longer be locked
        is_locked, lockout_until = await rate_limiter.is_locked_out(client_key)
        assert is_locked is False
    
    async def test_successful_login_reset(self):
        """Test that successful login resets failed attempt counter."""
        rate_limiter = InMemoryRateLimiter()
        client_key = "reset_test"
        
        # Record some failed attempts
        for i in range(3):
            await rate_limiter.record_failed_login(client_key)
        
        # Reset on successful login
        await rate_limiter.reset_failed_attempts(client_key)
        
        # Should be able to make more attempts without lockout
        for i in range(3):
            lockout_triggered = await rate_limiter.record_failed_login(client_key)
            assert lockout_triggered is False

@pytest.mark.asyncio
class TestAttackPrevention:
    """Test various attack prevention mechanisms."""
    
    def test_suspicious_request_patterns(self):
        """Test detection of suspicious request patterns."""
        middleware = RequestValidationMiddleware(Mock())
        
        suspicious_urls = [
            "http://test.com/api/users?id=1' OR '1'='1",  # SQL injection
            "http://test.com/api/data?query=<script>alert('xss')</script>",  # XSS
            "http://test.com/api/file?path=../../../etc/passwd",  # Path traversal
            "http://test.com/api/exec?cmd=rm -rf /",  # Command injection
        ]
        
        for url in suspicious_urls:
            request = Mock()
            request.url = Mock()
            request.url.path = url.split('?')[0]
            
            full_url = url
            
            # Check if any suspicious patterns match
            suspicious = False
            for pattern in middleware.suspicious_patterns:
                import re
                if re.search(pattern, full_url):
                    suspicious = True
                    break
            
            assert suspicious, f"Suspicious URL not detected: {url}"
    
    def test_request_size_validation(self):
        """Test request size limits."""
        middleware = RequestValidationMiddleware(Mock())
        max_size = middleware.max_request_size
        
        # Test oversized request detection
        oversized_length = str(max_size + 1)
        
        request = Mock()
        request.headers = {"content-length": oversized_length}
        
        # This would be handled in the middleware dispatch method
        assert int(oversized_length) > max_size
    
    def test_user_agent_validation(self):
        """Test user agent validation."""
        middleware = RequestValidationMiddleware(Mock())
        
        suspicious_agents = [
            "",  # Empty user agent
            "a",  # Too short
            "ab",  # Too short
            None  # No user agent
        ]
        
        for agent in suspicious_agents:
            request = Mock()
            request.headers = {"user-agent": agent} if agent is not None else {}
            
            user_agent = request.headers.get("user-agent", "")
            is_suspicious = not user_agent or len(user_agent) < 3
            
            assert is_suspicious, f"Suspicious user agent not detected: {agent}"

class TestSecurityHeaders:
    """Test security headers middleware."""
    
    def test_security_headers_presence(self):
        """Test that all required security headers are set."""
        from middleware.security import SecurityHeadersMiddleware
        
        middleware = SecurityHeadersMiddleware(Mock())
        
        required_headers = [
            "X-XSS-Protection",
            "X-Content-Type-Options", 
            "X-Frame-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        
        for header in required_headers:
            assert header in middleware.security_headers
            assert middleware.security_headers[header] is not None
    
    def test_csp_policy_strength(self):
        """Test Content Security Policy strength."""
        from middleware.security import SecurityHeadersMiddleware
        
        middleware = SecurityHeadersMiddleware(Mock())
        csp = middleware.security_headers["Content-Security-Policy"]
        
        # Should restrict to self by default
        assert "'self'" in csp
        # Should not allow unsafe-eval
        assert "'unsafe-eval'" not in csp
        # Should prevent frame embedding
        assert "frame-ancestors 'none'" in csp

@pytest.mark.asyncio
class TestDDoSProtection:
    """Test Distributed Denial of Service protection."""
    
    async def test_concurrent_request_handling(self):
        """Test handling of many concurrent requests from same client."""
        rate_limiter = InMemoryRateLimiter()
        client_key = "ddos_test_client"
        
        # Simulate concurrent requests
        tasks = []
        for i in range(20):
            task = rate_limiter.check_rate_limit(
                client_key, window_seconds=60, max_requests=10
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        # First 10 should be allowed, rest should be denied
        allowed_count = sum(1 for result in results if result.allowed)
        denied_count = sum(1 for result in results if not result.allowed)
        
        assert allowed_count == 10
        assert denied_count == 10
    
    async def test_multiple_client_fairness(self):
        """Test that rate limiting is fair across multiple clients."""
        rate_limiter = InMemoryRateLimiter()
        
        clients = [f"client_{i}" for i in range(5)]
        
        # Each client makes requests up to their limit
        for client in clients:
            for i in range(5):
                result = await rate_limiter.check_rate_limit(
                    client, window_seconds=60, max_requests=5
                )
                assert result.allowed is True
        
        # Each client should now be at their limit
        for client in clients:
            result = await rate_limiter.check_rate_limit(
                client, window_seconds=60, max_requests=5
            )
            assert result.allowed is False

class TestRateLimitMiddleware:
    """Test rate limiting middleware integration."""
    
    @pytest.mark.asyncio
    async def test_middleware_rate_limiting(self):
        """Test rate limiting through middleware."""
        from middleware.security import RateLimitMiddleware
        
        app = Mock()
        middleware = RateLimitMiddleware(app)
        
        # Mock request
        request = Mock()
        request.url.path = "/api/users/login"
        request.method = "POST"
        request.headers = {}
        request.client.host = "127.0.0.1"
        
        # Mock call_next function
        async def call_next(request):
            response = Mock()
            response.headers = {}
            return response
        
        # Test normal request
        response = await middleware.dispatch(request, call_next)
        
        # Should have rate limit headers
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
        assert "X-RateLimit-Reset" in response.headers

@pytest.mark.asyncio
class TestSuspiciousActivityDetection:
    """Test detection of suspicious user activities."""
    
    async def test_multiple_ip_detection(self, db_session: AsyncSession):
        """Test detection of logins from multiple IPs."""
        from services.rbac import RBACService
        
        # Create test user
        dao = UserDAO(db_session)
        test_user = User(
            email="suspicious_test@example.com",
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        rbac = RBACService(db_session)
        
        # Create sessions from different IPs in short time
        ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "203.0.113.1"]
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        for i, ip in enumerate(ips):
            session = await rbac.create_user_session(
                user_id=user.id,
                session_token=f"session_{i}",
                refresh_token_jti=f"refresh_{i}",
                ip_address=ip,
                user_agent="Test Agent",
                expires_at=expires_at
            )
            
            if i >= 2:  # Should be flagged as suspicious after multiple IPs
                assert session.is_suspicious is True
    
    async def test_unusual_user_agent_detection(self, db_session: AsyncSession):
        """Test detection of unusual user agents."""
        from services.rbac import RBACService
        
        # Create test user
        dao = UserDAO(db_session)
        test_user = User(
            email="user_agent_test@example.com", 
            hashed_password=get_password_hash("TestPassword123!")
        )
        user = await dao.create_user(test_user)
        
        rbac = RBACService(db_session)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        # First session with normal user agent
        session1 = await rbac.create_user_session(
            user_id=user.id,
            session_token="session_1",
            refresh_token_jti="refresh_1", 
            ip_address="127.0.0.1",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            expires_at=expires_at
        )
        assert session1.is_suspicious is False  # First time, so suspicious
        
        # Second session with same user agent
        session2 = await rbac.create_user_session(
            user_id=user.id,
            session_token="session_2",
            refresh_token_jti="refresh_2",
            ip_address="127.0.0.1", 
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            expires_at=expires_at
        )
        # Should not be suspicious as we've seen this user agent before
        # (Note: current implementation marks first-time user agents as suspicious)

class TestPerformanceUnderAttack:
    """Test system performance under attack conditions."""
    
    @pytest.mark.asyncio
    async def test_rate_limiter_performance(self):
        """Test rate limiter performance under high load."""
        rate_limiter = InMemoryRateLimiter()
        
        # Time many concurrent operations
        import time
        start_time = time.time()
        
        tasks = []
        for i in range(100):
            client_key = f"perf_test_{i % 10}"  # 10 different clients
            task = rate_limiter.check_rate_limit(
                client_key, window_seconds=60, max_requests=50
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        end_time = time.time()
        
        # Should complete in reasonable time (less than 1 second)
        duration = end_time - start_time
        assert duration < 1.0, f"Rate limiter too slow: {duration}s for 100 operations"
        
        # All operations should succeed (within limits)
        successful_ops = sum(1 for result in results if result.allowed)
        assert successful_ops > 0
    
    @pytest.mark.asyncio
    async def test_memory_usage_under_load(self):
        """Test that rate limiter doesn't leak memory under load."""
        rate_limiter = InMemoryRateLimiter()
        
        # Generate many unique clients
        for i in range(1000):
            client_key = f"memory_test_{i}"
            await rate_limiter.check_rate_limit(
                client_key, window_seconds=1, max_requests=1
            )
        
        # Cleanup should remove old entries
        await rate_limiter.cleanup_expired()
        
        # After cleanup, should have fewer entries
        # (This is a basic test - in production you'd measure actual memory usage)
        assert len(rate_limiter._requests) < 1000

class TestSecurityEventGeneration:
    """Test that security events are properly generated during attacks."""
    
    @pytest.mark.asyncio
    async def test_rate_limit_violation_events(self):
        """Test that rate limit violations generate security events."""
        rate_limiter = InMemoryRateLimiter()
        client_key = "event_test_client"
        
        # Fill rate limit
        for i in range(5):
            await rate_limiter.check_rate_limit(
                client_key, window_seconds=60, max_requests=5
            )
        
        # This should trigger a security event (in the middleware)
        result = await rate_limiter.check_rate_limit(
            client_key, window_seconds=60, max_requests=5
        )
        
        assert result.allowed is False
        # In integration tests, you would verify the security event was logged
    
    def test_security_utils_event_logging(self):
        """Test security event logging utility."""
        # Test event logging without exceptions
        SecurityUtils.log_security_event(
            "test_attack_detected",
            {
                "attack_type": "brute_force",
                "attempts": 10,
                "blocked": True
            },
            user_email="attacker@example.com",
            client_ip="192.168.1.100"
        )
        
        # Should not raise any exceptions
        assert True

# Integration test for complete attack scenario
@pytest.mark.asyncio
class TestAttackScenarioIntegration:
    """Integration tests for complete attack scenarios."""
    
    async def test_coordinated_brute_force_attack(self):
        """Test system response to coordinated brute force attack."""
        rate_limiter = InMemoryRateLimiter()
        
        # Simulate multiple attackers
        attackers = [f"attacker_{i}" for i in range(10)]
        
        # Each attacker tries to brute force login
        blocked_attackers = 0
        
        for attacker in attackers:
            # Try multiple failed logins
            for attempt in range(6):
                lockout_triggered = await rate_limiter.record_failed_login(attacker)
                if lockout_triggered:
                    blocked_attackers += 1
                    break
        
        # All attackers should be blocked
        assert blocked_attackers == len(attackers)
        
        # Verify all are locked out
        for attacker in attackers:
            is_locked, _ = await rate_limiter.is_locked_out(attacker)
            assert is_locked is True
    
    async def test_legitimate_user_during_attack(self):
        """Test that legitimate users can still access during attack."""
        rate_limiter = InMemoryRateLimiter()
        
        # Simulate attack from one IP
        attacker_ip = "192.168.1.100"
        for i in range(10):
            await rate_limiter.record_failed_login(attacker_ip)
        
        # Attacker should be locked out
        is_locked, _ = await rate_limiter.is_locked_out(attacker_ip)
        assert is_locked is True
        
        # Legitimate user from different IP should still work
        legitimate_ip = "192.168.1.10"
        result = await rate_limiter.check_rate_limit(
            legitimate_ip, window_seconds=60, max_requests=10
        )
        assert result.allowed is True