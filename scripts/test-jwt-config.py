#!/usr/bin/env python3
"""
JWT Configuration Test Tool

This script tests JWT configuration by creating and verifying tokens,
demonstrating proper JWT functionality and configuration consistency.
"""

import os
import sys
import argparse
from pathlib import Path
from typing import Dict, Any, Tuple
from datetime import datetime, timedelta, timezone
import json


def load_env_file(env_file: str) -> Dict[str, str]:
    """Load environment variables from file."""
    env_vars = {}
    env_path = Path(env_file)
    
    if not env_path.exists():
        print(f"❌ Environment file not found: {env_file}")
        return env_vars
    
    try:
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                env_vars[key] = value
    except Exception as e:
        print(f"❌ Error reading {env_file}: {e}")
    
    return env_vars


def setup_environment(env_vars: Dict[str, str]) -> None:
    """Setup environment variables for testing."""
    for key, value in env_vars.items():
        os.environ[key] = value


def test_jwt_creation_and_verification(test_email: str = "test@example.com") -> Tuple[bool, Dict[str, Any]]:
    """Test JWT token creation and verification."""
    results = {
        "jwt_secret_length": 0,
        "access_token_created": False,
        "access_token_verified": False,
        "refresh_token_created": False,
        "refresh_token_verified": False,
        "tokens_unique": False,
        "expiration_working": False,
        "claims_correct": False,
        "errors": []
    }
    
    try:
        # Import after environment is set
        from services.security import SecurityConfig
        from services.auth import create_access_token, create_refresh_token
        from jose import jwt, JWTError
        
        # Test security config
        config = SecurityConfig()
        results["jwt_secret_length"] = len(config.jwt_secret_key)
        
        print(f"✓ SecurityConfig loaded")
        print(f"  JWT Secret Length: {results['jwt_secret_length']} characters")
        print(f"  JWT Algorithm: {config.jwt_algorithm}")
        
        # Test access token creation
        try:
            access_token = create_access_token({"sub": test_email})
            results["access_token_created"] = True
            print(f"✓ Access token created: {access_token[:50]}...")
        except Exception as e:
            results["errors"].append(f"Access token creation failed: {e}")
            return False, results
        
        # Test access token verification
        try:
            payload = jwt.decode(
                access_token,
                config.jwt_secret_key,
                algorithms=[config.jwt_algorithm]
            )
            results["access_token_verified"] = True
            
            # Check claims
            if (payload.get("sub") == test_email and 
                payload.get("type") == "access" and
                "exp" in payload and "iat" in payload):
                results["claims_correct"] = True
                print(f"✓ Access token verified with correct claims")
                print(f"  Subject: {payload['sub']}")
                print(f"  Type: {payload['type']}")
                print(f"  Expires: {datetime.fromtimestamp(payload['exp'])}")
            else:
                results["errors"].append("Access token claims are incorrect")
        except JWTError as e:
            results["errors"].append(f"Access token verification failed: {e}")
        
        # Test refresh token creation
        try:
            refresh_token1 = create_refresh_token(test_email)
            refresh_token2 = create_refresh_token(test_email)
            results["refresh_token_created"] = True
            
            # Check if tokens are unique
            if refresh_token1 != refresh_token2:
                results["tokens_unique"] = True
                print(f"✓ Refresh tokens are unique")
            else:
                results["errors"].append("Refresh tokens are not unique")
            
            print(f"✓ Refresh tokens created")
        except Exception as e:
            results["errors"].append(f"Refresh token creation failed: {e}")
            return False, results
        
        # Test refresh token verification
        try:
            refresh_payload = jwt.decode(
                refresh_token1,
                config.jwt_secret_key,
                algorithms=[config.jwt_algorithm]
            )
            results["refresh_token_verified"] = True
            
            if (refresh_payload.get("sub") == test_email and 
                refresh_payload.get("type") == "refresh" and
                "jti" in refresh_payload):
                print(f"✓ Refresh token verified with correct claims")
                print(f"  Subject: {refresh_payload['sub']}")
                print(f"  Type: {refresh_payload['type']}")
                print(f"  JTI: {refresh_payload['jti']}")
            else:
                results["errors"].append("Refresh token claims are incorrect")
        except JWTError as e:
            results["errors"].append(f"Refresh token verification failed: {e}")
        
        # Test token expiration
        try:
            # Create a short-lived token
            short_token = create_access_token(
                {"sub": test_email}, 
                expires_delta=timedelta(seconds=1)
            )
            
            # Wait for expiration
            import time
            time.sleep(2)
            
            # Try to verify expired token
            try:
                jwt.decode(short_token, config.jwt_secret_key, algorithms=[config.jwt_algorithm])
                results["errors"].append("Expired token was accepted - expiration not working")
            except JWTError:
                results["expiration_working"] = True
                print(f"✓ Token expiration working correctly")
        except Exception as e:
            results["errors"].append(f"Expiration test failed: {e}")
        
    except ImportError as e:
        results["errors"].append(f"Import error - ensure application modules are available: {e}")
        return False, results
    except Exception as e:
        results["errors"].append(f"Unexpected error: {e}")
        return False, results
    
    # Determine overall success
    success = (
        results["access_token_created"] and
        results["access_token_verified"] and
        results["refresh_token_created"] and
        results["refresh_token_verified"] and
        results["tokens_unique"] and
        results["expiration_working"] and
        results["claims_correct"] and
        len(results["errors"]) == 0
    )
    
    return success, results


def test_cross_environment_isolation() -> Tuple[bool, Dict[str, Any]]:
    """Test that different environments use different JWT secrets."""
    results = {
        "different_secrets": False,
        "errors": []
    }
    
    try:
        env_files = [".env.development", ".env.test"]
        secrets = {}
        
        for env_file in env_files:
            if Path(env_file).exists():
                env_vars = load_env_file(env_file)
                if "JWT_SECRET_KEY" in env_vars:
                    secrets[env_file] = env_vars["JWT_SECRET_KEY"]
        
        if len(secrets) >= 2:
            secret_values = list(secrets.values())
            if len(set(secret_values)) == len(secret_values):
                results["different_secrets"] = True
                print(f"✓ Environment isolation: Different JWT secrets in use")
                for env_file, secret in secrets.items():
                    print(f"  {env_file}: {len(secret)} chars")
            else:
                results["errors"].append("Multiple environments are using the same JWT secret")
        else:
            results["errors"].append("Not enough environment files to test isolation")
    
    except Exception as e:
        results["errors"].append(f"Environment isolation test failed: {e}")
    
    return results["different_secrets"] and len(results["errors"]) == 0, results


def generate_test_report(test_results: Dict[str, Any], cross_env_results: Dict[str, Any]) -> str:
    """Generate a comprehensive test report."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "jwt_functionality": test_results,
        "environment_isolation": cross_env_results,
        "summary": {
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "overall_status": "UNKNOWN"
        }
    }
    
    # Count tests
    jwt_tests = [
        "access_token_created", "access_token_verified", "refresh_token_created",
        "refresh_token_verified", "tokens_unique", "expiration_working", "claims_correct"
    ]
    
    jwt_passed = sum(1 for test in jwt_tests if test_results.get(test, False))
    jwt_total = len(jwt_tests)
    
    env_passed = 1 if cross_env_results.get("different_secrets", False) else 0
    env_total = 1
    
    report["summary"]["total_tests"] = jwt_total + env_total
    report["summary"]["passed_tests"] = jwt_passed + env_passed
    report["summary"]["failed_tests"] = report["summary"]["total_tests"] - report["summary"]["passed_tests"]
    
    if report["summary"]["failed_tests"] == 0:
        report["summary"]["overall_status"] = "PASS"
    else:
        report["summary"]["overall_status"] = "FAIL"
    
    return json.dumps(report, indent=2)


def main():
    """Main function to handle command line interface."""
    parser = argparse.ArgumentParser(
        description="Test JWT configuration functionality",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test current environment JWT configuration
  python3 test-jwt-config.py
  
  # Test specific environment file
  python3 test-jwt-config.py --env .env.test
  
  # Test with custom user email
  python3 test-jwt-config.py --email custom@example.com
  
  # Generate JSON report
  python3 test-jwt-config.py --format json --output jwt-test-report.json
        """
    )
    
    parser.add_argument(
        "--env", "-e",
        type=str,
        help="Environment file to test"
    )
    
    parser.add_argument(
        "--email",
        type=str,
        default="test@example.com",
        help="Email to use for testing (default: test@example.com)"
    )
    
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file for results"
    )
    
    args = parser.parse_args()
    
    # Setup environment
    if args.env:
        print(f"🧪 Testing JWT Configuration: {args.env}")
        env_vars = load_env_file(args.env)
        if not env_vars:
            sys.exit(1)
        setup_environment(env_vars)
    else:
        print(f"🧪 Testing JWT Configuration: Current Environment")
    
    print("=" * 50)
    
    # Run JWT functionality tests
    print("\n🔐 Testing JWT Functionality")
    print("-" * 30)
    
    jwt_success, jwt_results = test_jwt_creation_and_verification(args.email)
    
    if jwt_results["errors"]:
        print("\n❌ Errors:")
        for error in jwt_results["errors"]:
            print(f"   • {error}")
    
    # Run cross-environment isolation tests
    print("\n🌍 Testing Environment Isolation")
    print("-" * 35)
    
    env_success, env_results = test_cross_environment_isolation()
    
    if env_results["errors"]:
        print("\n❌ Environment Isolation Errors:")
        for error in env_results["errors"]:
            print(f"   • {error}")
    
    # Generate summary
    print("\n📊 Test Summary")
    print("-" * 15)
    
    overall_success = jwt_success and env_success
    
    if overall_success:
        print("🎉 All JWT tests PASSED!")
        print("   ✅ JWT functionality is working correctly")
        print("   ✅ Environment isolation is properly configured")
    else:
        print("❌ Some JWT tests FAILED")
        if not jwt_success:
            print("   ❌ JWT functionality has issues")
        if not env_success:
            print("   ❌ Environment isolation has issues")
    
    # Handle output
    if args.format == "json" or args.output:
        report = generate_test_report(jwt_results, env_results)
        
        if args.output:
            Path(args.output).write_text(report)
            print(f"\n📄 Report written to: {args.output}")
        else:
            print(f"\n📄 JSON Report:")
            print(report)
    
    # Exit with appropriate code
    sys.exit(0 if overall_success else 1)


if __name__ == "__main__":
    main()