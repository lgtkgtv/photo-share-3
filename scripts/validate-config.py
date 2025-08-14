#!/usr/bin/env python3
"""
Configuration Validation Tool

This script validates the application configuration for security and completeness.
It checks environment variables, JWT configuration, database settings, and more.
"""

import os
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Any
import re
from datetime import datetime


class ConfigValidator:
    """Configuration validation utility."""
    
    def __init__(self, env_file: str = None):
        self.env_file = env_file
        self.warnings = []
        self.errors = []
        self.info = []
        
    def load_env_file(self, env_file: str) -> Dict[str, str]:
        """Load environment variables from file."""
        env_vars = {}
        env_path = Path(env_file)
        
        if not env_path.exists():
            self.errors.append(f"Environment file not found: {env_file}")
            return env_vars
        
        try:
            for line in env_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key] = value
        except Exception as e:
            self.errors.append(f"Error reading {env_file}: {e}")
        
        return env_vars
    
    def get_config_value(self, key: str, env_vars: Dict[str, str] = None) -> str:
        """Get configuration value from environment or env file."""
        if env_vars and key in env_vars:
            return env_vars[key]
        return os.getenv(key, "")
    
    def validate_jwt_config(self, env_vars: Dict[str, str] = None) -> None:
        """Validate JWT configuration."""
        print("🔐 Validating JWT Configuration")
        print("=" * 35)
        
        # Check JWT_SECRET_KEY
        jwt_secret = self.get_config_value("JWT_SECRET_KEY", env_vars)
        if not jwt_secret:
            self.errors.append("JWT_SECRET_KEY is not set")
        else:
            if len(jwt_secret) < 32:
                self.errors.append(f"JWT_SECRET_KEY too short ({len(jwt_secret)} chars). Minimum 32 required.")
            elif len(jwt_secret) < 64:
                self.warnings.append(f"JWT_SECRET_KEY length ({len(jwt_secret)} chars) is less than recommended 64.")
            else:
                self.info.append(f"JWT_SECRET_KEY length: {len(jwt_secret)} chars ✓")
            
            # Check for weak secrets
            weak_secrets = [
                "super-secret-key", "secret", "password", "key", "token",
                "development-secret", "test-secret"
            ]
            if any(weak in jwt_secret.lower() for weak in weak_secrets):
                self.warnings.append("JWT_SECRET_KEY appears to contain weak/default values")
            
            # Check character diversity
            has_letters = any(c.isalpha() for c in jwt_secret)
            has_digits = any(c.isdigit() for c in jwt_secret)
            has_special = any(c in "!@#$%^&*()_+-=" for c in jwt_secret)
            
            if not (has_letters and has_digits):
                self.warnings.append("JWT_SECRET_KEY should contain both letters and digits for better entropy")
        
        # Check JWT_ALGORITHM
        jwt_algorithm = self.get_config_value("JWT_ALGORITHM", env_vars)
        if not jwt_algorithm:
            self.warnings.append("JWT_ALGORITHM not set, using default")
        elif jwt_algorithm not in ["HS256", "HS384", "HS512"]:
            self.errors.append(f"Unsupported JWT_ALGORITHM: {jwt_algorithm}")
        else:
            self.info.append(f"JWT_ALGORITHM: {jwt_algorithm} ✓")
        
        # Check token expiration
        access_expire = self.get_config_value("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", env_vars)
        if access_expire:
            try:
                expire_minutes = int(access_expire)
                if expire_minutes > 60:
                    self.warnings.append(f"JWT access token expiration ({expire_minutes} min) is quite long for production")
                elif expire_minutes < 5:
                    self.warnings.append(f"JWT access token expiration ({expire_minutes} min) is very short")
                else:
                    self.info.append(f"JWT access token expiration: {expire_minutes} minutes ✓")
            except ValueError:
                self.errors.append(f"Invalid JWT_ACCESS_TOKEN_EXPIRE_MINUTES: {access_expire}")
    
    def validate_database_config(self, env_vars: Dict[str, str] = None) -> None:
        """Validate database configuration."""
        print("\n🗄️  Validating Database Configuration")
        print("=" * 38)
        
        required_db_vars = ["POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD", "DB_HOST", "DB_PORT"]
        
        for var in required_db_vars:
            value = self.get_config_value(var, env_vars)
            if not value:
                self.errors.append(f"{var} is not set")
            else:
                self.info.append(f"{var}: {value} ✓")
        
        # Validate database password strength
        db_password = self.get_config_value("POSTGRES_PASSWORD", env_vars)
        if db_password:
            if len(db_password) < 12:
                self.warnings.append(f"Database password is short ({len(db_password)} chars). Consider longer password.")
            if db_password in ["password", "admin", "root", "postgres"]:
                self.errors.append("Database password is a common/weak value")
    
    def validate_security_config(self, env_vars: Dict[str, str] = None) -> None:
        """Validate security configuration."""
        print("\n🛡️  Validating Security Configuration")
        print("=" * 37)
        
        # Password policy
        password_min_length = self.get_config_value("PASSWORD_MIN_LENGTH", env_vars)
        if password_min_length:
            try:
                min_len = int(password_min_length)
                if min_len < 8:
                    self.warnings.append(f"Password minimum length ({min_len}) is quite short")
                else:
                    self.info.append(f"Password minimum length: {min_len} ✓")
            except ValueError:
                self.errors.append(f"Invalid PASSWORD_MIN_LENGTH: {password_min_length}")
        
        # Rate limiting
        rate_limit = self.get_config_value("RATE_LIMIT_LOGIN_ATTEMPTS_PER_HOUR", env_vars)
        if rate_limit:
            try:
                limit = int(rate_limit)
                if limit > 20:
                    self.warnings.append(f"Login rate limit ({limit}/hour) may be too permissive for production")
                else:
                    self.info.append(f"Login rate limit: {limit} attempts/hour ✓")
            except ValueError:
                self.errors.append(f"Invalid RATE_LIMIT_LOGIN_ATTEMPTS_PER_HOUR: {rate_limit}")
        
        # Security headers
        csrf_protection = self.get_config_value("ENABLE_CSRF_PROTECTION", env_vars)
        if csrf_protection and csrf_protection.lower() == "false":
            self.warnings.append("CSRF protection is disabled - ensure this is intentional")
        
        security_headers = self.get_config_value("ENABLE_SECURITY_HEADERS", env_vars)
        if security_headers and security_headers.lower() == "false":
            self.warnings.append("Security headers are disabled - not recommended for production")
    
    def validate_environment_specific(self, env_vars: Dict[str, str] = None) -> None:
        """Validate environment-specific configuration."""
        print("\n🌍 Validating Environment-Specific Configuration")
        print("=" * 49)
        
        environment = self.get_config_value("ENVIRONMENT", env_vars)
        debug = self.get_config_value("DEBUG", env_vars)
        
        if environment:
            self.info.append(f"Environment: {environment} ✓")
            
            if environment.lower() == "production":
                # Production-specific checks
                if debug and debug.lower() == "true":
                    self.errors.append("DEBUG is enabled in production environment")
                
                api_docs = self.get_config_value("ENABLE_API_DOCS", env_vars)
                if api_docs and api_docs.lower() == "true":
                    self.warnings.append("API documentation is enabled in production")
                
                # Check for development/test secrets in production
                jwt_secret = self.get_config_value("JWT_SECRET_KEY", env_vars)
                if jwt_secret and ("development" in jwt_secret.lower() or "test" in jwt_secret.lower()):
                    self.errors.append("Production environment appears to use development/test JWT secret")
            
            elif environment.lower() in ["development", "dev"]:
                # Development-specific checks
                if not debug or debug.lower() != "true":
                    self.info.append("Consider enabling DEBUG for development environment")
            
            elif environment.lower() == "test":
                # Test-specific checks
                if debug and debug.lower() == "true":
                    self.info.append("DEBUG enabled for test environment ✓")
        else:
            self.warnings.append("ENVIRONMENT variable not set - defaulting behavior may be unclear")
    
    def check_file_permissions(self) -> None:
        """Check file permissions for security."""
        print("\n📁 Checking File Permissions")
        print("=" * 28)
        
        sensitive_files = [".env", ".env.production", ".env.local"]
        
        for file_name in sensitive_files:
            file_path = Path(file_name)
            if file_path.exists():
                try:
                    stat = file_path.stat()
                    mode = stat.st_mode
                    
                    # Check if file is readable by group/others
                    if mode & 0o044:  # Group or others can read
                        self.warnings.append(f"{file_name} is readable by group/others - consider restricting permissions")
                    else:
                        self.info.append(f"{file_name} permissions: secure ✓")
                except OSError as e:
                    self.warnings.append(f"Could not check permissions for {file_name}: {e}")
    
    def generate_recommendations(self) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if self.errors:
            recommendations.append("🚨 Fix all ERROR items before deploying to production")
        
        if self.warnings:
            recommendations.append("⚠️  Review and address WARNING items for better security")
        
        recommendations.extend([
            "🔄 Rotate JWT secrets regularly (at least every 6 months)",
            "🔐 Use a secure secret management system in production",
            "📊 Monitor security events and failed authentication attempts",
            "🧪 Run security tests regularly with: ./scripts/run-tests.sh --type security",
            "📋 Review security configuration before each deployment"
        ])
        
        return recommendations
    
    def run_validation(self, env_file: str = None) -> bool:
        """Run complete configuration validation."""
        print("🔍 Photo Share App Configuration Validation")
        print("=" * 45)
        print(f"Timestamp: {datetime.now().isoformat()}")
        
        env_vars = {}
        if env_file:
            print(f"Environment file: {env_file}")
            env_vars = self.load_env_file(env_file)
        else:
            print("Using current environment variables")
        
        # Run all validations
        self.validate_jwt_config(env_vars)
        self.validate_database_config(env_vars)
        self.validate_security_config(env_vars)
        self.validate_environment_specific(env_vars)
        self.check_file_permissions()
        
        # Display results
        print("\n📊 Validation Results")
        print("=" * 21)
        
        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"   • {error}")
        
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"   • {warning}")
        
        if self.info:
            print(f"\n✅ PASSED ({len(self.info)}):")
            for info in self.info:
                print(f"   • {info}")
        
        # Generate recommendations
        recommendations = self.generate_recommendations()
        if recommendations:
            print(f"\n💡 RECOMMENDATIONS:")
            for rec in recommendations:
                print(f"   • {rec}")
        
        # Summary
        total_issues = len(self.errors) + len(self.warnings)
        print(f"\n🎯 SUMMARY:")
        print(f"   • Total issues: {total_issues}")
        print(f"   • Errors: {len(self.errors)}")
        print(f"   • Warnings: {len(self.warnings)}")
        print(f"   • Passed checks: {len(self.info)}")
        
        if self.errors:
            print(f"\n🚨 Configuration has CRITICAL ERRORS and should not be used in production!")
            return False
        elif self.warnings:
            print(f"\n⚠️  Configuration has warnings but is usable. Consider addressing them.")
            return True
        else:
            print(f"\n🎉 Configuration validation passed!")
            return True


def main():
    """Main function to handle command line interface."""
    parser = argparse.ArgumentParser(
        description="Validate Photo Share App configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate current environment
  python3 validate-config.py
  
  # Validate specific environment file
  python3 validate-config.py --env .env.production
  
  # Validate all environment files
  python3 validate-config.py --all
        """
    )
    
    parser.add_argument(
        "--env", "-e",
        type=str,
        help="Environment file to validate"
    )
    
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Validate all environment files"
    )
    
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors"
    )
    
    args = parser.parse_args()
    
    validator = ConfigValidator()
    success = True
    
    if args.all:
        # Validate all environment files
        env_files = [".env", ".env.development", ".env.test", ".env.production"]
        
        for env_file in env_files:
            if Path(env_file).exists():
                print(f"\n{'='*60}")
                print(f"Validating {env_file}")
                print(f"{'='*60}")
                
                file_validator = ConfigValidator()
                file_success = file_validator.run_validation(env_file)
                
                if not file_success:
                    success = False
                
                if args.strict and file_validator.warnings:
                    success = False
            else:
                print(f"\n⚠️  Skipping {env_file} (not found)")
    
    else:
        # Validate single configuration
        file_success = validator.run_validation(args.env)
        
        if not file_success:
            success = False
        
        if args.strict and validator.warnings:
            success = False
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()