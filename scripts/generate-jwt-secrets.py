#!/usr/bin/env python3
"""
JWT Secret Generation Utility

This script generates cryptographically secure JWT secrets for different environments.
It can generate secrets of various lengths and formats suitable for production use.
"""

import secrets
import string
import argparse
import os
from pathlib import Path
from typing import Tuple


class JWTSecretGenerator:
    """Utility class for generating secure JWT secrets."""
    
    def __init__(self):
        self.base_alphabet = string.ascii_letters + string.digits
        self.secure_alphabet = self.base_alphabet + "!@#$%^&*()_+-="
    
    def generate_secret(self, length: int = 64, secure_chars: bool = True) -> str:
        """Generate a cryptographically secure secret."""
        alphabet = self.secure_alphabet if secure_chars else self.base_alphabet
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def generate_url_safe_secret(self, length: int = 64) -> str:
        """Generate a URL-safe secret (base64url)."""
        return secrets.token_urlsafe(length)
    
    def generate_hex_secret(self, length: int = 64) -> str:
        """Generate a hexadecimal secret."""
        return secrets.token_hex(length)
    
    def validate_secret_strength(self, secret: str) -> Tuple[bool, list[str]]:
        """Validate the strength of a secret."""
        issues = []
        
        if len(secret) < 32:
            issues.append(f"Secret too short ({len(secret)} chars). Minimum 32 characters required.")
        
        if len(secret) < 64:
            issues.append(f"Secret length ({len(secret)} chars) is less than recommended 64 characters.")
        
        # Check character diversity
        has_letters = any(c.isalpha() for c in secret)
        has_digits = any(c.isdigit() for c in secret)
        has_special = any(c in "!@#$%^&*()_+-=" for c in secret)
        
        if not has_letters:
            issues.append("Secret should contain letters for better entropy.")
        
        if not has_digits:
            issues.append("Secret should contain digits for better entropy.")
        
        # Check for common weak patterns
        if secret.lower() in ['secret', 'password', 'key', 'token']:
            issues.append("Secret appears to be a common weak value.")
        
        if 'super-secret' in secret.lower():
            issues.append("Secret contains default/example values.")
        
        return len(issues) == 0, issues


def update_env_file(env_file_path: Path, new_secret: str, backup: bool = True) -> bool:
    """Update JWT_SECRET_KEY in an environment file."""
    if not env_file_path.exists():
        print(f"❌ Environment file not found: {env_file_path}")
        return False
    
    # Create backup if requested
    if backup:
        backup_path = env_file_path.with_suffix(f"{env_file_path.suffix}.backup")
        backup_path.write_text(env_file_path.read_text())
        print(f"✅ Backup created: {backup_path}")
    
    # Read current content
    lines = env_file_path.read_text().splitlines()
    updated_lines = []
    jwt_key_updated = False
    
    for line in lines:
        if line.startswith("JWT_SECRET_KEY="):
            updated_lines.append(f"JWT_SECRET_KEY={new_secret}")
            jwt_key_updated = True
        else:
            updated_lines.append(line)
    
    # If JWT_SECRET_KEY wasn't found, add it
    if not jwt_key_updated:
        updated_lines.append(f"JWT_SECRET_KEY={new_secret}")
    
    # Write updated content
    env_file_path.write_text('\n'.join(updated_lines) + '\n')
    print(f"✅ Updated {env_file_path}")
    
    return True


def main():
    """Main function to handle command line interface."""
    parser = argparse.ArgumentParser(
        description="Generate cryptographically secure JWT secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a secure secret and display it
  python3 generate-jwt-secrets.py
  
  # Generate a 128-character secret
  python3 generate-jwt-secrets.py --length 128
  
  # Generate URL-safe secret
  python3 generate-jwt-secrets.py --format urlsafe
  
  # Update development environment file
  python3 generate-jwt-secrets.py --update-env .env.development
  
  # Generate secrets for all environments
  python3 generate-jwt-secrets.py --update-all
        """
    )
    
    parser.add_argument(
        "--length", "-l", 
        type=int, 
        default=64,
        help="Length of the secret (default: 64)"
    )
    
    parser.add_argument(
        "--format", "-f",
        choices=["secure", "urlsafe", "hex"],
        default="secure",
        help="Secret format (default: secure)"
    )
    
    parser.add_argument(
        "--update-env",
        type=str,
        help="Update JWT_SECRET_KEY in specified environment file"
    )
    
    parser.add_argument(
        "--update-all",
        action="store_true",
        help="Update JWT_SECRET_KEY in all environment files"
    )
    
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Don't create backup files when updating"
    )
    
    parser.add_argument(
        "--validate",
        type=str,
        help="Validate the strength of an existing secret"
    )
    
    args = parser.parse_args()
    
    generator = JWTSecretGenerator()
    
    # Handle validation mode
    if args.validate:
        is_strong, issues = generator.validate_secret_strength(args.validate)
        print(f"Secret validation for: {args.validate[:20]}...")
        print(f"Length: {len(args.validate)} characters")
        
        if is_strong:
            print("✅ Secret strength: GOOD")
        else:
            print("⚠️  Secret strength: NEEDS IMPROVEMENT")
            for issue in issues:
                print(f"   • {issue}")
        return
    
    # Generate secret
    if args.format == "urlsafe":
        secret = generator.generate_url_safe_secret(args.length)
    elif args.format == "hex":
        secret = generator.generate_hex_secret(args.length)
    else:
        secret = generator.generate_secret(args.length, secure_chars=True)
    
    print(f"🔐 Generated {args.format} JWT secret ({len(secret)} characters):")
    print(f"   {secret}")
    print()
    
    # Validate the generated secret
    is_strong, issues = generator.validate_secret_strength(secret)
    if is_strong:
        print("✅ Secret strength: EXCELLENT")
    else:
        print("⚠️  Secret validation issues:")
        for issue in issues:
            print(f"   • {issue}")
    
    # Handle environment file updates
    backup = not args.no_backup
    
    if args.update_env:
        env_path = Path(args.update_env)
        update_env_file(env_path, secret, backup)
    
    elif args.update_all:
        # Update common environment files
        env_files = [
            ".env",
            ".env.development", 
            ".env.test",
        ]
        
        updated_count = 0
        for env_file in env_files:
            env_path = Path(env_file)
            if env_path.exists():
                if env_file == ".env.test":
                    # Use a different secret for test environment
                    test_secret = f"test_jwt_{generator.generate_secret(60, secure_chars=False)}"
                    update_env_file(env_path, test_secret, backup)
                else:
                    update_env_file(env_path, secret, backup)
                updated_count += 1
        
        print(f"\n🎉 Updated {updated_count} environment files")
        print("\n⚠️  IMPORTANT: For production environments:")
        print("   • Never commit .env.production to version control")
        print("   • Use a secure secret management system")
        print("   • Generate unique secrets for each environment")
        print("   • Rotate secrets regularly")
    
    if not args.update_env and not args.update_all:
        print("\nTo use this secret:")
        print(f"   export JWT_SECRET_KEY='{secret}'")
        print(f"   # or add to your .env file:")
        print(f"   echo 'JWT_SECRET_KEY={secret}' >> .env")


if __name__ == "__main__":
    main()