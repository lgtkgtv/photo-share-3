# Production Security Guide

This document provides comprehensive guidance for securing the Photo Share App in production environments.

## Table of Contents

- [JWT Secret Management](#jwt-secret-management)
- [Environment Configuration](#environment-configuration)
- [Secret Management Systems](#secret-management-systems)
- [Deployment Security](#deployment-security)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Security Checklist](#security-checklist)

## JWT Secret Management

### Overview

JSON Web Tokens (JWT) are the backbone of authentication in the Photo Share App. Proper secret management is critical for security.

### Requirements

#### Secret Generation

```bash
# Generate a cryptographically secure JWT secret (recommended: 64+ characters)
python3 scripts/generate-jwt-secrets.py --length 64 --format secure

# For production, use URL-safe encoding
python3 scripts/generate-jwt-secrets.py --length 64 --format urlsafe
```

#### Secret Properties

- **Minimum Length**: 32 characters (64+ recommended)
- **Character Set**: Letters, numbers, and special characters
- **Uniqueness**: Each environment must have a unique secret
- **Rotation**: Rotate every 6 months or after security incidents

### Secret Storage

#### ❌ Never Do This

```bash
# DON'T: Store secrets in code
JWT_SECRET_KEY = "super-secret-key"

# DON'T: Commit secrets to version control
git add .env.production

# DON'T: Use the same secret across environments
JWT_SECRET_KEY=same_secret_everywhere

# DON'T: Use weak or predictable secrets
JWT_SECRET_KEY=password123
```

#### ✅ Best Practices

```bash
# DO: Use environment-specific secrets
# Development
JWT_SECRET_KEY=dev_unique_secret_64_chars_minimum...

# Production  
JWT_SECRET_KEY=prod_unique_secret_64_chars_minimum...

# DO: Store in secure secret management systems
# AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, etc.
```

## Environment Configuration

### Development Environment

```env
# .env.development
ENVIRONMENT=development
DEBUG=true
JWT_SECRET_KEY=dev_jwt_secret_64_chars_minimum_for_local_development_only
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
PASSWORD_MIN_LENGTH=8
RATE_LIMIT_LOGIN_ATTEMPTS_PER_HOUR=20
```

### Testing Environment

```env
# .env.test
ENVIRONMENT=test
DEBUG=false
JWT_SECRET_KEY=test_jwt_secret_64_chars_minimum_for_testing_only
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
PASSWORD_MIN_LENGTH=8
RATE_LIMIT_LOGIN_ATTEMPTS_PER_HOUR=10
```

### Production Environment

```env
# .env.production (NEVER commit this file)
ENVIRONMENT=production
DEBUG=false
JWT_SECRET_KEY=GENERATE_UNIQUE_64_CHAR_SECRET_FOR_PRODUCTION
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
PASSWORD_MIN_LENGTH=12
RATE_LIMIT_LOGIN_ATTEMPTS_PER_HOUR=5
ENABLE_CSRF_PROTECTION=true
FORCE_HTTPS=true
```

## Secret Management Systems

### AWS Secrets Manager

#### Setup

```bash
# Create secret in AWS Secrets Manager
aws secretsmanager create-secret \
    --name "photoapp/production/jwt-secret" \
    --description "JWT secret for Photo Share App production" \
    --secret-string "$(python3 scripts/generate-jwt-secrets.py --format urlsafe)"
```

#### Retrieval in Application

```python
import boto3
import json
from botocore.exceptions import ClientError

def get_jwt_secret():
    secret_name = "photoapp/production/jwt-secret"
    region_name = "us-east-1"
    
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return response['SecretString']
    except ClientError as e:
        raise e
```

### HashiCorp Vault

#### Setup

```bash
# Enable KV secrets engine
vault secrets enable -path=photoapp kv-v2

# Store JWT secret
vault kv put photoapp/production \
    jwt_secret="$(python3 scripts/generate-jwt-secrets.py --format urlsafe)"
```

#### Retrieval

```python
import hvac

def get_jwt_secret():
    client = hvac.Client(url='https://vault.company.com:8200')
    client.token = os.environ['VAULT_TOKEN']
    
    response = client.secrets.kv.v2.read_secret_version(
        path='production',
        mount_point='photoapp'
    )
    
    return response['data']['data']['jwt_secret']
```

### Azure Key Vault

#### Setup

```bash
# Create secret in Azure Key Vault
az keyvault secret set \
    --vault-name "photoapp-prod-vault" \
    --name "jwt-secret" \
    --value "$(python3 scripts/generate-jwt-secrets.py --format urlsafe)"
```

#### Retrieval

```python
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

def get_jwt_secret():
    vault_url = "https://photoapp-prod-vault.vault.azure.net/"
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)
    
    secret = client.get_secret("jwt-secret")
    return secret.value
```

## Deployment Security

### Docker Secrets

#### Using Docker Swarm Secrets

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  backend:
    image: photoapp:latest
    secrets:
      - jwt_secret
    environment:
      - JWT_SECRET_KEY_FILE=/run/secrets/jwt_secret
    deploy:
      replicas: 3

secrets:
  jwt_secret:
    external: true
```

#### Creating Secrets

```bash
# Create secret from file
echo "your_super_secure_jwt_secret_64_chars_minimum" | docker secret create jwt_secret -

# Deploy with secrets
docker stack deploy -c docker-compose.prod.yml photoapp
```

### Kubernetes Secrets

#### Creating Kubernetes Secret

```yaml
# jwt-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: jwt-secret
  namespace: photoapp
type: Opaque
data:
  jwt-secret-key: <base64-encoded-secret>
```

```bash
# Create secret
kubectl apply -f jwt-secret.yaml

# Or create directly
kubectl create secret generic jwt-secret \
    --from-literal=jwt-secret-key="$(python3 scripts/generate-jwt-secrets.py --format urlsafe)" \
    -n photoapp
```

#### Using in Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: photoapp-backend
spec:
  template:
    spec:
      containers:
      - name: backend
        image: photoapp:latest
        env:
        - name: JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: jwt-secret
              key: jwt-secret-key
```

### CI/CD Pipeline Security

#### GitHub Actions Example

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v2
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: us-east-1
    
    - name: Deploy application
      run: |
        # Retrieve secrets from AWS Secrets Manager
        JWT_SECRET=$(aws secretsmanager get-secret-value \
          --secret-id photoapp/production/jwt-secret \
          --query SecretString --output text)
        
        # Deploy with secrets
        docker run -e JWT_SECRET_KEY="$JWT_SECRET" photoapp:latest
```

## Monitoring and Alerting

### Security Event Monitoring

#### Log Analysis

```python
# Example security event monitoring
import logging
from datetime import datetime, timedelta

class SecurityMonitor:
    def __init__(self):
        self.failed_login_threshold = 10
        self.time_window = timedelta(minutes=5)
    
    def monitor_failed_logins(self, client_ip: str):
        # Count failed logins in time window
        recent_failures = self.count_recent_failures(client_ip)
        
        if recent_failures >= self.failed_login_threshold:
            self.alert_security_team(
                f"Suspicious activity: {recent_failures} failed logins from {client_ip}"
            )
    
    def alert_security_team(self, message: str):
        # Send alert to security team
        # Integration with Slack, PagerDuty, etc.
        pass
```

#### Metrics to Monitor

- Failed authentication attempts per IP/user
- JWT token validation failures
- Unusual access patterns
- Configuration changes
- Secret rotation events

### Health Checks

#### JWT Configuration Health Check

```python
from fastapi import APIRouter, HTTPException
from services.security import security_config

router = APIRouter()

@router.get("/health/jwt")
async def jwt_health_check():
    """Health check for JWT configuration."""
    issues = []
    
    # Check secret length
    if len(security_config.jwt_secret_key) < 32:
        issues.append("JWT secret too short")
    
    # Check algorithm
    if security_config.jwt_algorithm not in ["HS256", "HS384", "HS512"]:
        issues.append("Unsupported JWT algorithm")
    
    # Check expiration
    if security_config.jwt_access_token_expire_minutes > 60:
        issues.append("JWT expiration too long for production")
    
    if issues:
        raise HTTPException(status_code=500, detail={"issues": issues})
    
    return {"status": "healthy", "jwt_config": "valid"}
```

## Security Checklist

### Pre-Deployment Checklist

#### Configuration Security

- [ ] Unique JWT secrets for each environment
- [ ] JWT secrets are 64+ characters long
- [ ] No default/weak secrets in use
- [ ] Debug mode disabled in production
- [ ] CSRF protection enabled
- [ ] Security headers enabled
- [ ] Rate limiting properly configured
- [ ] Password policies enforced

#### Secret Management

- [ ] Secrets stored in secure management system
- [ ] No secrets in version control
- [ ] No secrets in Docker images
- [ ] Environment variables properly isolated
- [ ] Secret rotation procedure documented
- [ ] Backup and recovery plan for secrets

#### Infrastructure Security

- [ ] HTTPS enforced
- [ ] Database connection encrypted
- [ ] Network security groups configured
- [ ] Container security scanning enabled
- [ ] Vulnerability scanning implemented
- [ ] Access logs enabled

### Post-Deployment Checklist

#### Monitoring

- [ ] Security event monitoring enabled
- [ ] Failed login alerting configured
- [ ] JWT validation monitoring active
- [ ] Performance metrics collected
- [ ] Error tracking operational

#### Incident Response

- [ ] Security incident response plan documented
- [ ] Emergency secret rotation procedure ready
- [ ] Security team contact information updated
- [ ] Backup authentication methods available

### Regular Maintenance

#### Monthly Tasks

- [ ] Review security logs
- [ ] Check for security updates
- [ ] Validate monitoring alerts
- [ ] Review access permissions

#### Quarterly Tasks

- [ ] Security configuration audit
- [ ] Penetration testing
- [ ] Secret rotation (if not automated)
- [ ] Security training updates

#### Annual Tasks

- [ ] Comprehensive security review
- [ ] Disaster recovery testing
- [ ] Security policy updates
- [ ] Compliance audits

## Secret Rotation Procedures

### Planned Rotation

```bash
# 1. Generate new secret
NEW_SECRET=$(python3 scripts/generate-jwt-secrets.py --format urlsafe)

# 2. Update secret management system
aws secretsmanager update-secret \
    --secret-id photoapp/production/jwt-secret \
    --secret-string "$NEW_SECRET"

# 3. Deploy applications with new secret
# (Use blue-green deployment for zero downtime)

# 4. Verify all services are using new secret

# 5. Monitor for authentication issues
```

### Emergency Rotation

```bash
# Immediate rotation for security incidents
# 1. Generate emergency secret
EMERGENCY_SECRET=$(python3 scripts/generate-jwt-secrets.py --format urlsafe)

# 2. Update all environments immediately
# 3. Invalidate all existing tokens
# 4. Force user re-authentication
# 5. Investigate security incident
```

## Best Practices Summary

1. **Never hardcode secrets** - Always use environment variables or secret management systems
2. **Use unique secrets per environment** - Development, test, and production must have different secrets
3. **Implement proper secret rotation** - Regular rotation reduces impact of compromise
4. **Monitor security events** - Active monitoring enables quick incident response
5. **Follow principle of least privilege** - Limit access to secrets to necessary personnel only
6. **Maintain security documentation** - Keep procedures and contacts up to date
7. **Regular security audits** - Periodic reviews ensure ongoing security posture
8. **Incident response planning** - Prepare for security incidents before they occur

## Additional Resources

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [NIST Guidelines for Secret Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
- [HashiCorp Vault Best Practices](https://learn.hashicorp.com/tutorials/vault/production-hardening)

---

**Security is a shared responsibility. Everyone involved in the deployment and maintenance of this application should be familiar with these security practices.**