# Enterprise Photo Sharing Platform

## Overview

An enterprise-grade photo sharing platform built with FastAPI, PostgreSQL, and Docker. Features comprehensive security controls, multi-cloud storage support, enterprise malware scanning, and role-based access control. Designed for scalable deployment across development, testing, and production environments.

**Key Technologies**: FastAPI, PostgreSQL, Docker, Redis, JWT Authentication, Multi-Cloud Storage, Enterprise Security

## Features

### 🔐 **Authentication & Security**
- User registration with email verification workflow
- JWT-based authentication with configurable expiration
- Role-Based Access Control (RBAC) system
- Enterprise-grade password policies
- Rate limiting and brute force protection
- Account lockout mechanisms

### 📸 **Photo Management**
- Secure photo upload with comprehensive validation
- Multi-format support (JPEG, PNG, WebP, GIF)
- Automatic thumbnail generation
- EXIF metadata sanitization (privacy protection)
- File deduplication using SHA-256 hashing
- Storage quota management per user

### 🛡️ **Enterprise Security**
- **Multi-Engine Malware Scanning**: ClamAV, VirusTotal API integration
- **Content Moderation**: AI-based NSFW and harmful content detection
- **Steganography Detection**: Hidden content analysis
- **Advanced Threat Detection**: Pattern matching, entropy analysis
- **File Encryption**: AES-256 encryption at rest
- **Security Event Logging**: Comprehensive audit trails

### ☁️ **Cloud Storage**
- **Multi-Provider Support**: AWS S3, Azure Blob Storage, Google Cloud Storage
- **Encrypted Storage**: Client-side encryption before upload
- **Storage Tiers**: Hot, warm, cold, and archive storage options
- **Secure Key Management**: PBKDF2-HMAC-SHA256 key derivation
- **Local Storage**: Development and testing support

### 🏗️ **Album & Sharing**
- Album creation and organization
- Fine-grained sharing permissions (view, download, share, comment)
- Public, private, and link-based sharing
- Time-limited shares with view limits
- Social features (comments, likes, reactions)

### 📊 **Monitoring & Compliance**
- Comprehensive security event logging
- GDPR compliance features (data export, deletion)
- Performance metrics and health checks
- Rate limiting and abuse prevention
- Storage usage analytics

### 🐳 **Infrastructure**
- Docker containerization with multi-environment support
- PostgreSQL with advanced data models
- Redis caching and session management
- Nginx reverse proxy (production)
- Health checks and auto-restart policies

## Environment Setup on Ubuntu 24.04

### Prerequisites Installation

Use our smart installation script that checks for existing tools:

```bash
# Download and run the setup script
curl -fsSL https://raw.githubusercontent.com/your-repo/setup.sh | bash

# Or run manually:
chmod +x scripts/setup-ubuntu.sh
./scripts/setup-ubuntu.sh
```

### Manual Prerequisites Installation

```bash
# System update
sudo apt update && sudo apt upgrade -y

# Essential development tools
sudo apt install -y git curl wget vim build-essential

# Docker (latest version)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker

# Python development
sudo apt install -y python3 python3-venv python3-pip python3-dev

# Database and utilities
sudo apt install -y postgresql-client redis-tools jq httpie

# Optional: Development tools
sudo snap install code --classic  # VS Code
sudo apt install -y pgadmin4      # PostgreSQL admin
```

## Environment Configuration

### Development Environment

```bash
# Clone repository
git clone <repository-url> photo-share-3
cd photo-share-3

# Setup Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Configure development environment
cp .env.development .env

# Install Python dependencies
pip install -r backend/requirements.txt

# Start development environment
docker compose up --build

# Initialize database (in another terminal)
docker-compose exec backend python init_db.py
```

**Development Features**:
- Hot reload enabled
- Debug mode active
- API documentation available at `http://localhost:8000/docs`
- Relaxed security settings for development ease
- Local file storage

### Test Environment

```bash
# Configure test environment
cp .env.test .env.test.local

# Run isolated test environment
docker compose -f docker-compose.test.yml up --build

# Run tests manually
docker-compose exec test-backend pytest -v

# Run specific test categories
docker-compose exec test-backend pytest tests/test_auth.py -v
docker-compose exec test-backend pytest tests/test_photos.py -v
```

**Test Features**:
- Isolated test database and services
- Separate ports (5433, 8001, 6380) to avoid conflicts
- Automated test execution
- In-memory SQLite option for fast tests
- CI/CD integration ready

### Production Environment

```bash
# Configure production environment
cp .env.production .env.prod

# Edit secrets (use proper secret management in real production)
nano .env.prod

# Deploy production environment
docker compose -f docker-compose.prod.yml up --build

# Initialize production database
docker-compose -f docker-compose.prod.yml exec backend python init_db.py
```

**Production Features**:
- Nginx reverse proxy with SSL
- Redis caching and session management
- Strict security policies
- Resource limits and health checks
- Log aggregation ready
- Monitoring and alerting integration

## Building and Testing

### Development Build

```bash
# Start development environment
./scripts/dev.sh

# Or manually:
cp .env.development .env
docker compose down
docker compose up --build
```

### Running Tests

```bash
# Full test suite
./scripts/test.sh

# Or manually:
docker compose -f docker-compose.test.yml up --build

# Individual test categories
pytest backend/tests/test_auth.py -v        # Authentication tests
pytest backend/tests/test_photos.py -v     # Photo management tests
pytest backend/tests/test_security.py -v   # Security tests
pytest backend/tests/test_api.py -v        # API integration tests
```

### Production Build

```bash
# Simulate production locally
./scripts/prod-sim.sh

# Or manually:
cp .env.production .env.prod
# Edit .env.prod with appropriate secrets
docker compose -f docker-compose.prod.yml up --build
```

### Performance Testing

```bash
# Load testing with Apache Bench
ab -n 1000 -c 10 http://localhost:8000/health

# Security testing
docker run --rm -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-api-scan.py \
  -t http://host.docker.internal:8000/docs -f openapi
```

## Application User Guide

### Getting Started

1. **Account Registration**
   ```bash
   curl -X POST http://localhost:8000/api/users/register \
     -H "Content-Type: application/json" \
     -d '{"email": "user@example.com", "password": "SecurePass123!"}'
   ```

2. **Email Verification**
   ```bash
   # Request verification
   curl -X POST http://localhost:8000/api/users/request-verification \
     -H "Content-Type: application/json" \
     -d '{"email": "user@example.com"}'
   
   # Verify with token (check application logs for token)
   curl "http://localhost:8000/api/users/verify-email?secret=YOUR_TOKEN"
   ```

3. **Login and Get Access Token**
   ```bash
   TOKEN=$(curl -s -X POST http://localhost:8000/api/users/login \
     -F "username=user@example.com" \
     -F "password=SecurePass123!" | jq -r .access_token)
   ```

### Photo Management

1. **Upload Photo**
   ```bash
   curl -X POST http://localhost:8000/api/photos/upload \
     -H "Authorization: Bearer $TOKEN" \
     -F "file=@/path/to/photo.jpg" \
     -F "title=My Photo" \
     -F "description=A beautiful sunset"
   ```

2. **List Photos**
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:8000/api/photos/?page=1&size=10"
   ```

3. **Get Photo Details**
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:8000/api/photos/1"
   ```

4. **Share Photo**
   ```bash
   curl -X POST http://localhost:8000/api/photos/1/share \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"share_type": "shared_with_link", "expires_in_days": 7}'
   ```

### Album Management

1. **Create Album**
   ```bash
   curl -X POST http://localhost:8000/api/albums \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name": "Vacation Photos", "description": "Summer 2024 vacation"}'
   ```

2. **Add Photo to Album**
   ```bash
   curl -X POST http://localhost:8000/api/albums/1/photos \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"photo_ids": [1, 2, 3]}'
   ```

### Account Management

1. **Get User Profile**
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:8000/api/users/me"
   ```

2. **Update Profile**
   ```bash
   curl -X PUT http://localhost:8000/api/users/me \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"email": "newemail@example.com"}'
   ```

3. **Change Password**
   ```bash
   curl -X POST http://localhost:8000/api/users/change-password \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"current_password": "OldPass123!", "new_password": "NewPass456!"}'
   ```

## Application Tester Guide

### Testing Framework

The application uses pytest with comprehensive test coverage:

- **Unit Tests**: Individual component testing
- **Integration Tests**: API endpoint testing
- **Security Tests**: Vulnerability and penetration testing
- **Performance Tests**: Load and stress testing

### Running Tests

```bash
# Setup test environment
./scripts/setup-test-env.sh

# Run all tests
pytest backend/tests/ -v --tb=short

# Run specific test categories
pytest backend/tests/test_auth.py::test_user_registration -v
pytest backend/tests/test_photos.py::test_photo_upload -v
pytest backend/tests/test_security.py::test_malware_scanning -v

# Run tests with coverage
pytest backend/tests/ --cov=backend --cov-report=html

# Performance testing
pytest backend/tests/test_performance.py -v
```

### Test Data Management

```bash
# Create test data
python backend/scripts/create_test_data.py

# Reset test database
docker-compose -f docker-compose.test.yml exec test-backend python scripts/reset_test_db.py

# Load test fixtures
pytest backend/tests/ --fixtures=auth,photos,albums
```

### Security Testing

```bash
# Run security test suite
pytest backend/tests/test_security.py -v

# Test malware scanning
python backend/scripts/test_malware_scanner.py

# Test file upload security
python backend/scripts/test_upload_security.py

# OWASP ZAP security scan
./scripts/run-security-scan.sh
```

### API Testing with Different Tools

1. **HTTPie Examples**
   ```bash
   # Register user
   http POST localhost:8000/api/users/register email=test@example.com password=Test123!
   
   # Login
   http --form POST localhost:8000/api/users/login username=test@example.com password=Test123!
   
   # Upload photo
   http --form POST localhost:8000/api/photos/upload Authorization:"Bearer $TOKEN" file@photo.jpg
   ```

2. **Postman Collection**
   - Import `postman/PhotoShare.postman_collection.json`
   - Set environment variables for different environments
   - Run collection tests

3. **curl Scripts**
   - Use scripts in `scripts/api-tests/` directory
   - `./scripts/api-tests/test-auth-flow.sh`
   - `./scripts/api-tests/test-photo-upload.sh`

### Smart Setup Script

Create the setup script for Ubuntu 24.04:

```bash
# Create setup script
./scripts/create-setup-script.sh
```

This creates `scripts/setup-ubuntu.sh` that:
- Checks for existing installations
- Installs only missing dependencies
- Configures development environment
- Sets up testing tools
- Validates installation

### Testing Checklist

- [ ] Authentication flow (register, verify, login)
- [ ] Photo upload and validation
- [ ] Malware scanning functionality
- [ ] File encryption and cloud storage
- [ ] Album creation and management
- [ ] Sharing and permissions
- [ ] Rate limiting and security controls
- [ ] Performance under load
- [ ] Security vulnerability assessment
- [ ] Cross-environment compatibility

## API Documentation

- **Development**: http://localhost:8000/docs (Swagger UI)
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

## Troubleshooting

### Common Issues

1. **Docker Permission Issues**
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker
   ```

2. **Port Conflicts**
   ```bash
   # Check running services
   sudo netstat -tulpn | grep :8000
   
   # Stop conflicting services
   docker compose down
   ```

3. **Database Connection Issues**
   ```bash
   # Check database status
   docker-compose exec db pg_isready -U photo_user -d photoapp
   
   # Reset database
   docker-compose down -v
   docker-compose up --build
   ```

4. **Test Failures**
   ```bash
   # Clean test environment
   docker-compose -f docker-compose.test.yml down -v
   docker-compose -f docker-compose.test.yml up --build
   ```

### Environment-Specific Issues

- **Development**: Check `.env` file configuration
- **Testing**: Ensure test database is isolated
- **Production**: Verify all secrets are properly configured

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `pytest backend/tests/ -v`
4. Run security scans: `./scripts/run-security-scan.sh`
5. Submit pull request

## Security

- Report security vulnerabilities to: security@yourcompany.com
- Security documentation: `backend/docs/MEDIA_SECURITY_THREAT_MODEL.md`
- Regular security audits and penetration testing recommended

## License

[Specify your license here]

## Support

- Documentation: See `claude_chat_log.md` for detailed technical information
- Issues: Create GitHub issues for bugs and feature requests
- Enterprise Support: Contact support@yourcompany.com