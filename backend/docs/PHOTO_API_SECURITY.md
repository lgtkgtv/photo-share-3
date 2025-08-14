# Photo API Security Documentation

## Overview

This document outlines the comprehensive security features implemented in the photo sharing API system. The implementation includes enterprise-grade security controls for photo upload, management, sharing, and access control.

## Security Architecture

### 1. Multi-Layer Security Model

```
┌─────────────────────────────────────────────────────────────┐
│                    API Layer Security                       │
├─────────────────────────────────────────────────────────────┤
│ • Rate Limiting (Photo-specific)                           │
│ • Input Validation & Sanitization                          │
│ • Authentication & Authorization                           │
├─────────────────────────────────────────────────────────────┤
│                 File Processing Security                    │
├─────────────────────────────────────────────────────────────┤
│ • MIME Type Validation                                      │
│ • Malware Scanning                                         │
│ • Image Processing Security                                │
├─────────────────────────────────────────────────────────────┤
│                  Storage Security                          │
├─────────────────────────────────────────────────────────────┤
│ • Secure File Paths                                        │
│ • Permission Controls                                      │
│ • Storage Quota Management                                 │
└─────────────────────────────────────────────────────────────┘
```

## API Endpoints

### Photo Upload Endpoints

#### POST /photos/upload
- **Purpose**: Upload single photo with comprehensive security validation
- **Security Features**:
  - Rate limiting: 10 uploads per 5 minutes (IP), 50 per hour (user)
  - File validation: MIME type, size limits, malware scanning
  - Storage quota enforcement
  - EXIF data sanitization
  - Comprehensive audit logging

**Security Headers**:
```
Content-Type: multipart/form-data
Authorization: Bearer <JWT_TOKEN>
```

**Rate Limits**:
- IP-based: 10 uploads per 5 minutes
- User-based: 50 uploads per hour
- File size: Max 50MB per file

#### POST /photos/upload/batch
- **Purpose**: Upload multiple photos in batch
- **Additional Security**:
  - Batch size limit: 10 files maximum
  - Enhanced rate limiting: 3 batches per 10 minutes (IP), 10 per hour (user)
  - Large batch restriction: 1 batch >5 files per 30 minutes

### Photo Management Endpoints

#### GET /photos/{photo_id}
- **Security Features**:
  - Ownership verification
  - Share permission checking
  - View count tracking
  - Access logging

#### PUT /photos/{photo_id}/metadata
- **Security Features**:
  - Input sanitization (XSS prevention)
  - Owner/admin permission verification
  - Change tracking and logging

#### DELETE /photos/{photo_id}
- **Security Features**:
  - Soft delete implementation
  - Owner/admin permission verification
  - Storage quota adjustment
  - Deletion logging

### Photo Sharing Endpoints

#### POST /photos/{photo_id}/share
- **Purpose**: Create secure photo shares with granular permissions
- **Security Features**:
  - Sharing rate limiting: 20 operations per 5 minutes
  - Token-based access control
  - Expiration date enforcement
  - View count limits
  - Permission granularity (view, download, share, comment)

**Share Types Supported**:
- User-specific shares (with user ID)
- Email-based shares (for unregistered users)
- Link-based shares (with secure tokens)

#### GET /photos/shared/{token}
- **Purpose**: Access photos via secure share tokens
- **Security Features**:
  - Token validation
  - Expiration checking
  - View limit enforcement
  - Anonymous access support
  - Access tracking

## Security Features

### 1. File Validation System

**Comprehensive Validation Pipeline**:
```python
# File validation layers
1. File existence and basic checks
2. MIME type validation using python-magic
3. File extension verification
4. Image content validation
5. Dimension and size limits
6. Malware pattern scanning
7. Hash generation for deduplication
```

**Supported File Types**:
- JPEG (.jpg, .jpeg)
- PNG (.png)
- WebP (.webp)
- GIF (.gif)

**Security Limits**:
- File size: 1KB - 50MB
- Image dimensions: 1px - 10,000px
- Maximum batch size: 10 files

### 2. Rate Limiting System

**Multi-Level Rate Limiting**:

| Operation Type | IP Limit | User Limit | Window |
|---------------|----------|------------|---------|
| Single Upload | 10 req | 50 req | 5min / 1hr |
| Batch Upload | 3 req | 10 req | 10min / 1hr |
| Large Batch (>5) | - | 1 req | 30min |
| Photo Sharing | - | 20 req | 5min |
| Quota Checks | - | 30 req | 1min |

### 3. Authorization System

**Role-Based Access Control (RBAC)**:
- **Owner**: Full access to own photos
- **Shared User**: Access based on share permissions
- **Admin**: Override access to all photos
- **Public Access**: Limited to public photos only

**Permission Types**:
- `photo:create` - Upload photos
- `photo:read` - View photos
- `photo:update` - Edit photo metadata
- `photo:delete` - Delete photos
- `photo:share` - Create photo shares

### 4. Storage Quota Management

**Quota Features**:
- Per-user storage limits
- File count limits
- Real-time quota checking
- Automatic quota updates
- Rate-limited quota checks

**Default Quotas**:
- Free tier: 1GB storage, 10,000 files
- Premium tier: Configurable limits

### 5. Image Processing Security

**Advanced Processing Pipeline**:
- Auto-orientation based on EXIF
- EXIF data sanitization (removes GPS/sensitive data)
- Multiple thumbnail generation
- WebP format support
- Progressive JPEG generation
- Smart cropping algorithms
- Unsharp mask filtering

**Security Measures**:
- Decompression bomb protection
- Memory usage limits
- Processing timeout limits
- Temporary file cleanup

### 6. Secure File Storage

**Storage Security Features**:
- Secure file path generation (UUID-based)
- Directory structure isolation by user/date
- File permission controls (640)
- Duplicate file detection
- Atomic file operations
- Secure cleanup procedures

**Storage Structure**:
```
uploads/
├── photos/
│   └── {user_id}/
│       └── {year}/
│           └── {month}/
│               └── {uuid}.{ext}
├── thumbnails/
│   └── {user_id}/
│       └── {year}/
│           └── {month}/
│               ├── {uuid}_small.jpg
│               ├── {uuid}_medium.jpg
│               └── {uuid}_large.jpg
└── temp/
    └── upload_*.tmp
```

## Security Logging and Monitoring

### Security Events Tracked

**Upload Events**:
- `photo_upload_success` - Successful photo upload
- `photo_upload_validation_failed` - File validation failure
- `upload_quota_exceeded` - Storage quota exceeded
- `upload_rate_limited` - Rate limit exceeded
- `malicious_file_upload_attempt` - Malware detected

**Access Events**:
- `photo_accessed` - Photo viewed
- `unauthorized_photo_access_attempt` - Access denied
- `photo_metadata_updated` - Metadata changes
- `photo_deleted` - Photo deletion

**Sharing Events**:
- `photo_share_created` - Share created
- `photo_share_revoked` - Share revoked
- `shared_photo_accessed` - Share link accessed
- `photo_sharing_rate_limited` - Sharing rate limited

### Log Data Structure

```json
{
  "event_type": "photo_upload_success",
  "timestamp": "2024-01-15T10:30:00Z",
  "user_id": 123,
  "user_email": "user@example.com",
  "client_ip": "192.168.1.100",
  "details": {
    "photo_id": 456,
    "photo_uuid": "abc-123-def",
    "file_size": 2048000,
    "mime_type": "image/jpeg",
    "processing_time_ms": 150
  },
  "severity": "INFO"
}
```

## Testing and Validation

### Security Test Categories

1. **File Validation Tests**
   - Valid file uploads
   - Malicious file rejection
   - Size limit enforcement
   - Unsupported type rejection

2. **Rate Limiting Tests**
   - Upload rate limits
   - Batch upload limits
   - Sharing rate limits
   - Concurrent request handling

3. **Authorization Tests**
   - Ownership verification
   - Share permission checking
   - Admin override functionality
   - Public access controls

4. **Input Sanitization Tests**
   - XSS prevention in metadata
   - Filename sanitization
   - SQL injection prevention

5. **Integration Tests**
   - Complete upload workflow
   - Sharing workflow security
   - Quota management workflow

### Performance Benchmarks

- File validation: <1 second for files up to 10MB
- Thumbnail generation: <2 seconds for standard sizes
- Rate limit checks: <10ms per request
- Authorization checks: <50ms per request

## Configuration and Deployment

### Environment Variables

```bash
# Storage Configuration
UPLOAD_STORAGE_PATH=/app/uploads
MEDIA_URL=/media
MAX_FILE_SIZE=52428800  # 50MB

# Security Settings
RATE_LIMIT_ENABLED=true
MALWARE_SCANNING_ENABLED=true
ADVANCED_PROCESSING_ENABLED=true

# Quota Settings
DEFAULT_STORAGE_QUOTA=1073741824  # 1GB
DEFAULT_FILE_LIMIT=10000
```

### Security Recommendations

1. **Production Deployment**:
   - Use Redis for distributed rate limiting
   - Implement proper malware scanning service
   - Configure CDN for media delivery
   - Set up log aggregation and monitoring

2. **Monitoring Setup**:
   - Set alerts for rate limit violations
   - Monitor failed validation attempts
   - Track quota usage trends
   - Alert on unauthorized access attempts

3. **Regular Maintenance**:
   - Clean up expired share tokens
   - Archive old security logs
   - Review and update file type allowlists
   - Update malware scanning patterns

## API Response Examples

### Successful Upload Response
```json
{
  "id": 123,
  "uuid": "abc-123-def-456",
  "filename": "photo_abc123.jpg",
  "status": "ready",
  "message": "Photo uploaded successfully"
}
```

### Rate Limit Exceeded Response
```json
{
  "detail": "Upload rate limit exceeded. Try again in 60 seconds.",
  "headers": {
    "Retry-After": "60"
  }
}
```

### Validation Error Response
```json
{
  "detail": "File validation failed: Unsupported file type: application/octet-stream"
}
```

### Share Creation Response
```json
{
  "id": 789,
  "photo_id": 123,
  "share_token": "secure_token_here",
  "can_view": true,
  "can_download": false,
  "can_share": false,
  "can_comment": true,
  "expires_at": "2024-02-15T10:30:00Z",
  "max_views": 100,
  "current_views": 0,
  "created_at": "2024-01-15T10:30:00Z"
}
```

## Conclusion

This photo API implementation provides enterprise-grade security suitable for handling millions of users and photos. The multi-layered security approach ensures protection against common vulnerabilities while maintaining high performance and user experience.

The system is designed to be scalable, maintainable, and extensible, with comprehensive logging and monitoring capabilities for production deployments.