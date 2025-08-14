# Photo Sharing Application - Database Design & Security Architecture

## Overview
This document explains the database schema, security architecture, and data flow for the enterprise-grade photo sharing application with 18 tables implementing RBAC, audit logging, and comprehensive security controls.

## 🏗️ Database Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    PHOTO SHARING DATABASE                       │
├─────────────────────────────────────────────────────────────────┤
│  🔐 SECURITY LAYER    │  👥 USER LAYER     │  📸 CONTENT LAYER  │
│  ─────────────────────│  ──────────────────│  ─────────────────  │
│  • security_events   │  • users           │  • photos           │
│  • user_sessions      │  • email_verifications │ • albums       │
│  • blacklisted_tokens │  • storage_quotas  │  • upload_sessions  │
│  ─────────────────────│  ──────────────────│  ─────────────────  │
│  🛡️ RBAC LAYER       │  🤝 SOCIAL LAYER   │  🔗 RELATIONSHIP   │
│  ─────────────────────│  ──────────────────│  ─────────────────  │
│  • roles             │  • photo_shares    │  • photo_albums     │
│  • permissions       │  • album_shares    │  • role_permissions │
│  • user_roles        │  • photo_comments  │  • user_roles       │
│                      │  • photo_likes     │                    │
└─────────────────────────────────────────────────────────────────┘
```

## 📊 Core Database Tables (18 Tables)

### 🔐 Security & Authentication Layer (4 Tables)

#### 1. `users` - Core User Management
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    hashed_password VARCHAR NOT NULL,
    is_active BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until TIMESTAMP WITH TIME ZONE,
    first_name VARCHAR(50),
    last_name VARCHAR(50)
);
```
**Purpose**: Central user identity with built-in security controls
**Security Features**: Account lockout, failed login tracking, email verification

#### 2. `user_sessions` - Session Management & Tracking
```sql
CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    session_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token_jti VARCHAR(255) UNIQUE,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    device_fingerprint VARCHAR(255),
    location VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    login_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    logout_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_suspicious BOOLEAN DEFAULT false,
    login_method VARCHAR(50)
);
```
**Purpose**: Track all user sessions with security monitoring
**Security Features**: Device fingerprinting, suspicious activity detection, session expiration

#### 3. `security_events` - Comprehensive Audit Logging
```sql
CREATE TABLE security_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20), -- INFO, WARNING, CRITICAL
    user_id INTEGER REFERENCES users(id),
    user_email VARCHAR(255),
    session_id INTEGER REFERENCES user_sessions(id),
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    endpoint VARCHAR(255),
    http_method VARCHAR(10),
    message TEXT NOT NULL,
    details TEXT, -- JSON details
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);
```
**Purpose**: Immutable audit trail for all security events
**Events Tracked**: Login attempts, permission changes, suspicious activities, API access

#### 4. `blacklisted_tokens` - Token Security
```sql
CREATE TABLE blacklisted_tokens (
    id SERIAL PRIMARY KEY,
    jti VARCHAR(255) UNIQUE NOT NULL, -- JWT ID
    token_type VARCHAR(20) NOT NULL, -- access, refresh
    user_id INTEGER REFERENCES users(id),
    reason VARCHAR(100),
    blacklisted_by INTEGER REFERENCES users(id),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);
```
**Purpose**: Prevent token reuse after logout/security events
**Security Features**: Immediate token revocation, reason tracking

### 🛡️ RBAC (Role-Based Access Control) Layer (4 Tables)

#### 5. `roles` - Role Definition
```sql
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL, -- USER, ADMIN, SUPERADMIN
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    is_system_role BOOLEAN DEFAULT false, -- Prevent deletion
    parent_role_id INTEGER REFERENCES roles(id), -- Role hierarchy
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE,
    created_by INTEGER REFERENCES users(id)
);
```

#### 6. `permissions` - Granular Permissions
```sql
CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL, -- "photo:read", "admin:manage"
    resource VARCHAR(50) NOT NULL, -- "photo", "user", "admin"
    action VARCHAR(50) NOT NULL, -- "read", "write", "delete"
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE
);
```

#### 7. `role_permissions` - Role-Permission Mapping
```sql
CREATE TABLE role_permissions (
    role_id INTEGER REFERENCES roles(id),
    permission_id INTEGER REFERENCES permissions(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);
```

#### 8. `user_roles` - User-Role Assignment
```sql
CREATE TABLE user_roles (
    user_id INTEGER REFERENCES users(id),
    role_id INTEGER REFERENCES roles(id),
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    assigned_by_user_id INTEGER REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);
```

### 📸 Content Management Layer (6 Tables)

#### 9. `photos` - Core Photo Entity
```sql
CREATE TYPE photostatus AS ENUM ('UPLOADING', 'PROCESSING', 'READY', 'FAILED', 'DELETED');
CREATE TYPE sharetype AS ENUM ('PRIVATE', 'SHARED_WITH_USERS', 'SHARED_WITH_LINK', 'PUBLIC');

CREATE TABLE photos (
    id SERIAL PRIMARY KEY,
    uuid UUID UNIQUE DEFAULT gen_random_uuid(),
    owner_id INTEGER REFERENCES users(id),
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size INTEGER NOT NULL,
    file_hash VARCHAR(64) UNIQUE NOT NULL, -- SHA-256 for deduplication
    mime_type VARCHAR(100) NOT NULL,
    width INTEGER, height INTEGER,
    aspect_ratio DECIMAL(5,4),
    title VARCHAR(200), description TEXT,
    tags JSON, -- Searchable tags
    exif_data JSON, -- Camera metadata
    camera_make VARCHAR(100), camera_model VARCHAR(100),
    taken_at TIMESTAMP WITH TIME ZONE,
    location JSON, -- GPS coordinates
    status photostatus NOT NULL DEFAULT 'UPLOADING',
    processing_log TEXT,
    thumbnail_path VARCHAR(500),
    medium_path VARCHAR(500),
    large_path VARCHAR(500),
    share_type sharetype NOT NULL DEFAULT 'PRIVATE',
    share_token VARCHAR(64) UNIQUE,
    share_expires_at TIMESTAMP WITH TIME ZONE,
    content_warning BOOLEAN DEFAULT false,
    moderation_status VARCHAR(50),
    moderation_log JSON,
    view_count INTEGER DEFAULT 0,
    download_count INTEGER DEFAULT 0,
    last_viewed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE,
    deleted_at TIMESTAMP WITH TIME ZONE -- Soft delete
);
```

#### 10. `albums` - Photo Collections
```sql
CREATE TYPE albumtype AS ENUM ('PERSONAL', 'SHARED', 'PUBLIC');

CREATE TABLE albums (
    id SERIAL PRIMARY KEY,
    uuid UUID UNIQUE DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    description TEXT,
    owner_id INTEGER REFERENCES users(id),
    album_type albumtype NOT NULL DEFAULT 'PERSONAL',
    is_public BOOLEAN DEFAULT false,
    share_token VARCHAR(64) UNIQUE,
    cover_photo_id INTEGER REFERENCES photos(id),
    photo_count INTEGER DEFAULT 0,
    total_size INTEGER DEFAULT 0,
    sort_order VARCHAR(50) DEFAULT 'created_at_desc',
    tags JSON,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE,
    deleted_at TIMESTAMP WITH TIME ZONE
);
```

#### 11. `storage_quotas` - User Storage Management
```sql
CREATE TABLE storage_quotas (
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE REFERENCES users(id),
    quota_limit INTEGER NOT NULL, -- Bytes
    used_storage INTEGER DEFAULT 0,
    max_files INTEGER NOT NULL,
    file_count INTEGER DEFAULT 0,
    quota_type VARCHAR(50) DEFAULT 'standard', -- standard, premium
    last_calculated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE
);
```

#### 12. `upload_sessions` - Chunked Upload Management
```sql
CREATE TABLE upload_sessions (
    id SERIAL PRIMARY KEY,
    uuid UUID UNIQUE DEFAULT gen_random_uuid(),
    user_id INTEGER REFERENCES users(id),
    filename VARCHAR(255) NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    bytes_uploaded INTEGER DEFAULT 0,
    chunks_uploaded INTEGER DEFAULT 0,
    total_chunks INTEGER NOT NULL,
    status VARCHAR(50) DEFAULT 'active', -- active, completed, failed, expired
    temp_file_path VARCHAR(500),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    completed_at TIMESTAMP WITH TIME ZONE
);
```

#### 13. `photo_albums` - Many-to-Many Photo-Album Relationship
```sql
CREATE TABLE photo_albums (
    photo_id INTEGER REFERENCES photos(id),
    album_id INTEGER REFERENCES albums(id),
    added_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    added_by INTEGER REFERENCES users(id),
    sort_order INTEGER DEFAULT 0,
    PRIMARY KEY (photo_id, album_id)
);
```

#### 14. `email_verifications` - Email Verification Tokens
```sql
CREATE TABLE email_verifications (
    id SERIAL PRIMARY KEY,
    email VARCHAR NOT NULL,
    secret VARCHAR UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);
```

### 🤝 Social Features Layer (4 Tables)

#### 15. `photo_shares` - Individual Photo Sharing
```sql
CREATE TABLE photo_shares (
    id SERIAL PRIMARY KEY,
    photo_id INTEGER REFERENCES photos(id),
    shared_by_user_id INTEGER REFERENCES users(id),
    shared_with_user_id INTEGER REFERENCES users(id),
    share_token VARCHAR(64) UNIQUE,
    permissions JSON, -- read, download, comment
    expires_at TIMESTAMP WITH TIME ZONE,
    max_views INTEGER,
    current_views INTEGER DEFAULT 0,
    password_hash VARCHAR(255), -- Optional password protection
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    last_accessed_at TIMESTAMP WITH TIME ZONE
);
```

#### 16. `album_shares` - Album Sharing
```sql
CREATE TABLE album_shares (
    id SERIAL PRIMARY KEY,
    album_id INTEGER REFERENCES albums(id),
    shared_by_user_id INTEGER REFERENCES users(id),
    shared_with_user_id INTEGER REFERENCES users(id),
    share_token VARCHAR(64) UNIQUE,
    permissions JSON,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);
```

#### 17. `photo_comments` - Photo Comments
```sql
CREATE TABLE photo_comments (
    id SERIAL PRIMARY KEY,
    photo_id INTEGER REFERENCES photos(id),
    user_id INTEGER REFERENCES users(id),
    content TEXT NOT NULL,
    parent_comment_id INTEGER REFERENCES photo_comments(id), -- Threaded comments
    is_edited BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE,
    deleted_at TIMESTAMP WITH TIME ZONE
);
```

#### 18. `photo_likes` - Photo Likes/Reactions
```sql
CREATE TABLE photo_likes (
    id SERIAL PRIMARY KEY,
    photo_id INTEGER REFERENCES photos(id),
    user_id INTEGER REFERENCES users(id),
    like_type VARCHAR(20) DEFAULT 'like', -- like, love, etc.
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    UNIQUE(photo_id, user_id)
);
```

## 🔄 Data Flow Diagrams

### 1. User Registration & Authentication Flow
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User Signup   │ ──▶│ email_verifications │ ──▶│     users       │
│                 │    │                  │    │                 │
│ 1. Submit email │    │ 2. Generate      │    │ 4. Verify email │
│ 2. Password     │    │    secret token  │    │ 5. Activate     │
└─────────────────┘    │ 3. Send email    │    │    account      │
                       └──────────────────┘    └─────────────────┘
                                                         │
                                                         ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │ storage_quotas   │◄───│  user_roles     │
                       │                  │    │                 │
                       │ 6. Create quota  │    │ 7. Assign USER  │
                       │    for new user  │    │    role         │
                       └──────────────────┘    └─────────────────┘
```

### 2. Photo Upload & Processing Flow
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Client Upload  │ ──▶│ upload_sessions  │ ──▶│     photos      │
│                 │    │                  │    │                 │
│ 1. Start upload │    │ 2. Create session│    │ 6. Create photo │
│ 2. Send chunks  │    │ 3. Track progress│    │    record       │
└─────────────────┘    │ 4. Validate      │    │ 7. Status:      │
                       │ 5. Complete      │    │    PROCESSING   │
                       └──────────────────┘    └─────────────────┘
                                                         │
                                                         ▼
┌─────────────────┐    ┌──────────────────┐            ┌─────────────────┐
│ Image Processing│◄───│ Background Jobs  │            │ storage_quotas  │
│                 │    │                  │            │                 │
│ 8. Generate     │    │ • Resize         │            │ 9. Update user  │
│    thumbnails   │    │ • Extract EXIF   │            │    quota usage  │
│ 10. Set READY   │    │ • Scan malware   │            └─────────────────┘
└─────────────────┘    └──────────────────┘
```

### 3. RBAC Permission Check Flow
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   API Request   │ ──▶│   Middleware     │ ──▶│  Authorization  │
│                 │    │                  │    │     Check       │
│ 1. JWT Token    │    │ 2. Extract       │    │                 │
│ 2. Endpoint     │    │    user_id       │    │ 3. Query        │
└─────────────────┘    │ 3. Check session │    │    user_roles   │
                       └──────────────────┘    └─────────────────┘
                                                         │
                                                         ▼
┌─────────────────┐    ┌──────────────────┐            ┌─────────────────┐
│  Grant Access   │◄───│   Permission     │            │  role_permissions│
│                 │    │   Evaluation     │            │                 │
│ 6. Execute      │    │                  │            │ 4. Get role     │
│    request      │    │ 5. Allow/Deny    │            │    permissions  │
└─────────────────┘    │    decision      │            │ 5. Check match  │
                       └──────────────────┘            └─────────────────┘
```

### 4. Photo Sharing Security Flow
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Share Photo   │ ──▶│  photo_shares    │ ──▶│ Security Token  │
│                 │    │                  │    │                 │
│ 1. Owner shares │    │ 2. Create share  │    │ 3. Generate     │
│ 2. Set options  │    │    record        │    │    secure token │
└─────────────────┘    │ 3. Set expiry    │    │ 4. Optional     │
                       │ 4. Set max views │    │    password     │
                       └──────────────────┘    └─────────────────┘
                                                         │
                                                         ▼
┌─────────────────┐    ┌──────────────────┐            ┌─────────────────┐
│  Access Photo   │◄───│   Validation     │            │ security_events │
│                 │    │                  │            │                 │
│ 8. Serve photo  │    │ 5. Check token   │            │ 7. Log access   │
│ 9. Increment    │    │ 6. Check expiry  │            │    attempts     │
│    view count   │    │ 7. Check limits  │            └─────────────────┘
└─────────────────┘    └──────────────────┘
```

## 🔒 Security Controls & Data Protection

### 1. Authentication Security
- **Password Hashing**: bcrypt with salt
- **Account Lockout**: After failed attempts
- **Session Management**: JWT with refresh tokens
- **Token Blacklisting**: Immediate revocation capability

### 2. Authorization Security (RBAC)
- **Granular Permissions**: Resource:Action format
- **Role Hierarchy**: Inherited permissions
- **Resource Ownership**: User-specific access
- **Wildcard Permissions**: Flexible permission matching

### 3. Data Protection
- **Soft Deletes**: `deleted_at` timestamps
- **Audit Logging**: All security events tracked
- **Data Encryption**: At rest and in transit
- **File Deduplication**: SHA-256 hash matching

### 4. API Security
- **Rate Limiting**: Per user, per endpoint
- **Input Validation**: Schema-based validation
- **SQL Injection Prevention**: Parameterized queries
- **File Upload Security**: Type validation, malware scanning

## 📈 Usage Scenarios & Control Flow

### Scenario 1: New User Registration
1. **Input**: Email + Password
2. **Process**: 
   - Validate input → `users` table
   - Generate verification → `email_verifications`
   - Send email → External service
   - User clicks link → Verify token
   - Activate account → Update `users.is_verified`
   - Create quota → `storage_quotas`
   - Assign role → `user_roles` (USER role)
3. **Security**: Email verification prevents fake accounts

### Scenario 2: Photo Upload with Security
1. **Input**: File + Metadata
2. **Process**:
   - Check quota → `storage_quotas`
   - Create session → `upload_sessions`
   - Validate file → Security scanning
   - Process image → Generate thumbnails
   - Store metadata → `photos` table
   - Update quota → `storage_quotas.used_storage`
3. **Security**: Quota limits, file validation, malware scanning

### Scenario 3: Photo Sharing with Permissions
1. **Input**: Photo ID + Share settings
2. **Process**:
   - Verify ownership → `photos.owner_id`
   - Create share → `photo_shares`
   - Generate token → Secure random string
   - Set permissions → JSON permissions object
   - Log event → `security_events`
3. **Security**: Ownership verification, token expiry, access logging

### Scenario 4: Admin User Management
1. **Input**: User ID + New Role
2. **Process**:
   - Check admin permission → RBAC check
   - Verify target user → `users` table
   - Add role → `user_roles` table
   - Log change → `security_events`
3. **Security**: Admin-only operation, full audit trail

## 📊 Performance Optimizations

### Database Indexes
- **Primary Keys**: All tables have `id` indexes
- **Foreign Keys**: All relationships indexed
- **Search Fields**: Email, tokens, timestamps
- **Compound Indexes**: User-role combinations

### Query Optimization
- **Eager Loading**: Relationship pre-fetching
- **Connection Pooling**: Async connection management
- **Prepared Statements**: SQL injection prevention
- **Result Caching**: Session and permission caching

This architecture provides enterprise-grade security, comprehensive audit trails, and scalable performance for a photo sharing application handling thousands of users and millions of photos.