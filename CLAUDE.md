# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A containerized microservice-based Photo Sharing App built with FastAPI and PostgreSQL. The application provides user registration, email verification, JWT-based authentication, and photo metadata management.

## Architecture

- **Backend**: FastAPI application with SQLAlchemy ORM and AsyncPG for PostgreSQL
- **Database**: PostgreSQL 15 running in Docker container
- **Authentication**: JWT tokens with email verification workflow
- **Structure**: Clean architecture with separate layers:
  - `api/`: FastAPI route handlers
  - `dao/`: Data Access Objects for database operations
  - `models/`: SQLAlchemy models
  - `schemas/`: Pydantic schemas for request/response validation
  - `services/`: Business logic and utilities (auth, database connection)

## Development Commands

### Setup and Running
```bash
# Create virtual environment and activate
python3 -m venv .venv
source .venv/bin/activate

# Build and run with Docker Compose
docker compose down
docker compose up --build

# Initialize database (run after containers are up)
docker-compose exec backend python init_db.py
```

### Testing
```bash
# Run tests (pytest is included in requirements.txt)
docker-compose exec backend pytest

# Run specific test
docker-compose exec backend pytest path/to/test_file.py
```

### Database Operations
```bash
# Access PostgreSQL directly
docker-compose exec db psql -U ${POSTGRES_USER} -d ${POSTGRES_DB}

# Reset database
docker-compose down -v  # removes volumes
docker-compose up --build
docker-compose exec backend python init_db.py
```

## Key Environment Variables

Required in `.env` file:
- `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`: Database credentials
- `DB_HOST`, `DB_PORT`: Database connection (typically "db" and "5432" in Docker)
- JWT configuration for authentication

## Database Schema

- **users**: User accounts with email, hashed password, verification status
- **email_verifications**: Temporary verification tokens with expiration

## API Testing Examples

The README.md contains complete curl examples for:
- User registration: `POST /api/users/register`
- Email verification request: `POST /api/users/request-verification`
- Email verification: `GET /api/users/verify-email?secret=...`
- JWT login: `POST /api/users/login`
- Protected user info: `GET /api/users/me` (requires Bearer token)