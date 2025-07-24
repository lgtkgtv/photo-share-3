# Photo Sharing App

## Overview

A containerized microservice-based Photo Sharing App built with FastAPI and PostgreSQL.

## Features

- User registration with email verification
- JWT-based login
- Photo metadata upload
- Secure Docker Compose environment

## Setup (Ubuntu 24.04)

### 1. Install system packages

```bash
sudo apt update
sudo apt install -y python3 python3-venv docker docker-compose
```

### 2. Create and activate virtual environment

```bash
cd photo_share_app
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Start services

```bash
docker-compose up --build
```

### 4. Run tests

```bash
docker-compose exec backend pytest
```

## Sample test users

- Email: `user1@example.com` / Password: `testpass123`
- Email: `user2@example.com` / Password: `testpass456`

Sample images are in `sample_data/images/`.

