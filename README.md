# Photo Sharing App - added PostgreSQL for manaing user auth/login

## Overview

A containerized microservice-based Photo Sharing App built with FastAPI and PostgreSQL.

## Features

- User registration with email verification
- JWT-based login
- Photo metadata upload
- Secure Docker Compose environment

## Setup (Ubuntu 24.04)

```bash
sudo apt update
sudo apt install -y python3 python3-venv docker docker-compose
```


## 1. build and run the App
```
python3 -m venv .venv
source .venv/bin/activate

docker compose down
docker ps -a
docker compose up --build
```

## 2. Run the `DB initialization script` manually to initialize DB

```
docker-compose exec backend python init_db.py

    Expected output:

    CREATE TABLE users (
	    id              SERIAL NOT NULL, 
	    email           VARCHAR NOT NULL, 
	    hashed_password VARCHAR NOT NULL, 
	    is_active       BOOLEAN, 
	    is_verified     BOOLEAN, 
	    created_at      TIMESTAMP WITH TIME ZONE DEFAULT now(), 
	    PRIMARY KEY     (id)
    )

    CREATE TABLE email_verifications (
	    id          SERIAL NOT NULL, 
	    email       VARCHAR NOT NULL, 
	    secret      VARCHAR NOT NULL, 
	    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL, 
	    created_at  TIMESTAMP WITH TIME ZONE DEFAULT now(), 
	    PRIMARY KEY (id), 
	    UNIQUE      (secret)
    )

```

## 3. Register user
```
curl -X POST http://localhost:8000/api/users/register      -H "Content-Type: application/json"      -d '{"email": "user1@example.com", "password": "testpass123"}'

        Expected output:
        {"id":1,"email":"user1@example.com","is_active":true,"is_verified":false}
```

## 4. Request verification
```
curl -X POST http://localhost:8000/api/users/request-verification      -H "Content-Type: application/json"      -d '{"email": "user1@example.com"}'

        Expected output:
        {"message":"Verification email sent (simulated)"}
```

## 5. Verify in the browser
```
curl http://localhost:8000/api/users/verify-email?secret=BOAPBq_hhqa0cWRuFZ9xjmHw6WIne0wu0VZjRS1UILQ

        Expected output:
        {"message":"Email user1@example.com successfully verified."}

```

## 6. Testing `JWT login` and `Secure /me endpoint`

```

TOKEN=$(curl -s -X POST http://localhost:8000/api/users/login \
  -F "username=user1@example.com" \
  -F "password=testpass123" | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN"     http://localhost:8000/api/users/me

    Expected output:
    {"id":1,"email":"user1@example.com","is_active":true,"is_verified":true}

``` 

