#!/bin/bash

# Development Environment Startup Script
# This script configures and starts the development environment

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Starting Development Environment ===${NC}"

# Check if we're in the right directory
if [[ ! -f "docker-compose.yml" ]]; then
    echo -e "${YELLOW}Warning: docker-compose.yml not found. Are you in the project root?${NC}"
    exit 1
fi

# Copy development environment file
if [[ -f ".env.development" ]]; then
    echo -e "${GREEN}Configuring development environment...${NC}"
    cp .env.development .env
else
    echo -e "${YELLOW}Warning: .env.development not found${NC}"
fi

# Stop any running containers
echo -e "${GREEN}Stopping any existing containers...${NC}"
docker compose down

# Start development environment
echo -e "${GREEN}Building and starting development environment...${NC}"
docker compose up --build

echo -e "${GREEN}Development environment started!${NC}"
echo -e "${BLUE}API Documentation: http://localhost:8000/docs${NC}"
echo -e "${BLUE}API Alternative Docs: http://localhost:8000/redoc${NC}"
echo -e "${BLUE}Application: http://localhost:8000${NC}"