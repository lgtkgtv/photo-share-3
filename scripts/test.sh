#!/bin/bash

# Test Environment Startup Script
# This script configures and starts the test environment with isolated services

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Starting Test Environment ===${NC}"

# Check if we're in the right directory
if [[ ! -f "docker-compose.test.yml" ]]; then
    echo -e "${RED}Error: docker-compose.test.yml not found. Are you in the project root?${NC}"
    exit 1
fi

# Copy test environment file if it exists
if [[ -f ".env.test" ]]; then
    echo -e "${GREEN}Configuring test environment...${NC}"
    cp .env.test .env.test.local
else
    echo -e "${YELLOW}Warning: .env.test not found, using defaults${NC}"
fi

# Stop any running test containers
echo -e "${GREEN}Stopping any existing test containers...${NC}"
docker compose -f docker-compose.test.yml down

# Clean up test volumes for fresh start
echo -e "${GREEN}Cleaning test volumes for fresh start...${NC}"
docker compose -f docker-compose.test.yml down -v

# Start test environment
echo -e "${GREEN}Building and starting test environment...${NC}"
docker compose -f docker-compose.test.yml up --build

echo -e "${GREEN}Test environment completed!${NC}"
echo -e "${BLUE}Test results should be displayed above${NC}"
echo -e "${BLUE}Test services run on different ports to avoid conflicts:${NC}"
echo -e "${BLUE}  - Test Database: port 5433${NC}"
echo -e "${BLUE}  - Test Backend: port 8001${NC}"
echo -e "${BLUE}  - Test Redis: port 6380${NC}"