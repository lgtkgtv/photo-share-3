#!/bin/bash

# Production Simulation Script
# This script simulates a production environment locally for testing

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Starting Production Simulation ===${NC}"

# Check if we're in the right directory
if [[ ! -f "docker-compose.prod.yml" ]]; then
    echo -e "${RED}Error: docker-compose.prod.yml not found. Are you in the project root?${NC}"
    exit 1
fi

# Check if production environment template exists
if [[ ! -f ".env.production" ]]; then
    echo -e "${RED}Error: .env.production template not found${NC}"
    exit 1
fi

# Create local production environment file
echo -e "${GREEN}Creating local production environment configuration...${NC}"
cp .env.production .env.prod

# Replace managed secrets with local test values
echo -e "${YELLOW}Replacing managed secrets with local test values...${NC}"
sed -i 's/{{MANAGED_SECRET_DB_PASSWORD}}/local_test_db_password/g' .env.prod
sed -i 's/{{MANAGED_SECRET_JWT_KEY}}/local_test_jwt_key_at_least_32_characters_long_for_testing_only/g' .env.prod
sed -i 's/{{MANAGED_SECRET_REDIS_PASSWORD}}/local_test_redis_password/g' .env.prod
sed -i 's/{{MANAGED_SECRET_EMAIL_USERNAME}}/test_email_user/g' .env.prod
sed -i 's/{{MANAGED_SECRET_EMAIL_PASSWORD}}/test_email_password/g' .env.prod
sed -i 's/{{MANAGED_SECRET_LOG_API_KEY}}/test_log_api_key/g' .env.prod
sed -i 's/{{MANAGED_SECRET_NEWRELIC_KEY}}/test_newrelic_key/g' .env.prod
sed -i 's/{{MANAGED_SECRET_DATADOG_KEY}}/test_datadog_key/g' .env.prod

# Update database host for local testing
sed -i 's/your-production-db-host.amazonaws.com/db/g' .env.prod

echo -e "${YELLOW}WARNING: This is a LOCAL SIMULATION of production environment${NC}"
echo -e "${YELLOW}Do NOT use this configuration for actual production deployment${NC}"
echo ""

# Stop any running containers
echo -e "${GREEN}Stopping any existing containers...${NC}"
docker compose -f docker-compose.prod.yml down

# Start production simulation
echo -e "${GREEN}Building and starting production simulation...${NC}"
docker compose -f docker-compose.prod.yml up --build

echo -e "${GREEN}Production simulation started!${NC}"
echo -e "${BLUE}Application: http://localhost (port 80)${NC}"
echo -e "${BLUE}HTTPS: https://localhost (port 443 - self-signed cert)${NC}"
echo -e "${BLUE}Direct Backend: http://localhost:8000${NC}"
echo ""
echo -e "${YELLOW}Remember: This is a simulation for testing only${NC}"
echo -e "${YELLOW}For real production, use proper secret management${NC}"