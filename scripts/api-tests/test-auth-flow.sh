#!/bin/bash

# Authentication Flow Test Script
# Tests the complete user registration, verification, and login flow

set -e

# Configuration
BASE_URL="http://localhost:8000"
TEST_EMAIL="test-$(date +%s)@example.com"
TEST_PASSWORD="TestPassword123!"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Testing Authentication Flow ===${NC}"
echo -e "${BLUE}Test Email: $TEST_EMAIL${NC}"
echo ""

# Step 1: Register User
echo -e "${GREEN}Step 1: Registering user...${NC}"
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/users/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$TEST_EMAIL\", \"password\": \"$TEST_PASSWORD\"}")

echo "Registration Response: $REGISTER_RESPONSE"

if echo "$REGISTER_RESPONSE" | jq -e '.email' > /dev/null; then
    echo -e "${GREEN}✓ User registration successful${NC}"
else
    echo -e "${RED}✗ User registration failed${NC}"
    exit 1
fi

# Step 2: Request Email Verification
echo -e "${GREEN}Step 2: Requesting email verification...${NC}"
VERIFICATION_REQUEST=$(curl -s -X POST "$BASE_URL/api/users/request-verification" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$TEST_EMAIL\"}")

echo "Verification Request Response: $VERIFICATION_REQUEST"

if echo "$VERIFICATION_REQUEST" | jq -e '.message' > /dev/null; then
    echo -e "${GREEN}✓ Verification request successful${NC}"
else
    echo -e "${RED}✗ Verification request failed${NC}"
    exit 1
fi

# Step 3: Get verification token from logs (simulation)
echo -e "${YELLOW}Step 3: In a real scenario, check email for verification token${NC}"
echo -e "${YELLOW}For testing, check application logs for the verification secret${NC}"

# Step 4: Try login before verification (should fail)
echo -e "${GREEN}Step 4: Testing login before verification (should fail)...${NC}"
LOGIN_BEFORE_VERIFY=$(curl -s -X POST "$BASE_URL/api/users/login" \
  -F "username=$TEST_EMAIL" \
  -F "password=$TEST_PASSWORD")

echo "Login Before Verification Response: $LOGIN_BEFORE_VERIFY"

if echo "$LOGIN_BEFORE_VERIFY" | jq -e '.detail' | grep -q "not verified"; then
    echo -e "${GREEN}✓ Login properly blocked before verification${NC}"
else
    echo -e "${YELLOW}⚠ Expected verification check, but got different response${NC}"
fi

# Step 5: Simulate verification (manual step)
echo ""
echo -e "${BLUE}=== Manual Verification Required ===${NC}"
echo -e "${YELLOW}To complete the test:${NC}"
echo -e "${YELLOW}1. Check the application logs for verification secret${NC}"
echo -e "${YELLOW}2. Run: curl \"$BASE_URL/api/users/verify-email?secret=YOUR_SECRET\"${NC}"
echo -e "${YELLOW}3. Then run the login test below${NC}"
echo ""

# Provide login test command
echo -e "${BLUE}=== Login Test Command ===${NC}"
echo "After verification, test login with:"
echo ""
echo "TOKEN=\$(curl -s -X POST $BASE_URL/api/users/login \\"
echo "  -F \"username=$TEST_EMAIL\" \\"
echo "  -F \"password=$TEST_PASSWORD\" | jq -r .access_token)"
echo ""
echo "curl -H \"Authorization: Bearer \$TOKEN\" $BASE_URL/api/users/me"
echo ""

echo -e "${GREEN}Authentication flow test completed (manual verification required)${NC}"
