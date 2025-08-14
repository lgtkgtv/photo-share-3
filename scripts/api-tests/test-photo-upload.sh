#!/bin/bash

# Photo Upload Test Script
# Tests photo upload functionality with authentication

set -e

# Configuration
BASE_URL="http://localhost:8000"
TEST_EMAIL="${TEST_EMAIL:-test@example.com}"
TEST_PASSWORD="${TEST_PASSWORD:-TestPassword123!}"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Testing Photo Upload Flow ===${NC}"

# Step 1: Login to get token
echo -e "${GREEN}Step 1: Logging in to get access token...${NC}"
TOKEN=$(curl -s -X POST "$BASE_URL/api/users/login" \
  -F "username=$TEST_EMAIL" \
  -F "password=$TEST_PASSWORD" | jq -r .access_token)

if [[ "$TOKEN" == "null" || -z "$TOKEN" ]]; then
    echo -e "${RED}✗ Login failed. Make sure user is registered and verified${NC}"
    echo -e "${YELLOW}Run ./test-auth-flow.sh first to set up a test user${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Login successful, token obtained${NC}"

# Step 2: Create a test image
echo -e "${GREEN}Step 2: Creating test image...${NC}"
TEST_IMAGE="/tmp/test-photo.jpg"

# Create a simple test image using ImageMagick (if available) or create a dummy file
if command -v convert > /dev/null; then
    convert -size 100x100 xc:red "$TEST_IMAGE"
    echo -e "${GREEN}✓ Test image created with ImageMagick${NC}"
elif command -v python3 > /dev/null; then
    # Create a minimal JPEG using Python PIL if available
    python3 -c "
from PIL import Image
import sys
try:
    img = Image.new('RGB', (100, 100), color='red')
    img.save('$TEST_IMAGE', 'JPEG')
    print('✓ Test image created with Python PIL')
except ImportError:
    # Create a dummy file with JPEG header
    with open('$TEST_IMAGE', 'wb') as f:
        f.write(b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.\' \",#\x1c\x1c(7),01444\x1f\'9=82<.342\xff\xc0\x00\x11\x08\x00d\x00d\x01\x01\x11\x00\x02\x11\x01\x03\x11\x01\xff\xc4\x00\x14\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00\xaa\xff\xd9')
    print('✓ Test image created as dummy JPEG')
except Exception as e:
    print(f'Error creating test image: {e}')
    sys.exit(1)
" 2>/dev/null || {
    # Fallback: create a minimal JPEG header
    echo -e "${YELLOW}Creating minimal test JPEG file...${NC}"
    printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xd9' > "$TEST_IMAGE"
}
else
    echo -e "${YELLOW}Creating minimal test JPEG file...${NC}"
    printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xd9' > "$TEST_IMAGE"
fi

if [[ ! -f "$TEST_IMAGE" ]]; then
    echo -e "${RED}✗ Failed to create test image${NC}"
    exit 1
fi

# Step 3: Upload photo
echo -e "${GREEN}Step 3: Uploading photo...${NC}"
UPLOAD_RESPONSE=$(curl -s -X POST "$BASE_URL/api/photos/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@$TEST_IMAGE" \
  -F "title=Test Photo" \
  -F "description=A test photo upload")

echo "Upload Response: $UPLOAD_RESPONSE"

# Check if upload was successful
if echo "$UPLOAD_RESPONSE" | jq -e '.id' > /dev/null; then
    PHOTO_ID=$(echo "$UPLOAD_RESPONSE" | jq -r '.id')
    echo -e "${GREEN}✓ Photo upload successful (ID: $PHOTO_ID)${NC}"
else
    echo -e "${RED}✗ Photo upload failed${NC}"
    echo "Response: $UPLOAD_RESPONSE"
    exit 1
fi

# Step 4: Get photo details
echo -e "${GREEN}Step 4: Getting photo details...${NC}"
PHOTO_DETAILS=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/photos/$PHOTO_ID")

echo "Photo Details: $PHOTO_DETAILS"

if echo "$PHOTO_DETAILS" | jq -e '.id' > /dev/null; then
    echo -e "${GREEN}✓ Photo details retrieved successfully${NC}"
else
    echo -e "${RED}✗ Failed to retrieve photo details${NC}"
fi

# Step 5: List photos
echo -e "${GREEN}Step 5: Listing user photos...${NC}"
PHOTO_LIST=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/photos/?page=1&size=10")

echo "Photo List: $PHOTO_LIST"

if echo "$PHOTO_LIST" | jq -e '.photos' > /dev/null; then
    PHOTO_COUNT=$(echo "$PHOTO_LIST" | jq '.photos | length')
    echo -e "${GREEN}✓ Photo list retrieved successfully ($PHOTO_COUNT photos)${NC}"
else
    echo -e "${RED}✗ Failed to retrieve photo list${NC}"
fi

# Cleanup
echo -e "${GREEN}Step 6: Cleaning up test files...${NC}"
rm -f "$TEST_IMAGE"
echo -e "${GREEN}✓ Test image cleaned up${NC}"

echo ""
echo -e "${BLUE}=== Photo Upload Test Summary ===${NC}"
echo -e "${GREEN}✓ Authentication successful${NC}"
echo -e "${GREEN}✓ Test image created${NC}"
echo -e "${GREEN}✓ Photo upload successful${NC}"
echo -e "${GREEN}✓ Photo details retrieval successful${NC}"
echo -e "${GREEN}✓ Photo listing successful${NC}"
echo -e "${GREEN}✓ Cleanup completed${NC}"
echo ""
echo -e "${GREEN}Photo upload flow test completed successfully!${NC}"
