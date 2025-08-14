#!/bin/bash

# Test Environment Setup Script
# Prepares the testing environment and installs testing tools

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Setting Up Test Environment ===${NC}"

# Check if virtual environment exists
if [[ ! -d ".venv" ]]; then
    echo -e "${YELLOW}Creating Python virtual environment...${NC}"
    python3 -m venv .venv
fi

# Activate virtual environment
echo -e "${GREEN}Activating virtual environment...${NC}"
source .venv/bin/activate

# Install testing dependencies
if [[ -f "backend/requirements.txt" ]]; then
    echo -e "${GREEN}Installing Python dependencies...${NC}"
    pip install -r backend/requirements.txt
fi

# Install additional testing tools
echo -e "${GREEN}Installing additional testing tools...${NC}"
pip install pytest-cov pytest-html pytest-xdist pytest-mock

# Create test directories if they don't exist
mkdir -p backend/tests/unit
mkdir -p backend/tests/integration
mkdir -p backend/tests/security
mkdir -p backend/tests/performance
mkdir -p test-reports

# Create pytest configuration if it doesn't exist
if [[ ! -f "pytest.ini" ]]; then
    echo -e "${GREEN}Creating pytest configuration...${NC}"
    cat > pytest.ini << 'PYTEST_EOF'
[tool:pytest]
testpaths = backend/tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = --verbose --tb=short --strict-markers
markers =
    unit: Unit tests
    integration: Integration tests
    security: Security tests
    performance: Performance tests
    slow: Slow running tests
PYTEST_EOF
fi

# Create test environment file
if [[ ! -f ".env.test.local" && -f ".env.test" ]]; then
    echo -e "${GREEN}Creating local test environment file...${NC}"
    cp .env.test .env.test.local
fi

echo -e "${GREEN}Test environment setup complete!${NC}"
echo -e "${BLUE}You can now run tests with:${NC}"
echo -e "${BLUE}  pytest backend/tests/ -v${NC}"
echo -e "${BLUE}  pytest backend/tests/ --cov=backend --cov-report=html${NC}"
echo -e "${BLUE}  pytest -m unit${NC}"
echo -e "${BLUE}  pytest -m integration${NC}"

deactivate
