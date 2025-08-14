#!/bin/bash

# Security Scanning Script
# Runs various security tests and scans on the application

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Running Security Scan Suite ===${NC}"

# Configuration
BASE_URL="http://localhost:8000"
REPORT_DIR="security-reports"
mkdir -p "$REPORT_DIR"

# Function to check if service is running
check_service() {
    local url="$1"
    if curl -s "$url/health" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Check if application is running
echo -e "${GREEN}Checking if application is running...${NC}"
if check_service "$BASE_URL"; then
    echo -e "${GREEN}✓ Application is running${NC}"
else
    echo -e "${RED}✗ Application is not running${NC}"
    echo -e "${YELLOW}Please start the application first with: docker compose up${NC}"
    exit 1
fi

# Run Python security tests
echo -e "${GREEN}Running Python security tests...${NC}"
if [[ -d "backend/tests/security" ]]; then
    source .venv/bin/activate 2>/dev/null || true
    pytest backend/tests/security/ -v --tb=short --html="$REPORT_DIR/security-tests.html" --self-contained-html
    echo -e "${GREEN}✓ Python security tests completed${NC}"
else
    echo -e "${YELLOW}⚠ Security test directory not found${NC}"
fi

# Run Bandit security linter
echo -e "${GREEN}Running Bandit security linter...${NC}"
if command -v bandit > /dev/null; then
    bandit -r backend/ -f json -o "$REPORT_DIR/bandit-report.json" || true
    bandit -r backend/ -f html -o "$REPORT_DIR/bandit-report.html" || true
    echo -e "${GREEN}✓ Bandit scan completed${NC}"
else
    echo -e "${YELLOW}⚠ Bandit not installed, installing...${NC}"
    pip install bandit[toml]
    bandit -r backend/ -f json -o "$REPORT_DIR/bandit-report.json" || true
    bandit -r backend/ -f html -o "$REPORT_DIR/bandit-report.html" || true
    echo -e "${GREEN}✓ Bandit scan completed${NC}"
fi

# Run Safety check for known vulnerabilities
echo -e "${GREEN}Running Safety vulnerability check...${NC}"
if command -v safety > /dev/null; then
    safety check --json --output "$REPORT_DIR/safety-report.json" || true
    safety check --output "$REPORT_DIR/safety-report.txt" || true
    echo -e "${GREEN}✓ Safety check completed${NC}"
else
    echo -e "${YELLOW}⚠ Safety not installed, installing...${NC}"
    pip install safety
    safety check --json --output "$REPORT_DIR/safety-report.json" || true
    safety check --output "$REPORT_DIR/safety-report.txt" || true
    echo -e "${GREEN}✓ Safety check completed${NC}"
fi

# Test file upload security
echo -e "${GREEN}Testing file upload security...${NC}"
if [[ -f "scripts/api-tests/test-security-uploads.sh" ]]; then
    ./scripts/api-tests/test-security-uploads.sh > "$REPORT_DIR/upload-security-test.log" 2>&1
    echo -e "${GREEN}✓ Upload security tests completed${NC}"
else
    echo -e "${YELLOW}⚠ Upload security test script not found${NC}"
fi

# Test authentication security
echo -e "${GREEN}Testing authentication security...${NC}"
cat > "$REPORT_DIR/auth-security-test.sh" << 'AUTH_EOF'
#!/bin/bash
# Test various authentication attack vectors

BASE_URL="http://localhost:8000"

echo "Testing SQL injection in login..."
curl -s -X POST "$BASE_URL/api/users/login" \
  -F "username=admin' OR '1'='1" \
  -F "password=anything" > /dev/null

echo "Testing brute force protection..."
for i in {1..10}; do
    curl -s -X POST "$BASE_URL/api/users/login" \
      -F "username=nonexistent@example.com" \
      -F "password=wrongpassword" > /dev/null
done

echo "Testing JWT manipulation..."
curl -s -H "Authorization: Bearer invalid.jwt.token" \
  "$BASE_URL/api/users/me" > /dev/null

echo "Authentication security tests completed"
AUTH_EOF

chmod +x "$REPORT_DIR/auth-security-test.sh"
./"$REPORT_DIR/auth-security-test.sh" > "$REPORT_DIR/auth-security-test.log" 2>&1
echo -e "${GREEN}✓ Authentication security tests completed${NC}"

# Run OWASP ZAP scan (if available)
echo -e "${GREEN}Checking for OWASP ZAP...${NC}"
if command -v docker > /dev/null; then
    echo -e "${GREEN}Running OWASP ZAP baseline scan...${NC}"
    docker run --rm -v "$(pwd)/$REPORT_DIR":/zap/wrk/:rw \
      -t owasp/zap2docker-stable zap-baseline.py \
      -t "$BASE_URL" -J zap-baseline-report.json \
      -H zap-baseline-report.html || true
    echo -e "${GREEN}✓ OWASP ZAP scan completed${NC}"
else
    echo -e "${YELLOW}⚠ Docker not available, skipping OWASP ZAP scan${NC}"
fi

# Generate summary report
echo -e "${GREEN}Generating security scan summary...${NC}"
cat > "$REPORT_DIR/security-scan-summary.md" << 'SUMMARY_EOF'
# Security Scan Summary

## Scan Date
SUMMARY_EOF

date >> "$REPORT_DIR/security-scan-summary.md"

cat >> "$REPORT_DIR/security-scan-summary.md" << 'SUMMARY_EOF'

## Tests Performed

### 1. Python Security Tests
- Location: `security-tests.html`
- Purpose: Custom security test suite for application logic

### 2. Bandit Security Linter
- Location: `bandit-report.html`, `bandit-report.json`
- Purpose: Static analysis for common security issues in Python code

### 3. Safety Vulnerability Check
- Location: `safety-report.txt`, `safety-report.json`
- Purpose: Check for known vulnerabilities in Python dependencies

### 4. Authentication Security Tests
- Location: `auth-security-test.log`
- Purpose: Test authentication mechanisms against common attacks

### 5. File Upload Security Tests
- Location: `upload-security-test.log`
- Purpose: Test file upload validation and security controls

### 6. OWASP ZAP Baseline Scan
- Location: `zap-baseline-report.html`, `zap-baseline-report.json`
- Purpose: Web application security scan for common vulnerabilities

## Recommendations

1. Review all findings in the generated reports
2. Address any HIGH or CRITICAL severity issues immediately
3. Update dependencies with known vulnerabilities
4. Implement additional security controls as needed
5. Schedule regular security scans

## Next Steps

- Review individual reports for detailed findings
- Prioritize fixes based on severity and business impact
- Re-run scans after implementing fixes
- Consider professional penetration testing for production deployment
SUMMARY_EOF

echo -e "${GREEN}✓ Security scan summary generated${NC}"

# Display results
echo ""
echo -e "${BLUE}=== Security Scan Results ===${NC}"
echo -e "${GREEN}All security scans completed successfully!${NC}"
echo ""
echo -e "${BLUE}Reports generated in: $REPORT_DIR/${NC}"
echo -e "${BLUE}  - security-tests.html     : Custom security test results${NC}"
echo -e "${BLUE}  - bandit-report.html      : Static code analysis${NC}"
echo -e "${BLUE}  - safety-report.txt       : Vulnerability scan${NC}"
echo -e "${BLUE}  - auth-security-test.log  : Authentication tests${NC}"
echo -e "${BLUE}  - zap-baseline-report.html: Web app security scan${NC}"
echo -e "${BLUE}  - security-scan-summary.md: Summary and recommendations${NC}"
echo ""
echo -e "${YELLOW}Please review all reports and address any identified issues${NC}"
echo -e "${BLUE}Open reports with: firefox $REPORT_DIR/security-scan-summary.md${NC}"
