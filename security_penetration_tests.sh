#!/bin/bash

# ====================================================================
# Security Penetration Test Suite for Photo Sharing App
# Tests NGINX production security features vs development mode
# ====================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Test configuration
PROD_URL="http://localhost"      # Nginx proxy (production)
DEV_URL="http://localhost:8000"  # Direct backend (development)
TEST_RESULTS=()

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE} 🔍 Security Penetration Test Suite${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to run test and record results
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"
    
    echo -e "${YELLOW}Testing: ${test_name}${NC}"
    
    if eval "$test_command"; then
        if [ "$expected_result" = "pass" ]; then
            echo -e "${GREEN}✅ PASS: ${test_name}${NC}"
            TEST_RESULTS+=("PASS: $test_name")
        else
            echo -e "${RED}❌ FAIL: ${test_name} (security control bypassed)${NC}"
            TEST_RESULTS+=("FAIL: $test_name")
        fi
    else
        if [ "$expected_result" = "fail" ]; then
            echo -e "${GREEN}✅ PASS: ${test_name} (properly blocked)${NC}"
            TEST_RESULTS+=("PASS: $test_name")
        else
            echo -e "${RED}❌ FAIL: ${test_name} (unexpected failure)${NC}"
            TEST_RESULTS+=("FAIL: $test_name")
        fi
    fi
    echo ""
}

# ====================================================================
# TEST 1: Security Headers Presence
# ====================================================================
echo -e "${PURPLE}1. SECURITY HEADERS PENETRATION TESTS${NC}"
echo "=================================================="

# Test 1.1: X-Frame-Options Protection
run_test "X-Frame-Options Header (Production)" \
    'curl -s -I "$PROD_URL/health" | grep -q "x-frame-options: DENY"' \
    "pass"

run_test "X-Frame-Options Header (Development - should be missing)" \
    'curl -s -I "$DEV_URL/health" | grep -q "x-frame-options"' \
    "fail"

# Test 1.2: XSS Protection Header
run_test "X-XSS-Protection Header (Production)" \
    'curl -s -I "$PROD_URL/health" | grep -q "x-xss-protection.*mode=block"' \
    "pass"

run_test "X-XSS-Protection Header (Development - should be missing)" \
    'curl -s -I "$DEV_URL/health" | grep -q "x-xss-protection"' \
    "fail"

# Test 1.3: Content Type Options
run_test "X-Content-Type-Options Header (Production)" \
    'curl -s -I "$PROD_URL/health" | grep -q "x-content-type-options: nosniff"' \
    "pass"

run_test "X-Content-Type-Options Header (Development - should be missing)" \
    'curl -s -I "$DEV_URL/health" | grep -q "x-content-type-options"' \
    "fail"

# Test 1.4: HSTS Header
run_test "Strict-Transport-Security Header (Production)" \
    'curl -s -I "$PROD_URL/health" | grep -q "strict-transport-security"' \
    "pass"

run_test "HSTS Header (Development - should be missing)" \
    'curl -s -I "$DEV_URL/health" | grep -q "strict-transport-security"' \
    "fail"

# Test 1.5: Content Security Policy
run_test "Content-Security-Policy Header (Production)" \
    'curl -s -I "$PROD_URL/health" | grep -q "content-security-policy.*default-src.*self"' \
    "pass"

run_test "CSP Header (Development - should be missing)" \
    'curl -s -I "$DEV_URL/health" | grep -q "content-security-policy"' \
    "fail"

# ====================================================================
# TEST 2: Rate Limiting Penetration Tests
# ====================================================================
echo -e "${PURPLE}2. RATE LIMITING PENETRATION TESTS${NC}"
echo "=================================================="

# Test 2.1: Basic Rate Limiting (Production)
run_test "Rate Limit Headers Present (Production)" \
    'curl -s -I "$PROD_URL/health" | grep -q "x-ratelimit-limit"' \
    "pass"

run_test "Rate Limit Headers (Development - should be missing)" \
    'curl -s -I "$DEV_URL/health" | grep -q "x-ratelimit-limit"' \
    "fail"

# Test 2.2: Rate Limiting Enforcement (Production)
echo -e "${YELLOW}Testing Rate Limit Enforcement (Production)...${NC}"
rate_limit_test_prod() {
    local success_count=0
    local blocked_count=0
    
    for i in {1..35}; do
        response_code=$(curl -s -o /dev/null -w "%{http_code}" "$PROD_URL/health" 2>/dev/null || echo "000")
        if [ "$response_code" = "200" ] || [ "$response_code" = "405" ]; then
            ((success_count++))
        elif [ "$response_code" = "429" ]; then
            ((blocked_count++))
        fi
        sleep 0.1  # Small delay to avoid overwhelming
    done
    
    echo "Successful requests: $success_count, Blocked requests: $blocked_count"
    
    # Should have some blocked requests (rate limiting working)
    [ "$blocked_count" -gt 0 ]
}

run_test "Rate Limiting Enforcement (Production)" \
    "rate_limit_test_prod" \
    "pass"

# Test 2.3: No Rate Limiting in Development
echo -e "${YELLOW}Testing No Rate Limiting (Development)...${NC}"
rate_limit_test_dev() {
    local success_count=0
    local blocked_count=0
    
    for i in {1..10}; do  # Fewer requests for dev test
        response_code=$(curl -s -o /dev/null -w "%{http_code}" "$DEV_URL/health" 2>/dev/null || echo "000")
        if [ "$response_code" = "200" ] || [ "$response_code" = "405" ]; then
            ((success_count++))
        elif [ "$response_code" = "429" ]; then
            ((blocked_count++))
        fi
        sleep 0.1
    done
    
    echo "Successful requests: $success_count, Blocked requests: $blocked_count"
    
    # Should have no blocked requests (no rate limiting)
    [ "$blocked_count" -eq 0 ] && [ "$success_count" -gt 0 ]
}

run_test "No Rate Limiting (Development)" \
    "rate_limit_test_dev" \
    "pass"

# ====================================================================
# TEST 3: File Access Protection Tests
# ====================================================================
echo -e "${PURPLE}3. FILE ACCESS PROTECTION TESTS${NC}"
echo "=================================================="

# Create test files for penetration testing
echo "Creating test sensitive files..."
echo "SECRET_KEY=production_secret" > .env.test 2>/dev/null || true
echo "DROP TABLE users;" > backup.sql.test 2>/dev/null || true
echo "# Internal documentation" > README.md.test 2>/dev/null || true

# Test 3.1: Hidden Files Protection (Production)
run_test "Block .env file access (Production)" \
    'curl -s -o /dev/null -w "%{http_code}" "$PROD_URL/.env.test" | grep -q "403"' \
    "pass"

run_test "Block .env file access (Development - should be accessible)" \
    'curl -s -o /dev/null -w "%{http_code}" "$DEV_URL/.env.test" | grep -q "404"' \
    "pass"

# Test 3.2: SQL Files Protection (Production)
run_test "Block .sql file access (Production)" \
    'curl -s -o /dev/null -w "%{http_code}" "$PROD_URL/backup.sql.test" | grep -q "403"' \
    "pass"

# Test 3.3: Documentation Files Protection (Production)
run_test "Block .md file access (Production)" \
    'curl -s -o /dev/null -w "%{http_code}" "$PROD_URL/README.md.test" | grep -q "403"' \
    "pass"

# ====================================================================
# TEST 4: Compression and Performance Tests
# ====================================================================
echo -e "${PURPLE}4. COMPRESSION AND PERFORMANCE TESTS${NC}"
echo "=================================================="

# Test 4.1: Gzip Compression (Production)
run_test "Gzip Compression Enabled (Production)" \
    'curl -s -H "Accept-Encoding: gzip" -I "$PROD_URL/health" | grep -q "content-encoding: gzip"' \
    "pass"

run_test "Gzip Compression (Development - should be missing)" \
    'curl -s -H "Accept-Encoding: gzip" -I "$DEV_URL/health" | grep -q "content-encoding: gzip"' \
    "fail"

# Test 4.2: Vary Header for Caching
run_test "Vary Header Present (Production)" \
    'curl -s -H "Accept-Encoding: gzip" -I "$PROD_URL/health" | grep -q "vary:"' \
    "pass"

# ====================================================================
# TEST 5: Clickjacking Protection Tests
# ====================================================================
echo -e "${PURPLE}5. CLICKJACKING PROTECTION TESTS${NC}"
echo "=================================================="

# Create a test HTML page that tries to frame the application
cat > /tmp/clickjacking_test.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking Test</title>
</head>
<body>
    <h1>Clickjacking Protection Test</h1>
    <iframe id="target-frame" src="PLACEHOLDER_URL" width="800" height="600"></iframe>
    <script>
        // This should fail due to X-Frame-Options
        document.getElementById('target-frame').onload = function() {
            console.log('Frame loaded - X-Frame-Options not working!');
        };
        document.getElementById('target-frame').onerror = function() {
            console.log('Frame blocked - X-Frame-Options working!');
        };
    </script>
</body>
</html>
EOF

# Test would require browser automation for full testing
echo -e "${YELLOW}Clickjacking test HTML created at /tmp/clickjacking_test.html${NC}"
echo -e "${YELLOW}Manual test: Open in browser with PLACEHOLDER_URL replaced${NC}"

# ====================================================================
# TEST 6: SSL/TLS Configuration Tests
# ====================================================================
echo -e "${PURPLE}6. SSL/TLS CONFIGURATION TESTS${NC}"
echo "=================================================="

# Test 6.1: HSTS Enforcement
run_test "HSTS Max-Age Configuration" \
    'curl -s -I "$PROD_URL/health" | grep -q "strict-transport-security.*max-age=31536000"' \
    "pass"

run_test "HSTS includeSubDomains Directive" \
    'curl -s -I "$PROD_URL/health" | grep -q "includeSubDomains"' \
    "pass"

# ====================================================================
# TEST 7: Content Security Policy Validation
# ====================================================================
echo -e "${PURPLE}7. CONTENT SECURITY POLICY VALIDATION${NC}"
echo "=================================================="

# Test CSP directives
run_test "CSP default-src 'self' directive" \
    'curl -s -I "$PROD_URL/health" | grep -q "default-src.*self"' \
    "pass"

run_test "CSP frame-ancestors 'none' directive" \
    'curl -s -I "$PROD_URL/health" | grep -q "frame-ancestors.*none"' \
    "pass"

# ====================================================================
# TEST RESULTS SUMMARY
# ====================================================================
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE} 📊 PENETRATION TEST RESULTS SUMMARY${NC}"
echo -e "${BLUE}========================================${NC}"

pass_count=0
fail_count=0

for result in "${TEST_RESULTS[@]}"; do
    if [[ $result == PASS* ]]; then
        echo -e "${GREEN}$result${NC}"
        ((pass_count++))
    else
        echo -e "${RED}$result${NC}"
        ((fail_count++))
    fi
done

echo ""
echo -e "${BLUE}Total Tests: $((pass_count + fail_count))${NC}"
echo -e "${GREEN}Passed: $pass_count${NC}"
echo -e "${RED}Failed: $fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL SECURITY TESTS PASSED!${NC}"
    echo -e "${GREEN}Production security controls are working correctly.${NC}"
else
    echo -e "${RED}⚠️  SECURITY VULNERABILITIES DETECTED!${NC}"
    echo -e "${RED}Review failed tests and fix security configurations.${NC}"
fi

# Cleanup test files
rm -f .env.test backup.sql.test README.md.test 2>/dev/null || true

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE} 🔍 Security Analysis Complete${NC}"
echo -e "${BLUE}========================================${NC}"