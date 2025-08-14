#!/bin/bash

# Comprehensive Test Runner Script
# This script runs tests with proper environment setup and reporting

set -e  # Exit on any error

echo "🧪 Running Photo Share App Tests"
echo "================================"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_section() {
    echo -e "${PURPLE}${1}${NC}"
    echo -e "${PURPLE}$(printf '=%.0s' $(seq 1 ${#1}))${NC}"
}

# Parse command line arguments
TEST_TYPE="all"
VERBOSE=false
COVERAGE=false
FAST=false
CLEANUP=true
OUTPUT_FORMAT="standard"

while [[ $# -gt 0 ]]; do
    case $1 in
        --type|-t)
            TEST_TYPE="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --coverage|-c)
            COVERAGE=true
            shift
            ;;
        --fast|-f)
            FAST=true
            shift
            ;;
        --no-cleanup)
            CLEANUP=false
            shift
            ;;
        --format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -t, --type TYPE      Test type: all, security, jwt, unit, integration"
            echo "  -v, --verbose        Verbose output"
            echo "  -c, --coverage       Generate coverage report"
            echo "  -f, --fast           Fast mode (skip slow tests)"
            echo "  --no-cleanup         Don't cleanup after tests"
            echo "  --format FORMAT      Output format: standard, junit, json"
            echo "  -h, --help           Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                           # Run all tests"
            echo "  $0 --type security          # Run security tests only"
            echo "  $0 --type jwt --verbose      # Run JWT tests with verbose output"
            echo "  $0 --coverage                # Run tests with coverage"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate test type
case $TEST_TYPE in
    "all"|"security"|"jwt"|"unit"|"integration")
        ;;
    *)
        print_error "Invalid test type: $TEST_TYPE"
        print_info "Valid types: all, security, jwt, unit, integration"
        exit 1
        ;;
esac

# Setup test environment
setup_test_environment() {
    print_section "Setting Up Test Environment"
    
    # Ensure test configuration exists
    if [[ ! -f .env.test ]]; then
        print_error ".env.test not found. Please run scripts/setup-dev-env.sh first."
        exit 1
    fi
    print_status "Test configuration found"
    
    # Stop any running containers
    print_info "Stopping running containers..."
    docker compose down --remove-orphans 2>/dev/null || true
    docker compose -f docker-compose.test.yml down --remove-orphans 2>/dev/null || true
    
    # Start test environment
    print_info "Starting test environment..."
    docker compose -f docker-compose.test.yml up -d test-db test-redis
    
    # Wait for services to be ready
    print_info "Waiting for test services to be ready..."
    sleep 10
    
    print_status "Test environment ready"
}

# Build pytest command based on options
build_pytest_command() {
    local cmd="pytest"
    
    # Add test selection based on type
    case $TEST_TYPE in
        "security")
            cmd="$cmd tests/test_security_*"
            ;;
        "jwt")
            cmd="$cmd tests/test_security_authentication.py::TestJWTSecurity"
            ;;
        "unit")
            cmd="$cmd tests/ -m 'not integration and not slow'"
            ;;
        "integration")
            cmd="$cmd tests/ -m integration"
            ;;
        "all")
            if [[ "$FAST" == "true" ]]; then
                cmd="$cmd tests/ -m 'not slow'"
            else
                cmd="$cmd tests/"
            fi
            ;;
    esac
    
    # Add verbosity
    if [[ "$VERBOSE" == "true" ]]; then
        cmd="$cmd -v -s"
    else
        cmd="$cmd --tb=short"
    fi
    
    # Add coverage
    if [[ "$COVERAGE" == "true" ]]; then
        cmd="$cmd --cov=. --cov-report=html --cov-report=term"
    fi
    
    # Add output format
    case $OUTPUT_FORMAT in
        "junit")
            cmd="$cmd --junit-xml=test-results.xml"
            ;;
        "json")
            cmd="$cmd --json-report --json-report-file=test-results.json"
            ;;
    esac
    
    echo "$cmd"
}

# Run the tests
run_tests() {
    print_section "Running Tests: $TEST_TYPE"
    
    local pytest_cmd=$(build_pytest_command)
    print_info "Test command: $pytest_cmd"
    
    # Run tests in Docker container with proper environment
    if docker compose -f docker-compose.test.yml run --rm -e ENVIRONMENT=test test-backend $pytest_cmd; then
        print_status "Tests completed successfully"
        return 0
    else
        print_error "Tests failed"
        return 1
    fi
}

# Generate test summary
generate_summary() {
    print_section "Test Summary"
    
    # Check if results files exist and display summary
    if [[ -f test-results.xml ]]; then
        print_info "JUnit results: test-results.xml"
    fi
    
    if [[ -f test-results.json ]]; then
        print_info "JSON results: test-results.json"
    fi
    
    if [[ -d htmlcov ]]; then
        print_info "Coverage report: htmlcov/index.html"
        print_info "Open with: open htmlcov/index.html"
    fi
}

# Cleanup test environment
cleanup_test_environment() {
    if [[ "$CLEANUP" == "true" ]]; then
        print_section "Cleaning Up"
        
        print_info "Stopping test containers..."
        docker compose -f docker-compose.test.yml down --remove-orphans
        
        print_status "Cleanup completed"
    else
        print_info "Skipping cleanup (test containers still running)"
    fi
}

# Main execution with error handling
main() {
    local exit_code=0
    
    # Setup
    setup_test_environment
    
    # Run tests with error handling
    if ! run_tests; then
        exit_code=1
    fi
    
    # Generate summary regardless of test results
    generate_summary
    
    # Cleanup
    cleanup_test_environment
    
    # Final status
    echo ""
    if [[ $exit_code -eq 0 ]]; then
        print_status "All tests completed successfully! 🎉"
    else
        print_error "Some tests failed. Check the output above for details."
    fi
    
    exit $exit_code
}

# Trap to ensure cleanup on script exit
trap 'cleanup_test_environment' EXIT

# Run main function
main "$@"