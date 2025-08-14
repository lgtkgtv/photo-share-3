#!/bin/bash

# Development Environment Setup Script
# This script sets up a consistent development environment

set -e  # Exit on any error

echo "🚀 Setting up Photo Share App Development Environment"
echo "=================================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Check if required tools are installed
check_dependencies() {
    print_info "Checking dependencies..."
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker is required but not installed"
        exit 1
    fi
    print_status "Docker found"
    
    if ! command -v docker compose &> /dev/null; then
        print_error "Docker Compose is required but not installed"
        exit 1
    fi
    print_status "Docker Compose found"
    
    if ! command -v python3 &> /dev/null; then
        print_warning "Python3 not found - required for some utilities"
    else
        print_status "Python3 found"
    fi
}

# Setup environment files
setup_environment() {
    print_info "Setting up environment configuration..."
    
    # Check if .env exists, if not copy from .env.development
    if [[ ! -f .env ]]; then
        if [[ -f .env.development ]]; then
            cp .env.development .env
            print_status "Created .env from .env.development"
        else
            print_error ".env.development not found. Please ensure environment files exist."
            exit 1
        fi
    else
        print_warning ".env already exists - not overwriting"
        print_info "Consider reviewing .env.development for new configuration options"
    fi
}

# Generate secure JWT secrets if needed
generate_jwt_secrets() {
    print_info "Checking JWT configuration..."
    
    # Check if JWT_SECRET_KEY in .env is using a default value
    if grep -q "development_jwt_secret_key_for_local_development" .env 2>/dev/null; then
        print_warning "Using default development JWT secret"
        print_info "For enhanced security, consider generating a new secret with:"
        print_info "  python3 scripts/generate-jwt-secrets.py"
    else
        print_status "JWT secret appears to be customized"
    fi
}

# Setup Docker environment
setup_docker() {
    print_info "Setting up Docker environment..."
    
    # Stop any running containers
    print_info "Stopping any running containers..."
    docker compose down --remove-orphans 2>/dev/null || true
    
    # Build and start services
    print_info "Building and starting development services..."
    docker compose up --build -d
    
    # Wait for database to be ready
    print_info "Waiting for database to be ready..."
    sleep 10
    
    # Initialize database
    print_info "Initializing database..."
    docker compose exec backend python init_db.py
    
    print_status "Development environment is ready!"
}

# Run health checks
health_check() {
    print_info "Running health checks..."
    
    # Check if backend is responding
    if curl -s http://localhost:8000/health >/dev/null 2>&1; then
        print_status "Backend is healthy"
    else
        print_warning "Backend health check failed - it may still be starting up"
    fi
    
    # Check if database is accessible
    if docker compose exec -T backend python -c "
from services.db import get_db
import asyncio

async def test_db():
    async for db in get_db():
        print('Database connection: OK')
        return True
    return False

asyncio.run(test_db())
" 2>/dev/null; then
        print_status "Database connection is working"
    else
        print_warning "Database connection test failed"
    fi
}

# Display useful information
display_info() {
    echo ""
    echo "🎉 Development Environment Setup Complete!"
    echo "========================================"
    echo ""
    echo "Services running:"
    echo "  • Backend API: http://localhost:8000"
    echo "  • API Documentation: http://localhost:8000/docs"
    echo "  • Database: localhost:5432"
    echo ""
    echo "Useful commands:"
    echo "  • View logs: docker compose logs -f"
    echo "  • Run tests: ./scripts/run-tests.sh"
    echo "  • Stop services: docker compose down"
    echo "  • Access database: docker compose exec db psql -U photo_dev_user -d photoapp_dev"
    echo "  • Backend shell: docker compose exec backend bash"
    echo ""
    echo "Configuration files:"
    echo "  • Development: .env.development"
    echo "  • Testing: .env.test"
    echo "  • Production template: .env.production.template"
    echo ""
}

# Main execution
main() {
    check_dependencies
    setup_environment
    generate_jwt_secrets
    setup_docker
    health_check
    display_info
}

# Run main function
main "$@"