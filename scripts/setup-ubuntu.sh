#!/bin/bash

# Smart Ubuntu 24.04 Setup Script for Photo Sharing Platform
# This script checks for existing installations and only installs missing tools

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should NOT be run as root. Please run as a regular user."
        exit 1
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if package is installed
package_installed() {
    dpkg -l | grep -q "^ii  $1 "
}

# Install package if not present
install_package() {
    local package="$1"
    local description="$2"
    
    if package_installed "$package"; then
        log_success "$description already installed"
    else
        log_info "Installing $description..."
        sudo apt install -y "$package"
        log_success "$description installed successfully"
    fi
}

# Update system
update_system() {
    log_info "Updating system packages..."
    sudo apt update && sudo apt upgrade -y
    log_success "System updated successfully"
}

# Install essential development tools
install_essential_tools() {
    log_info "Installing essential development tools..."
    
    local packages=(
        "git:Git version control"
        "curl:Download tool"
        "wget:Web downloader"
        "vim:Text editor"
        "build-essential:Build tools"
        "software-properties-common:Software properties"
        "apt-transport-https:HTTPS transport"
        "ca-certificates:SSL certificates"
        "gnupg:GNU Privacy Guard"
        "lsb-release:LSB utilities"
    )
    
    for package_info in "${packages[@]}"; do
        IFS=':' read -r package description <<< "$package_info"
        install_package "$package" "$description"
    done
}

# Install Docker
install_docker() {
    if command_exists docker; then
        log_success "Docker already installed ($(docker --version))"
        
        # Check if user is in docker group
        if groups "$USER" | grep -q docker; then
            log_success "User already in docker group"
        else
            log_info "Adding user to docker group..."
            sudo usermod -aG docker "$USER"
            log_warning "Please log out and log back in for docker group changes to take effect"
        fi
    else
        log_info "Installing Docker..."
        
        # Remove old versions
        sudo apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
        
        # Install Docker using official script
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        rm get-docker.sh
        
        # Add user to docker group
        sudo usermod -aG docker "$USER"
        
        # Start and enable Docker
        sudo systemctl start docker
        sudo systemctl enable docker
        
        log_success "Docker installed successfully"
        log_warning "Please log out and log back in for docker group changes to take effect"
    fi
}

# Install Docker Compose
install_docker_compose() {
    if command_exists docker-compose; then
        log_success "Docker Compose already installed ($(docker-compose --version))"
    else
        log_info "Installing Docker Compose..."
        
        # Get latest version
        DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep -Po '"tag_name": "\K.*?(?=")')
        
        # Download and install
        sudo curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
        
        # Create symlink for compatibility
        sudo ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
        
        log_success "Docker Compose installed successfully ($(docker-compose --version))"
    fi
}

# Install Python development tools
install_python_tools() {
    log_info "Installing Python development tools..."
    
    local packages=(
        "python3:Python 3"
        "python3-venv:Python virtual environment"
        "python3-pip:Python package installer"
        "python3-dev:Python development headers"
        "python3-setuptools:Python setup tools"
        "python3-wheel:Python wheel support"
    )
    
    for package_info in "${packages[@]}"; do
        IFS=':' read -r package description <<< "$package_info"
        install_package "$package" "$description"
    done
    
    # Upgrade pip
    log_info "Upgrading pip..."
    python3 -m pip install --user --upgrade pip
    log_success "pip upgraded successfully"
}

# Install database and utility tools
install_utilities() {
    log_info "Installing database and utility tools..."
    
    local packages=(
        "postgresql-client:PostgreSQL client"
        "redis-tools:Redis client tools"
        "jq:JSON processor"
        "httpie:HTTP client"
        "tree:Directory tree viewer"
        "htop:Process viewer"
        "net-tools:Network tools"
        "unzip:Archive extractor"
    )
    
    for package_info in "${packages[@]}"; do
        IFS=':' read -r package description <<< "$package_info"
        install_package "$package" "$description"
    done
}

# Install optional development tools
install_optional_tools() {
    log_info "Installing optional development tools..."
    
    # VS Code
    if command_exists code; then
        log_success "VS Code already installed"
    else
        log_info "Installing VS Code..."
        if command_exists snap; then
            sudo snap install code --classic
            log_success "VS Code installed via snap"
        else
            # Install via APT
            wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
            sudo install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/
            sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
            sudo apt update
            sudo apt install -y code
            log_success "VS Code installed via APT"
        fi
    fi
    
    # pgAdmin4 (optional)
    read -p "Install pgAdmin4 for PostgreSQL management? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_package "pgadmin4" "pgAdmin4"
    fi
    
    # Postman (optional)
    read -p "Install Postman for API testing? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command_exists postman; then
            log_success "Postman already installed"
        else
            if command_exists snap; then
                sudo snap install postman
                log_success "Postman installed via snap"
            else
                log_warning "Snap not available, please install Postman manually"
            fi
        fi
    fi
}

# Install VS Code extensions
install_vscode_extensions() {
    if command_exists code; then
        log_info "Installing VS Code extensions..."
        
        local extensions=(
            "ms-python.python"
            "ms-python.black-formatter"
            "ms-vscode.vscode-docker"
            "ms-vscode.vscode-json"
            "bradlc.vscode-tailwindcss"
            "esbenp.prettier-vscode"
            "ms-python.pylint"
        )
        
        for extension in "${extensions[@]}"; do
            if code --list-extensions | grep -q "$extension"; then
                log_success "VS Code extension $extension already installed"
            else
                log_info "Installing VS Code extension: $extension"
                code --install-extension "$extension" --force
            fi
        done
        
        log_success "VS Code extensions installed"
    fi
}

# Setup project environment
setup_project_environment() {
    local project_dir="$1"
    
    if [[ -z "$project_dir" ]]; then
        project_dir="./photo-share-3"
    fi
    
    log_info "Setting up project environment in $project_dir..."
    
    # Create project directory if it doesn't exist
    if [[ ! -d "$project_dir" ]]; then
        log_info "Project directory doesn't exist. Please clone the repository first."
        return 1
    fi
    
    cd "$project_dir"
    
    # Create Python virtual environment
    if [[ ! -d ".venv" ]]; then
        log_info "Creating Python virtual environment..."
        python3 -m venv .venv
        log_success "Virtual environment created"
    else
        log_success "Virtual environment already exists"
    fi
    
    # Activate virtual environment and install requirements
    if [[ -f "backend/requirements.txt" ]]; then
        log_info "Installing Python requirements..."
        source .venv/bin/activate
        pip install -r backend/requirements.txt
        deactivate
        log_success "Python requirements installed"
    fi
    
    # Copy environment files if they don't exist
    if [[ ! -f ".env" && -f ".env.development" ]]; then
        log_info "Creating development environment file..."
        cp .env.development .env
        log_success "Development environment configured"
    fi
    
    # Create scripts directory and make scripts executable
    if [[ -d "scripts" ]]; then
        log_info "Making scripts executable..."
        chmod +x scripts/*.sh 2>/dev/null || true
        log_success "Scripts made executable"
    fi
    
    log_success "Project environment setup complete"
}

# Validate installation
validate_installation() {
    log_info "Validating installation..."
    
    local errors=0
    
    # Check essential tools
    local tools=(
        "git:Git"
        "docker:Docker"
        "docker-compose:Docker Compose"
        "python3:Python 3"
        "pip:pip"
        "psql:PostgreSQL client"
        "redis-cli:Redis client"
        "jq:jq JSON processor"
        "http:HTTPie"
    )
    
    for tool_info in "${tools[@]}"; do
        IFS=':' read -r tool description <<< "$tool_info"
        if command_exists "$tool"; then
            log_success "$description is available"
        else
            log_error "$description is not available"
            ((errors++))
        fi
    done
    
    # Check Docker group membership
    if groups "$USER" | grep -q docker; then
        log_success "User is in docker group"
    else
        log_warning "User is not in docker group - please log out and log back in"
    fi
    
    # Check Python virtual environment
    if [[ -d ".venv" ]]; then
        log_success "Python virtual environment is available"
    else
        log_warning "Python virtual environment not found"
    fi
    
    if [[ $errors -eq 0 ]]; then
        log_success "All essential tools are properly installed!"
        return 0
    else
        log_error "$errors essential tools are missing"
        return 1
    fi
}

# Print usage instructions
print_usage() {
    cat << EOF

${GREEN}=== Ubuntu 24.04 Setup Complete ===${NC}

${BLUE}Next Steps:${NC}
1. If this was your first Docker installation, please log out and log back in
2. Clone the photo sharing repository (if not already done):
   ${YELLOW}git clone <repository-url> photo-share-3${NC}
3. Navigate to the project directory:
   ${YELLOW}cd photo-share-3${NC}
4. Activate the Python virtual environment:
   ${YELLOW}source .venv/bin/activate${NC}
5. Start the development environment:
   ${YELLOW}./scripts/dev.sh${NC}
   or manually:
   ${YELLOW}docker compose up --build${NC}

${BLUE}Environment Scripts:${NC}
- ${YELLOW}./scripts/dev.sh${NC}      - Start development environment
- ${YELLOW}./scripts/test.sh${NC}     - Run test environment
- ${YELLOW}./scripts/prod-sim.sh${NC} - Simulate production environment

${BLUE}Useful Commands:${NC}
- ${YELLOW}docker compose logs -f${NC}           - View container logs
- ${YELLOW}docker-compose exec backend bash${NC} - Access backend container
- ${YELLOW}pytest backend/tests/ -v${NC}         - Run tests

${BLUE}Documentation:${NC}
- API Docs: http://localhost:8000/docs
- README.md for detailed instructions
- claude_chat_log.md for technical details

EOF
}

# Main installation function
main() {
    echo "=============================================="
    echo "  Photo Sharing Platform Setup for Ubuntu 24.04"
    echo "=============================================="
    echo
    
    check_root
    
    log_info "Starting intelligent setup process..."
    
    # Core installation steps
    update_system
    install_essential_tools
    install_docker
    install_docker_compose
    install_python_tools
    install_utilities
    
    # Optional tools
    echo
    log_info "Installing optional development tools..."
    install_optional_tools
    install_vscode_extensions
    
    # Project setup
    echo
    read -p "Setup project environment in current directory? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        setup_project_environment "."
    fi
    
    # Validation
    echo
    validate_installation
    
    # Usage instructions
    print_usage
    
    log_success "Setup completed successfully!"
}

# Run main function
main "$@"