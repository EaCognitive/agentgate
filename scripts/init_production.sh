#!/bin/bash
# Production Initialization Script for AgentGate
# This script sets up a production-ready AgentGate deployment using Docker Compose
#
# Features:
# - Generates secure random passwords
# - Creates necessary directories
# - Validates environment
# - Builds Docker images
# - Runs database migrations
# - Starts all services
# - Performs health checks

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Generate secure random password
generate_password() {
    openssl rand -hex 32
}

# Validate prerequisites
validate_prerequisites() {
    log_info "Validating prerequisites..."

    if ! command_exists docker; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! command_exists docker-compose; then
        log_error "docker-compose is not installed. Please install docker-compose first."
        exit 1
    fi

    if ! command_exists openssl; then
        log_error "openssl is not installed. Please install openssl first."
        exit 1
    fi

    log_info "All prerequisites satisfied."
}

# Create required directories
create_directories() {
    log_info "Creating required directories..."

    mkdir -p data/postgres
    mkdir -p data/redis
    mkdir -p logs
    mkdir -p backups

    log_info "Directories created successfully."
}

# Generate or load environment variables
setup_environment() {
    log_info "Setting up environment variables..."

    if [ -f .env.production ]; then
        log_warn ".env.production already exists. Do you want to regenerate it? (y/N)"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log_info "Using existing .env.production"
            return
        fi
    fi

    # Copy from example
    if [ ! -f .env.production.example ]; then
        log_error ".env.production.example not found"
        exit 1
    fi

    cp .env.production.example .env.production

    # Generate secure passwords
    log_info "Generating secure passwords..."
    POSTGRES_PASSWORD=$(generate_password)
    REDIS_PASSWORD=$(generate_password)
    SECRET_KEY=$(generate_password)
    NEXTAUTH_SECRET=$(generate_password)

    # Update .env.production with generated values
    sed -i.bak "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/" .env.production
    sed -i.bak "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=$REDIS_PASSWORD/" .env.production
    sed -i.bak "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env.production
    sed -i.bak "s/NEXTAUTH_SECRET=.*/NEXTAUTH_SECRET=$NEXTAUTH_SECRET/" .env.production

    # Remove backup file
    rm -f .env.production.bak

    log_info "Environment variables configured."
    log_warn "IMPORTANT: .env.production contains sensitive credentials. Keep it secure!"
}

# Build Docker images
build_images() {
    log_info "Building Docker images..."

    docker-compose -f docker-compose.production.yml build --no-cache

    log_info "Docker images built successfully."
}

# Start services
start_services() {
    log_info "Starting services..."

    docker-compose -f docker-compose.production.yml up -d postgres redis

    log_info "Waiting for PostgreSQL to be ready..."
    sleep 10

    # Wait for PostgreSQL health check
    for i in {1..30}; do
        if docker-compose -f docker-compose.production.yml exec -T postgres pg_isready -U agentgate >/dev/null 2>&1; then
            log_info "PostgreSQL is ready."
            break
        fi
        if [ $i -eq 30 ]; then
            log_error "PostgreSQL failed to start within 30 seconds."
            exit 1
        fi
        sleep 1
    done

    log_info "Waiting for Redis to be ready..."
    for i in {1..30}; do
        if docker-compose -f docker-compose.production.yml exec -T redis redis-cli ping >/dev/null 2>&1; then
            log_info "Redis is ready."
            break
        fi
        if [ $i -eq 30 ]; then
            log_error "Redis failed to start within 30 seconds."
            exit 1
        fi
        sleep 1
    done

    log_info "Database services started successfully."
}

# Run database migrations
run_migrations() {
    log_info "Running database migrations..."

    # Check if Alembic is set up
    if [ ! -d alembic/versions ]; then
        log_info "Creating initial migration..."
        docker-compose -f docker-compose.production.yml run --rm server \
            alembic revision --autogenerate -m "Initial schema"
    fi

    # Apply migrations
    docker-compose -f docker-compose.production.yml run --rm server \
        alembic upgrade head

    log_info "Database migrations completed."
}

# Start application services
start_app_services() {
    log_info "Starting application services..."

    docker-compose -f docker-compose.production.yml up -d server dashboard

    log_info "Application services started."
}

# Perform health checks
health_check() {
    log_info "Performing health checks..."

    sleep 15

    # Check server health
    log_info "Checking server health..."
    for i in {1..60}; do
        if curl -sf http://localhost:8000/api/health >/dev/null 2>&1; then
            log_info "Server is healthy."
            break
        fi
        if [ $i -eq 60 ]; then
            log_error "Server failed health check after 60 seconds."
            docker-compose -f docker-compose.production.yml logs server
            exit 1
        fi
        sleep 1
    done

    # Check dashboard health
    log_info "Checking dashboard health..."
    for i in {1..60}; do
        if curl -sf http://localhost:3000/ >/dev/null 2>&1; then
            log_info "Dashboard is healthy."
            break
        fi
        if [ $i -eq 60 ]; then
            log_warn "Dashboard health check timeout (this is normal if dashboard is not built)."
            break
        fi
        sleep 1
    done

    log_info "Health checks completed."
}

# Print summary
print_summary() {
    log_info "=================================="
    log_info "AgentGate Production Setup Complete!"
    log_info "=================================="
    echo ""
    log_info "Services are running at:"
    log_info "  API Server:   http://localhost:8000"
    log_info "  API Docs:     http://localhost:8000/docs"
    log_info "  Dashboard:    http://localhost:3000"
    echo ""
    log_info "Useful commands:"
    log_info "  View logs:    docker-compose -f docker-compose.production.yml logs -f"
    log_info "  Stop:         docker-compose -f docker-compose.production.yml down"
    log_info "  Restart:      docker-compose -f docker-compose.production.yml restart"
    log_info "  Status:       docker-compose -f docker-compose.production.yml ps"
    echo ""
    log_warn "IMPORTANT: Secure your .env.production file - it contains sensitive credentials!"
    echo ""
}

# Main execution
main() {
    log_info "Starting AgentGate production initialization..."
    echo ""

    validate_prerequisites
    create_directories
    setup_environment
    build_images
    start_services
    run_migrations
    start_app_services
    health_check
    print_summary

    log_info "Setup completed successfully!"
}

# Run main function
main "$@"
