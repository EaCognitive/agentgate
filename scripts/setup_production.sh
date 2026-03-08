#!/bin/bash
# AgentGate Production Setup Script
# Automates initial production environment setup

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════╗"
echo "║  AgentGate Production Setup            ║"
echo "╚════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running on supported OS
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${YELLOW}Warning: This script is optimized for Linux${NC}"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check for required commands
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}✗${NC} $1 is not installed"
        return 1
    else
        echo -e "${GREEN}✓${NC} $1 is installed"
        return 0
    fi
}

echo "Checking prerequisites..."
MISSING=0
check_command docker || MISSING=$((MISSING + 1))
check_command "docker compose" || MISSING=$((MISSING + 1))
check_command openssl || MISSING=$((MISSING + 1))

if [ $MISSING -gt 0 ]; then
    echo -e "${RED}Missing required dependencies. Please install them first.${NC}"
    exit 1
fi

cd "$PROJECT_ROOT"

# Create directory structure
echo ""
echo "Creating directory structure..."
mkdir -p data/{postgres,redis} secrets docker/nginx/ssl logs
chmod 700 data/ secrets/
echo -e "${GREEN}✓${NC} Directories created"

# Generate secrets
echo ""
echo "Generating secrets..."
if [ -f "scripts/generate_secrets.sh" ]; then
    bash scripts/generate_secrets.sh
else
    echo "Generating secrets manually..."
    openssl rand -hex 32 > secrets/api_secret_key.txt
    openssl rand -hex 32 > secrets/nextauth_secret.txt
    openssl rand -base64 32 > secrets/db_password.txt
    openssl rand -base64 32 > secrets/redis_password.txt
    chmod 600 secrets/*.txt
    echo -e "${GREEN}✓${NC} Secrets generated"
fi

# Create .env.production from template
echo ""
if [ ! -f ".env.production" ]; then
    if [ -f ".env.production.example" ]; then
        cp .env.production.example .env.production
        echo -e "${GREEN}✓${NC} Created .env.production from template"
        
        # Read secrets and update .env.production
        DB_PASSWORD=$(cat secrets/db_password.txt)
        REDIS_PASSWORD=$(cat secrets/redis_password.txt)
        
        # Update passwords in .env.production (basic sed, may need manual review)
        sed -i.bak "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$DB_PASSWORD/" .env.production
        sed -i.bak "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=$REDIS_PASSWORD/" .env.production
        rm -f .env.production.bak
        
        echo -e "${YELLOW}⚠${NC}  Please review and update .env.production with:"
        echo "   - Your domain name (ALLOWED_ORIGINS, NEXTAUTH_URL)"
        echo "   - Number of workers (WORKERS)"
        echo "   - Any other environment-specific settings"
    else
        echo -e "${YELLOW}⚠${NC}  .env.production.example not found"
        echo "Please create .env.production manually"
    fi
else
    echo -e "${YELLOW}⚠${NC}  .env.production already exists, skipping"
fi

# SSL certificate setup
echo ""
echo "SSL Certificate Setup"
echo "Do you want to set up SSL certificates now?"
echo "1) Let's Encrypt (recommended for production)"
echo "2) Self-signed (development only)"
echo "3) Skip (I'll do it manually)"
read -p "Choose option (1-3): " -n 1 -r SSL_OPTION
echo

case $SSL_OPTION in
    1)
        read -p "Enter your domain name: " DOMAIN
        if [ -z "$DOMAIN" ]; then
            echo -e "${RED}Domain name required for Let's Encrypt${NC}"
        else
            echo "Installing certbot..."
            if command -v apt-get &> /dev/null; then
                sudo apt-get update
                sudo apt-get install -y certbot
            elif command -v yum &> /dev/null; then
                sudo yum install -y certbot
            else
                echo -e "${YELLOW}Please install certbot manually${NC}"
            fi
            
            echo "Generating certificate..."
            sudo certbot certonly --standalone -d "$DOMAIN"
            
            echo "Copying certificates..."
            sudo cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem docker/nginx/ssl/cert.pem
            sudo cp /etc/letsencrypt/live/$DOMAIN/privkey.pem docker/nginx/ssl/key.pem
            sudo chmod 644 docker/nginx/ssl/cert.pem
            sudo chmod 600 docker/nginx/ssl/key.pem
            
            echo -e "${GREEN}✓${NC} SSL certificates configured"
        fi
        ;;
    2)
        echo "Generating self-signed certificate..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout docker/nginx/ssl/key.pem \
            -out docker/nginx/ssl/cert.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        chmod 644 docker/nginx/ssl/cert.pem
        chmod 600 docker/nginx/ssl/key.pem
        echo -e "${GREEN}✓${NC} Self-signed certificate created"
        echo -e "${YELLOW}⚠${NC}  This is for development only!"
        ;;
    3)
        echo "Skipping SSL setup"
        echo "Remember to place your certificates in:"
        echo "  - docker/nginx/ssl/cert.pem"
        echo "  - docker/nginx/ssl/key.pem"
        ;;
esac

# Build Docker images
echo ""
read -p "Build Docker images now? (Y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo "Building images..."
    docker compose -f docker-compose.prod.yml build
    echo -e "${GREEN}✓${NC} Images built successfully"
fi

# Summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Setup Complete!                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""
echo "Next steps:"
echo "1. Review and update .env.production with your settings"
echo "2. If you haven't set up SSL, add your certificates to docker/nginx/ssl/"
echo "3. Configure firewall: sudo ufw allow 80/tcp && sudo ufw allow 443/tcp"
echo "4. Start services: docker compose -f docker-compose.prod.yml up -d"
echo "5. Create admin user: docker compose -f docker-compose.prod.yml exec server python -m server.cli create-admin"
echo "6. Configure backups: sudo crontab -e and add backup script"
echo "7. Review SECURITY_CHECKLIST.md and complete all items"
echo ""
echo -e "${YELLOW}Important files:${NC}"
echo "  - .env.production: Environment configuration"
echo "  - secrets/: Generated secrets (NEVER commit to git)"
echo "  - DOCKER_DEPLOYMENT.md: Full deployment guide"
echo "  - SECURITY_CHECKLIST.md: Security verification"
echo ""
