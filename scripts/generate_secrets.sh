#!/bin/bash
# AgentGate Secret Generation Script
# Generates strong secrets for production deployment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SECRETS_DIR="secrets"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "${GREEN}AgentGate Secret Generation${NC}"
echo "=========================================="
echo ""

# Create secrets directory
mkdir -p "$PROJECT_ROOT/$SECRETS_DIR"
chmod 700 "$PROJECT_ROOT/$SECRETS_DIR"

# Function to generate secret
generate_secret() {
    local name=$1
    local filename="$PROJECT_ROOT/$SECRETS_DIR/$name.txt"

    if [ -f "$filename" ]; then
        echo -e "${YELLOW}Warning: $name already exists${NC}"
        read -p "Overwrite? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Skipping $name"
            return
        fi
    fi

    # Generate secret based on type
    case $name in
        db_password|redis_password)
            # Generate strong password (32 chars, base64)
            openssl rand -base64 32 > "$filename"
            ;;
        api_secret_key|nextauth_secret|jwt_secret)
            # Generate hex key (64 chars)
            openssl rand -hex 32 > "$filename"
            ;;
        *)
            # Default: hex key
            openssl rand -hex 32 > "$filename"
            ;;
    esac

    # Set restrictive permissions
    chmod 600 "$filename"

    echo -e "${GREEN}✓${NC} Generated $name"
}

# Generate all required secrets
echo "Generating secrets..."
echo ""

generate_secret "db_password"
generate_secret "redis_password"
generate_secret "api_secret_key"
generate_secret "nextauth_secret"
generate_secret "jwt_secret"

echo ""
echo -e "${GREEN}✓ All secrets generated successfully${NC}"
echo ""
echo "Secrets location: $PROJECT_ROOT/$SECRETS_DIR/"
echo ""
echo -e "${YELLOW}IMPORTANT SECURITY NOTES:${NC}"
echo "1. Never commit the secrets/ directory to version control"
echo "2. Backup secrets securely (encrypted)"
echo "3. Rotate secrets regularly"
echo "4. Use different secrets for each environment"
echo ""
echo "Next steps:"
echo "1. Copy .env.production.example to .env.production"
echo "2. Update .env.production with your domain and settings"
echo "3. Run: docker compose -f docker-compose.prod.yml up -d"
echo ""
