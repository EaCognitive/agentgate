#!/bin/bash
# AgentGate Restore Script
# Restores PostgreSQL, Redis, and secrets from backup

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/var/backups/agentgate}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

# Check arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup_date> [component]"
    echo ""
    echo "Examples:"
    echo "  $0 20250128_020000              # Restore all from backup"
    echo "  $0 20250128_020000 postgres     # Restore PostgreSQL only"
    echo "  $0 20250128_020000 redis        # Restore Redis only"
    echo "  $0 20250128_020000 secrets      # Restore secrets only"
    echo ""
    echo "Available backups:"
    find "$BACKUP_DIR" -maxdepth 1 -name "postgres_*.sql.gz" -printf '%f\n' 2>/dev/null | sed 's/postgres_/  /' | sed 's/.sql.gz//' | sort -r | head -5
    exit 1
fi

BACKUP_DATE=$1
COMPONENT=${2:-all}

cd "$PROJECT_ROOT"

# Download from cloud storage if configured and backup not found locally
if [ ! -f "$BACKUP_DIR/postgres_${BACKUP_DATE}.sql.gz" ]; then
    if [ -n "$CLOUD_PROVIDER" ] && [ -n "$CLOUD_BUCKET" ]; then
        log "Backup not found locally, attempting to download from cloud storage..."

        # Build base cloud command (word splitting is intentional)
        # shellcheck disable=SC2086
        CLOUD_BASE="python3 $SCRIPT_DIR/cloud_backup.py download --provider $CLOUD_PROVIDER --bucket $CLOUD_BUCKET --backup-dir $BACKUP_DIR"

        if [ -n "$GCP_PROJECT_ID" ]; then
            CLOUD_BASE="$CLOUD_BASE --project-id $GCP_PROJECT_ID"
        fi

        # Try to download the PostgreSQL backup
        # shellcheck disable=SC2086
        if $CLOUD_BASE --remote-path "backups/$BACKUP_DATE/postgres_${BACKUP_DATE}.sql.gz"; then
            log "Downloaded PostgreSQL backup from cloud storage"
        fi

        # Try to download the Redis backup
        # shellcheck disable=SC2086
        $CLOUD_BASE --remote-path "backups/$BACKUP_DATE/redis_${BACKUP_DATE}.rdb" 2>/dev/null || true

        # Try to download the secrets backup
        # shellcheck disable=SC2086
        $CLOUD_BASE --remote-path "backups/$BACKUP_DATE/secrets_${BACKUP_DATE}.tar.gz" 2>/dev/null || true

        # Try to download the config backup
        # shellcheck disable=SC2086
        $CLOUD_BASE --remote-path "backups/$BACKUP_DATE/config_${BACKUP_DATE}.tar.gz" 2>/dev/null || true
    fi
fi

# Check if backup exists
if [ ! -f "$BACKUP_DIR/postgres_${BACKUP_DATE}.sql.gz" ]; then
    error "Backup not found: postgres_${BACKUP_DATE}.sql.gz"
    exit 1
fi

# Confirmation
echo -e "${YELLOW}WARNING: This will replace existing data!${NC}"
echo "Backup date: $BACKUP_DATE"
echo "Component: $COMPONENT"
echo ""
read -p "Are you sure you want to continue? (yes/no): " -r
if [[ ! $REPLY == "yes" ]]; then
    echo "Restore cancelled."
    exit 0
fi

# Stop services
log "Stopping services..."
docker compose -f "$COMPOSE_FILE" down

# Restore PostgreSQL
if [ "$COMPONENT" = "all" ] || [ "$COMPONENT" = "postgres" ]; then
    log "Restoring PostgreSQL database..."
    
    # Start only database
    docker compose -f "$COMPOSE_FILE" up -d db
    sleep 5
    
    # Wait for database to be ready
    log "Waiting for database to be ready..."
    until docker compose -f "$COMPOSE_FILE" exec -T db pg_isready -U agentgate; do
        sleep 1
    done
    
    # Drop and recreate database
    docker compose -f "$COMPOSE_FILE" exec -T db psql -U agentgate -c "DROP DATABASE IF EXISTS agentgate;"
    docker compose -f "$COMPOSE_FILE" exec -T db psql -U agentgate -c "CREATE DATABASE agentgate;"
    
    # Restore from backup
    gunzip < "$BACKUP_DIR/postgres_${BACKUP_DATE}.sql.gz" | \
        docker compose -f "$COMPOSE_FILE" exec -T db psql -U agentgate agentgate
    
    log "PostgreSQL restore completed"
    
    # Stop database
    docker compose -f "$COMPOSE_FILE" down
fi

# Restore Redis
if [ "$COMPONENT" = "all" ] || [ "$COMPONENT" = "redis" ]; then
    if [ -f "$BACKUP_DIR/redis_${BACKUP_DATE}.rdb" ]; then
        log "Restoring Redis data..."
        
        # Copy Redis backup
        mkdir -p data/redis
        cp "$BACKUP_DIR/redis_${BACKUP_DATE}.rdb" data/redis/dump.rdb
        chmod 644 data/redis/dump.rdb
        
        log "Redis restore completed"
    else
        warning "Redis backup not found: redis_${BACKUP_DATE}.rdb"
    fi
fi

# Restore secrets
if [ "$COMPONENT" = "all" ] || [ "$COMPONENT" = "secrets" ]; then
    if [ -f "$BACKUP_DIR/secrets_${BACKUP_DATE}.tar.gz" ]; then
        log "Restoring secrets..."
        
        # Backup existing secrets
        if [ -d "secrets" ]; then
            warning "Backing up existing secrets to secrets.old"
            mv secrets secrets.old
        fi
        
        # Extract secrets
        tar -xzf "$BACKUP_DIR/secrets_${BACKUP_DATE}.tar.gz"
        chmod 700 secrets
        chmod 600 secrets/*
        
        log "Secrets restore completed"
    else
        warning "Secrets backup not found: secrets_${BACKUP_DATE}.tar.gz"
    fi
fi

# Restore configuration
if [ "$COMPONENT" = "all" ]; then
    if [ -f "$BACKUP_DIR/config_${BACKUP_DATE}.tar.gz" ]; then
        log "Restoring configuration..."
        
        read -p "Restore configuration files? This will overwrite docker-compose.prod.yml and .env.production (yes/no): " -r
        if [[ $REPLY == "yes" ]]; then
            tar -xzf "$BACKUP_DIR/config_${BACKUP_DATE}.tar.gz"
            log "Configuration restore completed"
        else
            log "Skipping configuration restore"
        fi
    else
        warning "Configuration backup not found: config_${BACKUP_DATE}.tar.gz"
    fi
fi

# Start services
log "Starting services..."
docker compose -f "$COMPOSE_FILE" up -d

# Wait for services to be healthy
log "Waiting for services to be healthy..."
sleep 10

# Verify restore
log "Verifying restore..."
if docker compose -f "$COMPOSE_FILE" ps | grep -q "healthy"; then
    log "Services are healthy"
else
    warning "Some services may not be healthy. Check with: docker compose -f $COMPOSE_FILE ps"
fi

log "Restore completed successfully!"
echo ""
echo "Next steps:"
echo "1. Verify data integrity"
echo "2. Test application functionality"
echo "3. Check logs: docker compose -f $COMPOSE_FILE logs -f"
echo ""
