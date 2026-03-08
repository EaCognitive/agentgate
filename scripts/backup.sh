#!/bin/bash
# AgentGate Backup Script
# Backs up PostgreSQL, Redis, and secrets

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/var/backups/agentgate}"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS="${RETENTION_DAYS:-30}"
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

# Check if running as root (optional)
if [ "$EUID" -ne 0 ] && [ ! -w "$BACKUP_DIR" ]; then
    warning "Not running as root. May need sudo for some operations."
fi

# Create backup directory
log "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

cd "$PROJECT_ROOT"

# Check if services are running
if ! docker compose -f "$COMPOSE_FILE" ps | grep -q "Up"; then
    error "Services are not running. Start them with: docker compose -f $COMPOSE_FILE up -d"
    exit 1
fi

# Backup PostgreSQL
log "Backing up PostgreSQL database..."
if docker compose -f "$COMPOSE_FILE" exec -T db pg_dump -U agentgate agentgate | gzip > "$BACKUP_DIR/postgres_$DATE.sql.gz"; then
    log "PostgreSQL backup completed: postgres_$DATE.sql.gz"
    chmod 600 "$BACKUP_DIR/postgres_$DATE.sql.gz"
else
    error "PostgreSQL backup failed"
    exit 1
fi

# Backup Redis (BGSAVE to avoid blocking traffic)
log "Backing up Redis data..."
LASTSAVE_BEFORE=$(docker compose -f "$COMPOSE_FILE" exec -T redis redis-cli LASTSAVE 2>/dev/null | grep -o '[0-9]*')
if docker compose -f "$COMPOSE_FILE" exec -T redis redis-cli BGSAVE > /dev/null 2>&1; then
    # Wait for background save to complete by polling LASTSAVE
    for _ in $(seq 1 30); do
        LASTSAVE_NOW=$(docker compose -f "$COMPOSE_FILE" exec -T redis redis-cli LASTSAVE 2>/dev/null | grep -o '[0-9]*')
        if [ "$LASTSAVE_NOW" != "$LASTSAVE_BEFORE" ]; then
            break
        fi
        sleep 1
    done
    if [ -f "data/redis/dump.rdb" ]; then
        cp "data/redis/dump.rdb" "$BACKUP_DIR/redis_$DATE.rdb"
        log "Redis backup completed: redis_$DATE.rdb"
        chmod 600 "$BACKUP_DIR/redis_$DATE.rdb"
    else
        warning "Redis dump.rdb not found in data/redis/"
    fi
else
    warning "Redis backup command failed"
fi

# Backup secrets
log "Backing up secrets..."
if [ -d "secrets" ]; then
    if tar -czf "$BACKUP_DIR/secrets_$DATE.tar.gz" secrets/; then
        log "Secrets backup completed: secrets_$DATE.tar.gz"
        chmod 600 "$BACKUP_DIR/secrets_$DATE.tar.gz"
    else
        error "Secrets backup failed"
        exit 1
    fi
else
    warning "Secrets directory not found"
fi

# Backup configuration files
log "Backing up configuration files..."
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" \
    docker-compose.prod.yml \
    .env.production \
    docker/ \
    2>/dev/null || warning "Some configuration files not found"

if [ -f "$BACKUP_DIR/config_$DATE.tar.gz" ]; then
    log "Configuration backup completed: config_$DATE.tar.gz"
    chmod 600 "$BACKUP_DIR/config_$DATE.tar.gz"
fi

# Calculate backup size
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
log "Total backup size: $BACKUP_SIZE"

# Remove old backups
log "Cleaning up backups older than $RETENTION_DAYS days..."
DELETED_COUNT=0

# Delete old database backups
DELETED=$(find "$BACKUP_DIR" -name "postgres_*.sql.gz" -mtime +"$RETENTION_DAYS" -delete -print | wc -l)
DELETED_COUNT=$((DELETED_COUNT + DELETED))

# Delete old Redis backups
DELETED=$(find "$BACKUP_DIR" -name "redis_*.rdb" -mtime +"$RETENTION_DAYS" -delete -print | wc -l)
DELETED_COUNT=$((DELETED_COUNT + DELETED))

# Delete old secrets backups
DELETED=$(find "$BACKUP_DIR" -name "secrets_*.tar.gz" -mtime +"$RETENTION_DAYS" -delete -print | wc -l)
DELETED_COUNT=$((DELETED_COUNT + DELETED))

# Delete old config backups
DELETED=$(find "$BACKUP_DIR" -name "config_*.tar.gz" -mtime +"$RETENTION_DAYS" -delete -print | wc -l)
DELETED_COUNT=$((DELETED_COUNT + DELETED))

if [ $DELETED_COUNT -gt 0 ]; then
    log "Deleted $DELETED_COUNT old backup files"
else
    log "No old backups to delete"
fi

# List recent backups
log "Recent backups:"
# shellcheck disable=SC2012
ls -lht "$BACKUP_DIR" 2>/dev/null | head -6 | tail -5

# Upload to cloud storage if configured
if [ -n "$CLOUD_PROVIDER" ] && [ -n "$CLOUD_BUCKET" ]; then
    log "Uploading backup to cloud storage ($CLOUD_PROVIDER)..."

    # Build cloud backup command arguments
    # shellcheck disable=SC2086
    CLOUD_CMD="python3 $SCRIPT_DIR/cloud_backup.py upload --provider $CLOUD_PROVIDER --bucket $CLOUD_BUCKET --backup-dir $BACKUP_DIR"

    if [ -n "$GCP_PROJECT_ID" ]; then
        CLOUD_CMD="$CLOUD_CMD --project-id $GCP_PROJECT_ID"
    fi

    if [ "${CLOUD_AUTO_CREATE_BUCKET:-false}" = "true" ]; then
        CLOUD_CMD="$CLOUD_CMD --auto-create-bucket"
    fi

    CLOUD_CMD="$CLOUD_CMD --prefix backups/$DATE"

    # Execute cloud upload (word splitting is intentional here)
    # shellcheck disable=SC2086
    if $CLOUD_CMD; then
        log "Cloud upload completed successfully"
    else
        warning "Cloud upload failed - backup is still available locally"
    fi
else
    log "Cloud storage not configured - skipping upload"
    log "Set CLOUD_PROVIDER and CLOUD_BUCKET to enable cloud backups"
fi

log "Backup completed successfully!"
echo ""
echo "Backup location: $BACKUP_DIR"
echo "Backup date: $DATE"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "1. Test restore procedure regularly"
echo "2. Store backups off-site (S3, NAS, etc.)"
echo "3. Encrypt backups if storing remotely"
echo ""
