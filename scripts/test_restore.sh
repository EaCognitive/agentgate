#!/bin/bash
# AgentGate Restore Test Script
# Validates backup artifacts and optionally runs verification checks.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/var/backups/agentgate}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERIFY_SCRIPT="$SCRIPT_DIR/verify_backup.py"

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

usage() {
    echo "Usage: $0 <backup_date> [component]"
    echo ""
    echo "Examples:"
    echo "  $0 20250128_020000              # Validate all backup artifacts"
    echo "  $0 20250128_020000 postgres     # Validate PostgreSQL backup only"
    echo "  $0 20250128_020000 redis        # Validate Redis backup only"
    echo "  $0 20250128_020000 secrets      # Validate secrets backup only"
    echo ""
}

if [ $# -lt 1 ]; then
    usage
    exit 1
fi

BACKUP_DATE="$1"
COMPONENT="${2:-all}"

cd "$PROJECT_ROOT"

log "Testing restore artifacts for backup date: $BACKUP_DATE (component: $COMPONENT)"

check_file() {
    local file_path="$1"
    if [ ! -f "$file_path" ]; then
        error "Missing backup artifact: $file_path"
        return 1
    fi
    log "Found backup artifact: $file_path"
    return 0
}

case "$COMPONENT" in
    all|postgres)
        check_file "$BACKUP_DIR/postgres_${BACKUP_DATE}.sql.gz"
        ;;
esac

case "$COMPONENT" in
    all|redis)
        if [ -f "$BACKUP_DIR/redis_${BACKUP_DATE}.rdb" ]; then
            log "Found Redis backup: redis_${BACKUP_DATE}.rdb"
        else
            log "Redis backup not found (optional): redis_${BACKUP_DATE}.rdb"
        fi
        ;;
esac

case "$COMPONENT" in
    all|secrets)
        if [ -f "$BACKUP_DIR/secrets_${BACKUP_DATE}.tar.gz" ]; then
            log "Found secrets backup: secrets_${BACKUP_DATE}.tar.gz"
        else
            log "Secrets backup not found (optional): secrets_${BACKUP_DATE}.tar.gz"
        fi
        ;;
esac

case "$COMPONENT" in
    all)
        if [ -f "$BACKUP_DIR/config_${BACKUP_DATE}.tar.gz" ]; then
            log "Found config backup: config_${BACKUP_DATE}.tar.gz"
        else
            log "Config backup not found (optional): config_${BACKUP_DATE}.tar.gz"
        fi
        ;;
esac

# Optional database integrity verification if DATABASE_URL is available
if [ -x "$VERIFY_SCRIPT" ] && [ -n "${DATABASE_URL:-}" ]; then
    log "Running database verification against DATABASE_URL"
    "$VERIFY_SCRIPT" --database-url "$DATABASE_URL"
else
    log "Skipping database verification (DATABASE_URL not set or verifier missing)"
fi

log "Restore artifact checks complete."
