#!/bin/bash
# AgentGate Health Check Script
# Verifies all services are healthy and accessible

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Counters
PASSED=0
FAILED=0

# Functions
check() {
    local name=$1
    local command=$2
    
    echo -n "Checking $name... "
    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ OK${NC}"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

check_url() {
    local name=$1
    local url=$2
    local expected_status=${3:-200}
    
    echo -n "Checking $name... "
    status=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    if [ "$status" = "$expected_status" ]; then
        echo -e "${GREEN}✓ OK${NC} (HTTP $status)"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC} (HTTP $status, expected $expected_status)"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

cd "$PROJECT_ROOT"

echo "=========================================="
echo "AgentGate Health Check"
echo "=========================================="
echo ""

# Check Docker
echo "Docker Status:"
check "Docker daemon" "docker info"
check "Docker Compose" "docker compose version"
echo ""

# Check if services are running
echo "Service Status:"
check "Services running" "docker compose -f $COMPOSE_FILE ps | grep -q 'Up'"

if docker compose -f "$COMPOSE_FILE" ps > /dev/null 2>&1; then
    echo ""
    docker compose -f "$COMPOSE_FILE" ps
    echo ""
fi

# Check container health
echo "Container Health:"
for container in db redis server dashboard; do
    check "$container container" "docker compose -f $COMPOSE_FILE ps $container | grep -q 'healthy\|Up'"
done
echo ""

# Check network connectivity
echo "Network Connectivity:"
check "Database port" "docker compose -f $COMPOSE_FILE exec -T server nc -zv db 5432"
check "Redis port" "docker compose -f $COMPOSE_FILE exec -T server nc -zv redis 6379"
echo ""

# Check HTTP endpoints
echo "HTTP Endpoints:"
check_url "API health" "http://localhost:8000/api/health" 200
check_url "Dashboard" "http://localhost:3000/" 200

if [ -f "docker/nginx/nginx.conf" ]; then
    check_url "Nginx health" "http://localhost/health" 200
fi
echo ""

# Check database
echo "Database:"
check "PostgreSQL connection" "docker compose -f $COMPOSE_FILE exec -T db psql -U agentgate -d agentgate -c 'SELECT 1'"
check "Database tables" "docker compose -f $COMPOSE_FILE exec -T db psql -U agentgate -d agentgate -c '\dt'"
echo ""

# Check Redis
echo "Redis:"
check "Redis PING" "docker compose -f $COMPOSE_FILE exec -T redis redis-cli PING | grep -q PONG"
check "Redis persistence" "docker compose -f $COMPOSE_FILE exec -T redis redis-cli CONFIG GET appendonly | grep -q yes"
echo ""

# Check disk space
echo "Disk Space:"
check "Root partition (>10% free)" "[ $(df / | tail -1 | awk '{print $5}' | sed 's/%//') -lt 90 ]"
if [ -d "data/postgres" ]; then
    check "PostgreSQL volume" "[ -d data/postgres ]"
fi
if [ -d "data/redis" ]; then
    check "Redis volume" "[ -d data/redis ]"
fi
echo ""

# Check resource usage
echo "Resource Usage:"
echo "Container resources:"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" | head -5
echo ""

# Security checks
echo "Security:"
check "Secrets directory permissions" "[ $(stat -f '%A' secrets 2>/dev/null || stat -c '%a' secrets 2>/dev/null) = '700' ]"
check "No root containers" "! docker compose -f $COMPOSE_FILE exec -T server whoami | grep -q root"
echo ""

# Summary
echo "=========================================="
echo "Summary"
echo "=========================================="
echo -e "${GREEN}Passed: $PASSED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED${NC}"
    echo ""
    echo "Some health checks failed. Please review the output above."
    exit 1
else
    echo -e "${GREEN}All health checks passed!${NC}"
    exit 0
fi
