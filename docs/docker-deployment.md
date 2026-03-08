# AgentGate Docker Production Deployment Guide

This guide covers deploying AgentGate in production using Docker with enterprise-grade security and reliability practices.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Production Setup](#production-setup)
- [Security Configuration](#security-configuration)
- [Monitoring and Maintenance](#monitoring-and-maintenance)
- [Backup and Disaster Recovery](#backup-and-disaster-recovery)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- Docker Engine 24.0+ with Docker Compose v2
- Minimum 4GB RAM, 2 CPU cores
- 20GB free disk space
- Linux host (Ubuntu 22.04 LTS recommended) or Docker Desktop
- Domain name with SSL certificate (production)

### Software Dependencies

```bash
# Install Docker (Ubuntu/Debian)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose v2
sudo apt-get update
sudo apt-get install docker-compose-plugin

# Verify installation
docker --version
docker compose version
```

## Quick Start

For the local portfolio stack:

```bash
# Clone repository
git clone https://github.com/EaCognitive/agentgate.git
cd agentgate

# Create .env file
cp .env.example .env
# Edit .env and set required values

# Start the production-like local stack
./run demo --fresh

# View logs
./run logs

# Access dashboard and docs
open http://localhost:3000
open http://localhost:3000/docs
```

### First-Run Reset (Development/Test Only)

To validate onboarding from a clean state, remove all compose volumes and rebuild:

```bash
docker compose down --volumes --remove-orphans
docker compose up -d --build
curl http://127.0.0.1:8000/api/setup/status
curl http://127.0.0.1:3000/api/setup/status
```

Verify both status responses show:
- `setup_required: true`
- `user_count: 0`

Do not run this reset flow in production.

## Production Setup

### 1. Prepare Environment

```bash
# Create production directories
mkdir -p data/{postgres,redis} secrets docker/nginx/ssl

# Set proper permissions
chmod 700 data/ secrets/
```

### 2. Generate Secrets

```bash
# Generate strong passwords and keys
./scripts/generate_secrets.sh

# Or manually:
openssl rand -hex 32 > secrets/api_secret_key.txt
openssl rand -hex 32 > secrets/nextauth_secret.txt
openssl rand -base64 32 > secrets/db_password.txt

# Set proper permissions
chmod 600 secrets/*.txt
```

### 3. Configure Environment

```bash
# Copy production environment template
cp .env.production.example .env.production

# Edit configuration
nano .env.production
```

Required configuration:

```env
# Database
POSTGRES_PASSWORD=<from secrets/db_password.txt>

# Redis
REDIS_PASSWORD=<strong-password>

# Application
SECRET_KEY=<from secrets/api_secret_key.txt>
NEXTAUTH_SECRET=<from secrets/nextauth_secret.txt>

# Domains (update with your actual domain)
ALLOWED_ORIGINS=https://yourdomain.com
NEXTAUTH_URL=https://yourdomain.com
NEXT_PUBLIC_API_URL=https://yourdomain.com/api
```

### 4. SSL Certificates

#### Option A: Let's Encrypt (Recommended)

```bash
# Install certbot
sudo apt-get install certbot

# Generate certificate
sudo certbot certonly --standalone -d yourdomain.com

# Copy to Docker volume
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem docker/nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem docker/nginx/ssl/key.pem
sudo chmod 644 docker/nginx/ssl/cert.pem
sudo chmod 600 docker/nginx/ssl/key.pem

# Set up auto-renewal
sudo certbot renew --dry-run
```

#### Option B: Self-Signed (Development Only)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout docker/nginx/ssl/key.pem \
  -out docker/nginx/ssl/cert.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

### 5. Build and Deploy

```bash
# Build images
docker compose -f docker-compose.prod.yml build

# Start services
docker compose -f docker-compose.prod.yml up -d

# Verify health
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs -f

# Check health endpoints
curl http://localhost:8000/api/health
curl http://localhost:3000/
```

### 6. Initialize Database

```bash
# Run database migrations (if applicable)
docker compose -f docker-compose.prod.yml exec server python -m alembic upgrade head

# Create admin user
docker compose -f docker-compose.prod.yml exec server python -m server.cli create-admin
```

## Security Configuration

### Security Checklist

- [ ] Strong unique passwords for all services
- [ ] Secrets stored in files, not environment variables
- [ ] SSL/TLS certificates configured
- [ ] Firewall rules configured (only 80/443 public)
- [ ] Non-root users in all containers
- [ ] Read-only root filesystems where possible
- [ ] Resource limits configured
- [ ] Security headers enabled
- [ ] Rate limiting enabled
- [ ] Regular security updates

### Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Block direct database access from outside
sudo ufw deny 5432/tcp
sudo ufw deny 6379/tcp
```

### Docker Security

```bash
# Enable Docker content trust
export DOCKER_CONTENT_TRUST=1

# Scan images for vulnerabilities
docker scan agentgate-server:latest
docker scan agentgate-dashboard:latest
```

### Network Isolation

The production setup uses two networks:

- **frontend**: Public-facing services (nginx, dashboard, server)
- **backend**: Internal services only (database, redis)

Database and Redis are not exposed to the public internet.

## Monitoring and Maintenance

### Health Checks

```bash
# Check all services
docker compose -f docker-compose.prod.yml ps

# Test health endpoints
curl -f http://localhost/health || echo "Nginx failed"
curl -f http://localhost:8000/api/health || echo "API failed"
curl -f http://localhost:3000/ || echo "Dashboard failed"
```

### Log Management

```bash
# View logs
docker compose -f docker-compose.prod.yml logs -f

# View specific service
docker compose -f docker-compose.prod.yml logs -f server

# Export logs
docker compose -f docker-compose.prod.yml logs --no-color > logs/agentgate.log
```

### Resource Monitoring

```bash
# View resource usage
docker stats

# Check disk usage
docker system df
docker volume ls

# Clean up unused resources
docker system prune -a --volumes
```

### Updates and Maintenance

```bash
# Pull latest images
docker compose -f docker-compose.prod.yml pull

# Rebuild with new code
git pull
docker compose -f docker-compose.prod.yml build

# Rolling update (zero downtime)
docker compose -f docker-compose.prod.yml up -d --no-deps --build server
docker compose -f docker-compose.prod.yml up -d --no-deps --build dashboard

# Restart all services
docker compose -f docker-compose.prod.yml restart
```

## Backup and Disaster Recovery

### Automated Backup Script

Create `/usr/local/bin/backup-agentgate.sh`:

```bash
#!/bin/bash
set -e

BACKUP_DIR="/var/backups/agentgate"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup PostgreSQL
docker compose -f docker-compose.prod.yml exec -T db \
  pg_dump -U agentgate agentgate | gzip > "$BACKUP_DIR/postgres_$DATE.sql.gz"

# Backup Redis
docker compose -f docker-compose.prod.yml exec -T redis \
  redis-cli --rdb /data/dump.rdb
cp data/redis/dump.rdb "$BACKUP_DIR/redis_$DATE.rdb"

# Backup secrets
tar -czf "$BACKUP_DIR/secrets_$DATE.tar.gz" secrets/

# Remove old backups
find "$BACKUP_DIR" -name "*.gz" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "*.rdb" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $DATE"
```

### Schedule Backups

```bash
# Make script executable
sudo chmod +x /usr/local/bin/backup-agentgate.sh

# Add to crontab (daily at 2 AM)
sudo crontab -e
# Add line:
0 2 * * * /usr/local/bin/backup-agentgate.sh >> /var/log/agentgate-backup.log 2>&1
```

### Restore from Backup

```bash
# Stop services
docker compose -f docker-compose.prod.yml down

# Restore PostgreSQL
gunzip < /var/backups/agentgate/postgres_20250128_020000.sql.gz | \
  docker compose -f docker-compose.prod.yml exec -T db \
  psql -U agentgate agentgate

# Restore Redis
cp /var/backups/agentgate/redis_20250128_020000.rdb data/redis/dump.rdb

# Restore secrets
tar -xzf /var/backups/agentgate/secrets_20250128_020000.tar.gz

# Start services
docker compose -f docker-compose.prod.yml up -d
```

## Troubleshooting

### Common Issues

#### Database Connection Errors

```bash
# Check if database is healthy
docker compose -f docker-compose.prod.yml exec db pg_isready

# Check logs
docker compose -f docker-compose.prod.yml logs db

# Verify password
docker compose -f docker-compose.prod.yml exec db psql -U agentgate
```

#### Redis Connection Errors

```bash
# Test Redis connection
docker compose -f docker-compose.prod.yml exec redis redis-cli ping

# Check authentication
docker compose -f docker-compose.prod.yml exec redis redis-cli -a $REDIS_PASSWORD ping
```

#### High Memory Usage

```bash
# Check container stats
docker stats

# Adjust resource limits in docker-compose.prod.yml
# Restart affected services
docker compose -f docker-compose.prod.yml restart
```

#### SSL Certificate Issues

```bash
# Verify certificate
openssl x509 -in docker/nginx/ssl/cert.pem -text -noout

# Test SSL configuration
docker compose -f docker-compose.prod.yml exec nginx nginx -t

# Reload nginx
docker compose -f docker-compose.prod.yml exec nginx nginx -s reload
```

### Performance Optimization

#### Database

```sql
-- Check slow queries
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements
ORDER BY mean_time DESC LIMIT 10;

-- Check indexes
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
WHERE idx_scan = 0;
```

#### Redis

```bash
# Check memory usage
docker compose -f docker-compose.prod.yml exec redis redis-cli info memory

# Check slow log
docker compose -f docker-compose.prod.yml exec redis redis-cli slowlog get 10
```

### Getting Help

- GitHub Issues: https://github.com/EaCognitive/agentgate/issues
- Documentation: https://github.com/EaCognitive/agentgate#readme
- Security Issues: security@agentgate.dev (private disclosure)

## Production Checklist

Before going to production, verify:

- [ ] All secrets are strong and unique
- [ ] SSL certificates are valid and auto-renewing
- [ ] Firewall rules are configured
- [ ] Backups are automated and tested
- [ ] Monitoring is set up
- [ ] Resource limits are appropriate
- [ ] Logs are being rotated
- [ ] Security headers are enabled
- [ ] Rate limiting is configured
- [ ] Admin users are created securely
- [ ] Domain DNS is configured correctly
- [ ] Health checks are passing
- [ ] Documentation is updated

## Additional Resources

- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [PostgreSQL Performance Tuning](https://wiki.postgresql.org/wiki/Performance_Optimization)
- [Redis Security](https://redis.io/docs/management/security/)
- [Nginx Configuration](https://nginx.org/en/docs/)
