# Production Deployment Guide

This directory contains production-ready deployment configurations for AgentGate.

## Overview

AgentGate supports multiple deployment strategies:

1. **Docker Compose** - Simple production deployment on a single server
2. **Kubernetes (Helm)** - Scalable cloud-native deployment
3. **Manual** - Traditional server deployment

## Marketplace Baseline (Azure)

For Azure Marketplace deployment, use `cloud_strict` profile with external managed services:

- `AGENTGATE_RUNTIME_PROFILE=cloud_strict`
- `DATABASE_AUTH_MODE=entra_token`
- `AGENTGATE_Z3_MODE=enforce` (or `shadow`)
- `AZURE_KEY_VAULT_URL` must be set
- `DATABASE_URL` must be passwordless (Entra token auth)
- Run schema migrations and guardrails sync before workload startup

## Quick Start

### Docker Compose (Recommended for Single Server)

```bash
# Initialize production environment
make prod-init

# Or manually:
./scripts/init_production.sh
```

This script will:
- Generate secure passwords
- Create necessary directories
- Build Docker images
- Start PostgreSQL and Redis
- Run database migrations
- Start application services
- Perform health checks

### Kubernetes (Recommended for Cloud)

```bash
# Add Bitnami repository
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Install AgentGate
helm install agentgate ./deploy/helm/agentgate \
  --namespace agentgate \
  --create-namespace \
  -f values-production.yaml
```

See [helm/agentgate/README.md](helm/agentgate/README.md) for detailed instructions.

## Architecture

### Production Stack

```
┌─────────────────┐
│   Dashboard     │ (Next.js)
│   Port 3000     │
└────────┬────────┘
         │
┌────────┴────────┐
│   API Server    │ (FastAPI)
│   Port 8000     │
│   Metrics 9090  │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
┌───┴───┐ ┌──┴───┐
│ Redis │ │ PG15 │
│ 6379  │ │ 5432 │
└───────┘ └──────┘
```

### Components

- **PostgreSQL 15**: Primary database with connection pooling
- **Redis 7**: Rate limiting and caching
- **FastAPI Server**: API backend (3-10 replicas with HPA)
- **Next.js Dashboard**: Web interface
- **Nginx Ingress**: Load balancer and TLS termination

## Database Migrations

### Creating Migrations

```bash
# Create a new migration
make migrate-create MESSAGE="Add new feature"

# Or manually:
alembic revision --autogenerate -m "Your message"
```

### Applying Migrations

```bash
# Apply all pending migrations
make migrate-up

# Or manually:
alembic upgrade head
```

### Rollback

```bash
# Rollback last migration
make migrate-down

# Or manually:
alembic downgrade -1
```

### View History

```bash
# View migration history
make migrate-history

# View current version
make migrate-current
```

## Configuration

### Environment Variables

Create `.env.production` from `.env.production.example`:

```bash
cp .env.production.example .env.production
```

#### Critical Variables

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string with password
- `SECRET_KEY`: Application secret (generate with `openssl rand -hex 32`)
- `NEXTAUTH_SECRET`: NextAuth secret
- `POSTGRES_PASSWORD`: PostgreSQL password
- `REDIS_PASSWORD`: Redis password

#### Database Pool Configuration

- `DATABASE_POOL_SIZE=20`: Base connection pool size
- `DATABASE_MAX_OVERFLOW=40`: Additional connections under load
- `DATABASE_POOL_TIMEOUT=30`: Connection wait timeout (seconds)
- `DATABASE_POOL_RECYCLE=3600`: Recycle connections after 1 hour

#### Server Configuration

- `UVICORN_WORKERS=4`: Number of worker processes
- `LOG_LEVEL=info`: Logging level (debug, info, warning, error)
- `LOG_FORMAT=json`: Log format (json or text)

### Scaling Configuration

#### Docker Compose

Edit `docker-compose.production.yml`:

```yaml
server:
  deploy:
    replicas: 3  # Number of instances
```

#### Kubernetes

Edit Helm values:

```yaml
server:
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80
```

## Monitoring

### Metrics

Prometheus metrics are exposed on port 9090:

```bash
curl http://localhost:9090/metrics
```

### Health Checks

```bash
# Server health
curl http://localhost:8000/api/health

# Database health
docker-compose -f docker-compose.production.yml exec postgres pg_isready

# Redis health
docker-compose -f docker-compose.production.yml exec redis redis-cli ping
```

### Logs

```bash
# View all logs
make prod-logs

# View specific service logs
docker-compose -f docker-compose.production.yml logs -f server
docker-compose -f docker-compose.production.yml logs -f postgres
docker-compose -f docker-compose.production.yml logs -f redis
```

## Backup and Recovery

### Database Backup

```bash
# Backup PostgreSQL
docker-compose -f docker-compose.production.yml exec postgres \
  pg_dump -U agentgate agentgate > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore from backup
cat backup_20250210_120000.sql | docker-compose -f docker-compose.production.yml exec -T postgres \
  psql -U agentgate agentgate
```

### Redis Backup

```bash
# Redis uses AOF persistence by default
# Backup Redis data
docker-compose -f docker-compose.production.yml exec redis redis-cli BGSAVE

# Copy dump file
docker cp agentgate-redis:/data/dump.rdb ./redis_backup_$(date +%Y%m%d_%H%M%S).rdb
```

## Security

### TLS/SSL Configuration

#### Docker Compose

Use a reverse proxy (nginx, Caddy, Traefik) for TLS termination.

#### Kubernetes

TLS is configured via cert-manager and Ingress:

```yaml
ingress:
  enabled: true
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  tls:
    - secretName: agentgate-tls
      hosts:
        - agentgate.example.com
```

### Secrets Management

#### Docker Compose

Store secrets in `.env.production`:

```bash
# Generate secure passwords
openssl rand -hex 32
```

#### Kubernetes

Use Kubernetes Secrets or external-secrets operator:

```bash
kubectl create secret generic agentgate-credentials \
  --from-literal=postgres-password=$(openssl rand -hex 32) \
  --from-literal=redis-password=$(openssl rand -hex 32) \
  --from-literal=secret-key=$(openssl rand -hex 32) \
  -n agentgate
```

## Performance Tuning

### Database

Edit `docker-compose.production.yml`:

```yaml
postgres:
  environment:
    POSTGRES_SHARED_BUFFERS: 256MB
    POSTGRES_EFFECTIVE_CACHE_SIZE: 1GB
    POSTGRES_MAX_CONNECTIONS: 100
```

### Redis

```yaml
redis:
  command: >
    redis-server
    --maxmemory 256mb
    --maxmemory-policy allkeys-lru
```

### Application

```yaml
server:
  environment:
    DATABASE_POOL_SIZE: 20
    DATABASE_MAX_OVERFLOW: 40
    UVICORN_WORKERS: 4
```

## Troubleshooting

### Database Connection Issues

```bash
# Check database logs
docker-compose -f docker-compose.production.yml logs postgres

# Test connection
docker-compose -f docker-compose.production.yml exec postgres \
  psql -U agentgate -d agentgate -c "SELECT 1;"
```

### Migration Failures

```bash
# Check migration status
alembic current

# View migration history
alembic history

# Manually fix issues and retry
alembic upgrade head
```

### Server Startup Issues

```bash
# Check server logs
docker-compose -f docker-compose.production.yml logs server

# Check environment variables
docker-compose -f docker-compose.production.yml exec server env | grep DATABASE
```

### High Memory Usage

```bash
# Check resource usage
docker stats

# Reduce pool size
# Edit .env.production:
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20
```

## Maintenance

### Updates

```bash
# Pull latest images
docker-compose -f docker-compose.production.yml pull

# Rebuild with updates
docker-compose -f docker-compose.production.yml build --no-cache

# Restart services
docker-compose -f docker-compose.production.yml up -d
```

### Cleanup

```bash
# Remove old images
docker image prune -a

# Remove old volumes (CAUTION: This deletes data!)
docker volume prune
```

## High Availability

### Multi-Node Setup (Kubernetes)

The Helm chart supports:
- Horizontal Pod Autoscaling (HPA)
- Pod Disruption Budgets (PDB)
- Rolling updates with zero downtime
- Multi-replica deployment

### Database Replication

For PostgreSQL HA, consider:
- Patroni + etcd for automatic failover
- Stolon for PostgreSQL cluster management
- Cloud-managed PostgreSQL (RDS, Cloud SQL, Azure Database)

### Redis Clustering

For Redis HA:
- Redis Sentinel for failover
- Redis Cluster for sharding
- Cloud-managed Redis (ElastiCache, MemoryStore)

## Production Checklist

- [ ] Generated secure passwords for all services
- [ ] Configured DATABASE_URL with PostgreSQL
- [ ] Configured REDIS_URL with password
- [ ] Set SECRET_KEY and NEXTAUTH_SECRET
- [ ] Configured allowed origins (CORS)
- [ ] Set up TLS/SSL certificates
- [ ] Configured backup strategy
- [ ] Enabled monitoring (Prometheus/Grafana)
- [ ] Configured log aggregation
- [ ] Set up alerting
- [ ] Performed load testing
- [ ] Documented disaster recovery plan
- [ ] Configured rate limiting
- [ ] Enabled security headers
- [ ] Set up WAF (if applicable)

## Support

For issues and questions:
- GitHub: https://github.com/EaCognitive/agentgate/issues
- Documentation: https://github.com/EaCognitive/agentgate
