# AgentGate Docker Configuration

This directory contains production-ready Docker configurations for AgentGate.

## Directory Structure

```
docker/
├── README.md                    # This file
├── nginx/
│   ├── nginx.conf              # Main Nginx configuration
│   ├── conf.d/
│   │   └── agentgate.conf        # Virtual host configuration
│   └── ssl/                    # SSL certificates (not in git)
│       ├── cert.pem           # SSL certificate
│       └── key.pem            # SSL private key
├── postgres/
│   ├── postgresql.conf        # PostgreSQL performance tuning
│   └── init/                  # Database initialization scripts
└── redis/
    └── redis.conf             # Redis configuration
```

## Quick Reference

### Nginx Configuration

- **Main config**: `nginx/nginx.conf` - Worker processes, logging, gzip
- **Virtual host**: `nginx/conf.d/agentgate.conf` - Routing, SSL, security headers
- **SSL certs**: `nginx/ssl/` - Place your SSL certificates here

Key features:
- HTTP to HTTPS redirect
- Modern TLS configuration (TLS 1.2+)
- Security headers (HSTS, CSP, etc.)
- Rate limiting
- Gzip compression
- Static asset caching

### PostgreSQL Configuration

- **Config**: `postgres/postgresql.conf`
- **Init scripts**: `postgres/init/` (optional)

Optimizations:
- Shared buffers: 256MB
- Effective cache: 1GB
- Max connections: 100
- WAL configuration for reliability
- Query logging for slow queries (>1s)

### Redis Configuration

- **Config**: `redis/redis.conf`

Features:
- AOF persistence enabled
- LRU eviction policy
- 256MB memory limit
- Slow query logging
- Connection security

## SSL Certificate Setup

### Production (Let's Encrypt)

```bash
# Install certbot
sudo apt-get install certbot

# Generate certificate
sudo certbot certonly --standalone -d yourdomain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem nginx/ssl/key.pem
sudo chmod 644 nginx/ssl/cert.pem
sudo chmod 600 nginx/ssl/key.pem
```

### Development (Self-Signed)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/CN=localhost"
```

## Configuration Tuning

### Adjust for Your Workload

#### High Traffic (>1000 req/s)

```yaml
# docker-compose.prod.yml
deploy:
  replicas: 4
  resources:
    limits:
      cpus: '8.0'
      memory: 4G
```

#### Memory-Constrained (< 4GB RAM)

Reduce limits in `docker-compose.prod.yml`:
- PostgreSQL: 512M shared_buffers, 1G memory limit
- Redis: 128M max memory
- Server: 2 workers, 512M memory limit

#### Database-Heavy Workload

Update `postgres/postgresql.conf`:
```
shared_buffers = 512MB
effective_cache_size = 2GB
work_mem = 8MB
```

## Security Notes

1. **Never commit**:
   - SSL private keys (`nginx/ssl/*.key`)
   - Environment files (`.env.production`)
   - Secrets directory

2. **File permissions**:
   ```bash
   chmod 644 nginx/ssl/cert.pem
   chmod 600 nginx/ssl/key.pem
   chmod 600 postgres/postgresql.conf
   chmod 600 redis/redis.conf
   ```

3. **Update security headers** in `nginx/conf.d/agentgate.conf`:
   - Adjust CSP for your needs
   - Add additional security headers if needed

4. **Rate limiting**: Adjust zones in `nginx/nginx.conf` based on your traffic:
   ```nginx
   limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/s;
   ```

## Monitoring

### Check Nginx Status

```bash
docker compose exec nginx nginx -t  # Test configuration
docker compose exec nginx nginx -s reload  # Reload config
```

### Check PostgreSQL Performance

```bash
docker compose exec db psql -U agentgate -d agentgate
```

```sql
-- Check slow queries
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements
ORDER BY mean_time DESC LIMIT 10;

-- Check database size
SELECT pg_database.datname, pg_size_pretty(pg_database_size(pg_database.datname))
FROM pg_database;
```

### Check Redis Statistics

```bash
docker compose exec redis redis-cli INFO
docker compose exec redis redis-cli SLOWLOG GET 10
```

## Troubleshooting

### Nginx Won't Start

```bash
# Test configuration
docker compose exec nginx nginx -t

# Check logs
docker compose logs nginx

# Common issues:
# - SSL certificate not found
# - Port already in use
# - Configuration syntax error
```

### Database Connection Issues

```bash
# Test connection
docker compose exec db pg_isready

# Check logs
docker compose logs db

# Verify credentials
docker compose exec db psql -U agentgate
```

### Redis Connection Issues

```bash
# Test connection
docker compose exec redis redis-cli PING

# Check authentication
docker compose exec redis redis-cli -a $REDIS_PASSWORD PING
```

## Additional Resources

- [Nginx Documentation](https://nginx.org/en/docs/)
- [PostgreSQL Tuning Guide](https://wiki.postgresql.org/wiki/Tuning_Your_PostgreSQL_Server)
- [Redis Configuration](https://redis.io/docs/management/config/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
