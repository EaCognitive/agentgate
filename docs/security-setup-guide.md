# AgentGate Security Setup Guide

This guide contains critical security setup steps that MUST be completed before deploying to production.

## CRITICAL: Before Deployment

### 1. Generate Secure Secrets

Generate a strong SECRET_KEY for JWT signing:

```bash
# Generate SECRET_KEY (use this value in your .env file)
openssl rand -hex 32
```

### 2. Configure Environment Variables

Create `server/.env` from the example for development only:

```bash
cd server
cp .env.example .env
```

Edit `server/.env` and set development defaults:

```env
# Use the key generated above
SECRET_KEY=<your-generated-secret-key-here>

# Database
DATABASE_URL=postgresql://user:password@host:5432/agentgate

# CORS origins
ALLOWED_ORIGINS=https://yourdashboard.com

# Environment
AGENTGATE_ENV=development
```

### 3. Use Azure Key Vault in Production (Fail Closed)

In production (`AGENTGATE_ENV=production`), AgentGate reads secrets
from **Azure Key Vault** and fails closed if the vault is
unreachable. Configure:

- Set `AZURE_KEY_VAULT_URL` in the environment
  (e.g., `https://your-vault.vault.azure.net`).
- Create Key Vault secrets named after required variables
  (e.g., `SECRET-KEY`, `DATABASE-URL`, `ALLOWED-ORIGINS`,
  `DEFAULT-ADMIN-EMAIL`, `DEFAULT-ADMIN-PASSWORD`).
- Authentication uses `DefaultAzureCredential` -- on Azure
  infrastructure use Managed Identity, locally use `az login`
  or a service principal (`AZURE_TENANT_ID`,
  `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`).
- Do **not** ship `.env` files to production. The server will
  not start without Azure Key Vault when
  `AGENTGATE_ENV=production`.

### 3. Never Commit Secrets

Verify .env files are in .gitignore:

```bash
# Check .gitignore
grep -E "^\.env$|^server/\.env$" .gitignore

# If .env is already committed, remove it:
git rm --cached server/.env
git commit -m "Remove .env from version control"
```

### 4. Set Up TLS/HTTPS

Configure reverse proxy (nginx example):

```nginx
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name api.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

### 5. Enable Rate Limiting (REQUIRED)

Install rate limiting library:

```bash
pip install slowapi
```

The security headers middleware (added in this review) includes rate limiting configuration.

### 6. Container Security

Build containers with non-root user:

```bash
# Build server with non-root user
docker-compose build server

# Verify non-root user
docker-compose run server id
# Should show: uid=1000(agentgate) gid=1000(agentgate)
```

### 7. Database Security

Use strong passwords for PostgreSQL:

```bash
# Generate database password
openssl rand -base64 32
```

Update docker-compose.yml or production database configuration with secure credentials.

### 8. Production Checklist

Before going live, verify:

- [ ] SECRET_KEY is randomly generated (not the default)
- [ ] .env file is not in version control
- [ ] Database uses strong passwords
- [ ] HTTPS/TLS is configured
- [ ] ALLOWED_ORIGINS is set to production domains only
- [ ] DEFAULT_ADMIN_PASSWORD is strong (or admin created manually)
- [ ] Rate limiting is enabled
- [ ] Security headers are configured
- [ ] All containers run as non-root users
- [ ] Health checks are configured
- [ ] Log aggregation is set up
- [ ] Monitoring/alerting is configured
- [ ] Backup/disaster recovery plan is documented

## Security Maintenance

### Regular Tasks:

1. **Rotate SECRET_KEY** (recommended every 90 days):
   ```bash
   openssl rand -hex 32
   # Update .env and restart services
   ```

2. **Update dependencies** (monthly):
   ```bash
   pip list --outdated
   npm outdated
   ```

3. **Review audit logs** (weekly):
   ```bash
   # Check for suspicious activity
   docker-compose exec server python -m ea_agentgate.security.audit --export
   ```

4. **Security scanning** (weekly):
   ```bash
   # Dependency vulnerabilities
   pip-audit

   # Container scanning
   trivy image agentgate-server:latest
   ```

## Incident Response

If you suspect a security breach:

1. **Immediately rotate all secrets**:
   - SECRET_KEY
   - Database passwords
   - API keys
   - Admin passwords

2. **Review audit logs**:
   ```bash
   # Export logs for forensic analysis
   curl -X GET "http://localhost:8000/api/audit/export?format=json" \
        -H "Authorization: Bearer <admin-token>" \
        > incident-$(date +%Y%m%d-%H%M%S).json
   ```

3. **Disable compromised accounts**

4. **Notify affected users** (if applicable)

5. **Conduct post-incident review**

## Support

For security issues:
- Report vulnerabilities via GitHub Security Advisories
- Do not disclose security issues publicly

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
