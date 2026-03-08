# TLS/HTTPS Setup Guide for AgentGate

This guide walks you through setting up TLS/HTTPS for production deployment.

## Prerequisites

- Ubuntu/Debian server with root access
- Domain names pointed to your server:
  - `api.yourdomain.com` → API server
  - `dashboard.yourdomain.com` → Dashboard
- Ports 80 and 443 open in firewall

## Option 1: Let's Encrypt (Recommended - Free)

### Step 1: Install Certbot

```bash
sudo apt update
sudo apt install certbot python3-certbot-nginx -y
```

### Step 2: Obtain Certificates

```bash
# For API domain
sudo certbot certonly --nginx -d api.yourdomain.com

# For Dashboard domain
sudo certbot certonly --nginx -d dashboard.yourdomain.com
```

### Step 3: Install Nginx

```bash
sudo apt install nginx -y
sudo systemctl enable nginx
sudo systemctl start nginx
```

### Step 4: Configure Nginx

```bash
# Copy example configuration
sudo cp nginx.conf.example /etc/nginx/sites-available/agentgate

# Update domain names
sudo nano /etc/nginx/sites-available/agentgate
# Replace yourdomain.com with your actual domain

# Enable site
sudo ln -s /etc/nginx/sites-available/agentgate /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default  # Remove default site

# Test configuration
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

### Step 5: Set Up Auto-Renewal

```bash
# Test renewal
sudo certbot renew --dry-run

# Certbot automatically sets up a cron job for renewal
# Verify it's scheduled:
sudo systemctl list-timers | grep certbot
```

## Option 2: Self-Signed Certificate (Development Only)

**WARNING:** Only use for development/testing, never in production!

```bash
# Generate self-signed certificate
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/agentgate-selfsigned.key \
  -out /etc/ssl/certs/agentgate-selfsigned.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Update nginx configuration to use these certificates
# Replace in nginx.conf.example:
#   ssl_certificate /etc/ssl/certs/agentgate-selfsigned.crt;
#   ssl_certificate_key /etc/ssl/private/agentgate-selfsigned.key;
```

## Option 3: Commercial Certificate (Paid)

If you have a certificate from a commercial CA (DigiCert, Sectigo, etc.):

```bash
# Copy certificate files to server
sudo cp fullchain.pem /etc/ssl/certs/agentgate.crt
sudo cp privkey.pem /etc/ssl/private/agentgate.key
sudo chmod 600 /etc/ssl/private/agentgate.key

# Update nginx.conf.example with your certificate paths
```

## Docker Compose with Nginx

If you want to run Nginx in Docker with AgentGate:

### docker-compose.nginx.yml

```yaml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf.example:/etc/nginx/nginx.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - /var/www/certbot:/var/www/certbot:ro
    depends_on:
      - server
      - dashboard
    restart: unless-stopped

  certbot:
    image: certbot/certbot
    volumes:
      - /etc/letsencrypt:/etc/letsencrypt
      - /var/www/certbot:/var/www/certbot
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew; sleep 12h & wait $${!}; done;'"

  # Your existing services
  db:
    # ... (from docker-compose.yml)

  server:
    # ... (from docker-compose.yml)
    # Remove ports exposure if behind nginx
    # ports:
    #   - "8000:8000"

  dashboard:
    # ... (from docker-compose.yml)
    # Remove ports exposure if behind nginx
    # ports:
    #   - "3000:3000"
```

## Verification

### Test HTTPS

```bash
# Check certificate
curl -vI https://api.yourdomain.com/api/health

# Test SSL configuration
openssl s_client -connect api.yourdomain.com:443 -servername api.yourdomain.com
```

### SSL Labs Test

Visit https://www.ssllabs.com/ssltest/ and enter your domain to get a security rating.

**Target Rating:** A or A+

### Check HSTS

```bash
curl -I https://api.yourdomain.com | grep -i strict-transport-security
# Should show: Strict-Transport-Security: max-age=63072000; includeSubDomains
```

## Environment Variables Update

After setting up TLS, update your `.env` file:

```bash
# Update CORS origins to use HTTPS
ALLOWED_ORIGINS=https://dashboard.yourdomain.com

# Update dashboard environment
NEXTAUTH_URL=https://dashboard.yourdomain.com
API_URL=https://api.yourdomain.com

# Enable HSTS in production
AGENTGATE_ENV=production
```

## Security Best Practices

1. **Always use TLS 1.2 or higher** (configured in nginx.conf.example)
2. **Enable HSTS** with long max-age (2 years recommended)
3. **Use strong ciphers** (modern configuration in example)
4. **Enable OCSP stapling** (reduces handshake time)
5. **Rotate certificates** before expiry (auto-renewed with Let's Encrypt)
6. **Monitor certificate expiry** (set up alerts)

## Troubleshooting

### Certificate Not Found

```bash
# Check certificate location
sudo ls -la /etc/letsencrypt/live/

# Verify permissions
sudo chmod 755 /etc/letsencrypt/live
sudo chmod 755 /etc/letsencrypt/archive
```

### Nginx Configuration Error

```bash
# Test configuration
sudo nginx -t

# Check error logs
sudo tail -f /var/log/nginx/error.log
```

### Mixed Content Warnings

Ensure all API calls from dashboard use HTTPS:
- Update `API_URL` to use `https://`
- Check browser console for mixed content warnings

### Certificate Renewal Fails

```bash
# Manual renewal
sudo certbot renew --force-renewal

# Check certbot logs
sudo cat /var/log/letsencrypt/letsencrypt.log
```

## Monitoring

Set up monitoring for:
- Certificate expiry (30 days before)
- TLS handshake errors
- SSL Labs rating changes

### Example Alert Script

```bash
#!/bin/bash
# check-cert-expiry.sh

DOMAIN="api.yourdomain.com"
DAYS_BEFORE_EXPIRY=30

EXPIRY_DATE=$(echo | openssl s_client -servername $DOMAIN -connect $DOMAIN:443 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))

if [ $DAYS_LEFT -lt $DAYS_BEFORE_EXPIRY ]; then
    echo "WARNING: Certificate for $DOMAIN expires in $DAYS_LEFT days"
    # Send alert (email, Slack, etc.)
fi
```

## Additional Resources

- Let's Encrypt: https://letsencrypt.org/
- SSL Labs Test: https://www.ssllabs.com/ssltest/
- Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/
- Nginx TLS Documentation: https://nginx.org/en/docs/http/configuring_https_servers.html

## Quick Start Checklist

- [ ] Install Certbot and Nginx
- [ ] Obtain SSL certificates for both domains
- [ ] Copy and configure nginx.conf.example
- [ ] Update .env with HTTPS URLs
- [ ] Test nginx configuration
- [ ] Reload nginx
- [ ] Verify HTTPS works
- [ ] Test on SSL Labs (target A/A+)
- [ ] Set up certificate renewal monitoring
- [ ] Update docker-compose if needed

**After completing these steps, your AgentGate deployment will have production-grade TLS/HTTPS!**
