# AgentGate Helm Chart

Enterprise-grade Kubernetes deployment for AgentGate.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.8+
- kubectl configured with cluster access
- Ingress controller (nginx recommended)
- cert-manager (for TLS certificates)

## Quick Start

```bash
# Add Bitnami repository for dependencies
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Install with default values
helm install agentgate ./deploy/helm/agentgate

# Install with custom values
helm install agentgate ./deploy/helm/agentgate -f values-production.yaml
```

## Configuration

### Essential Configuration

Create a `values-production.yaml` file:

```yaml
ingress:
  hosts:
    - host: agentgate.yourdomain.com
      paths:
        - path: /api
          pathType: Prefix
          backend:
            service:
              name: agentgate-server
              port: 8000
        - path: /
          pathType: Prefix
          backend:
            service:
              name: agentgate-dashboard
              port: 3000
  tls:
    - secretName: agentgate-tls
      hosts:
        - agentgate.yourdomain.com

postgresql:
  auth:
    password: "YOUR_SECURE_PASSWORD"

redis:
  auth:
    password: "YOUR_SECURE_PASSWORD"

server:
  env:
    AGENTGATE_ENV: production
    AGENTGATE_RUNTIME_PROFILE: cloud_strict
    DATABASE_AUTH_MODE: entra_token
    AGENTGATE_Z3_MODE: enforce
    AZURE_KEY_VAULT_URL: https://your-vault-name.vault.azure.net
  secrets:
    secretKey: "YOUR_SECRET_KEY"
    nextauthSecret: "YOUR_NEXTAUTH_SECRET"

postgresql:
  enabled: false

redis:
  enabled: false

externalDatabase:
  url: "postgresql+asyncpg://agentgate@your-postgres-host:5432/agentgate?sslmode=require"

externalRedis:
  url: "rediss://your-redis-host:6380/0"
```

### Scaling Configuration

```yaml
server:
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80
```

### Resource Configuration

```yaml
server:
  resources:
    limits:
      cpu: 2000m
      memory: 4Gi
    requests:
      cpu: 500m
      memory: 1Gi
```

## Installation Steps

### 1. Create Namespace

```bash
kubectl create namespace agentgate
```

### 2. Create Secrets (Recommended Approach)

```bash
# Generate secure random passwords
export POSTGRES_PASSWORD=$(openssl rand -hex 32)
export REDIS_PASSWORD=$(openssl rand -hex 32)
export SECRET_KEY=$(openssl rand -hex 32)
export NEXTAUTH_SECRET=$(openssl rand -hex 32)

# Create secret
kubectl create secret generic agentgate-credentials \
  --from-literal=postgres-password=$POSTGRES_PASSWORD \
  --from-literal=redis-password=$REDIS_PASSWORD \
  --from-literal=secret-key=$SECRET_KEY \
  --from-literal=nextauth-secret=$NEXTAUTH_SECRET \
  -n agentgate
```

### 3. Install Chart

```bash
helm install agentgate ./deploy/helm/agentgate \
  --namespace agentgate \
  --set postgresql.auth.password=$POSTGRES_PASSWORD \
  --set redis.auth.password=$REDIS_PASSWORD \
  --set server.secrets.secretKey=$SECRET_KEY \
  --set server.secrets.nextauthSecret=$NEXTAUTH_SECRET \
  -f values-production.yaml
```

### 4. Verify Deployment

```bash
# Check deployment status
kubectl get pods -n agentgate

# Check services
kubectl get svc -n agentgate

# Check ingress
kubectl get ingress -n agentgate

# View logs
kubectl logs -n agentgate deployment/agentgate-server
```

## Upgrade

```bash
# Update dependencies
helm dependency update ./deploy/helm/agentgate

# Upgrade release
helm upgrade agentgate ./deploy/helm/agentgate \
  --namespace agentgate \
  -f values-production.yaml
```

## Uninstall

```bash
helm uninstall agentgate --namespace agentgate
```

## Production Checklist

- [ ] TLS certificates configured (cert-manager)
- [ ] PostgreSQL password set
- [ ] Redis password set
- [ ] Secret keys generated (SECRET_KEY, NEXTAUTH_SECRET)
- [ ] Ingress hostname configured
- [ ] Resource limits configured
- [ ] Autoscaling enabled
- [ ] Pod disruption budget enabled
- [ ] Monitoring enabled (Prometheus/Grafana)
- [ ] Backup strategy implemented
- [ ] Network policies configured

## Monitoring

The chart exposes Prometheus metrics on port 9090:

```yaml
monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
```

## Backup and Recovery

Enable automated backups:

```yaml
backup:
  enabled: true
  schedule: "0 2 * * *"  # Daily at 2 AM
  retention: 30
```

## Troubleshooting

### Pods not starting

```bash
kubectl describe pod -n agentgate <pod-name>
kubectl logs -n agentgate <pod-name>
```

### Database connection issues

```bash
kubectl exec -it -n agentgate deployment/agentgate-server -- env | grep DATABASE_URL
```

### Migration issues

```bash
kubectl logs -n agentgate <pod-name> -c migrations
```

## Support

For issues and questions:
- GitHub: https://github.com/EaCognitive/agentgate/issues
- Documentation: https://github.com/EaCognitive/agentgate
