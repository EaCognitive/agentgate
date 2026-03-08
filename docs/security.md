# Security Documentation

**AgentGate Security Architecture**
**Version**: 0.2.x
**Last Updated**: 2026-01-28
**Security Score**: 9.5/10

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Authorization (RBAC)](#authorization-rbac)
4. [Security Features](#security-features)
5. [Security Headers](#security-headers)
6. [Threat Detection](#threat-detection)
7. [Compliance](#compliance)
8. [Best Practices](#best-practices)
9. [Reporting Vulnerabilities](#reporting-vulnerabilities)

---

## Overview

AgentGate implements enterprise-grade security for AI agent tool execution. The platform provides multiple layers of defense including authentication, authorization, threat detection, and comprehensive audit logging.

**Security Principles**:
- Defense in depth
- Principle of least privilege
- Zero trust architecture
- Secure by default
- Comprehensive audit logging (sync or async via Redis Streams)

---

## Authentication

AgentGate supports multiple authentication methods with progressive security enhancement.

### JWT-Based Authentication

All API requests require a valid JWT token issued after successful login.

**Token Configuration**:
- Algorithm: HS256 (HMAC-SHA256)
- Expiration: 30 minutes (configurable)
- Secure: httpOnly cookies in production
- Claims: user_id, email, role, permissions

**Login Endpoint**:
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "totp_code": "123456"  # Required if MFA enabled
}
```

### Multi-Factor Authentication (MFA/2FA)

TOTP-based 2FA (RFC 6238) for enhanced account security.

**Implementation**:
- Algorithm: TOTP (Time-based One-Time Password)
- Hash: SHA-1 (industry standard for TOTP)
- Period: 30 seconds
- Digits: 6
- Window: ±1 period (allows for clock drift)

**Security Features**:
- Secrets stored encrypted in database
- Backup codes hashed with SHA-256
- Single-use backup codes (8 per user)
- Rate limiting on verification attempts
- Complete audit logging
- Brute force protection

**MFA Endpoints**:
```bash
# Enable MFA (generates QR code)
POST /api/auth/enable-2fa
Authorization: Bearer <token>

# Verify and activate
POST /api/auth/verify-2fa
Authorization: Bearer <token>
{
  "code": "123456"
}

# Disable MFA
POST /api/auth/disable-2fa
Authorization: Bearer <token>
{
  "password": "<current_password>"
}

# Regenerate backup codes
POST /api/auth/regenerate-backup-codes
Authorization: Bearer <token>
{
  "password": "<current_password>"
}
```

**Tests**: 70 comprehensive tests covering all MFA flows

### WebAuthn / Passkeys

Phishing-resistant authentication using Face ID, Touch ID, or hardware security keys.

**Features**:
- Biometric authentication support
- Multi-device passkey support
- Credential management (list, rename, delete)
- Complete audit logging
- Industry-standard WebAuthn protocol

**WebAuthn Endpoints**:
```bash
# Begin passkey registration
POST /api/auth/passkey/register-start
Authorization: Bearer <token>

# Complete registration
POST /api/auth/passkey/register-finish
Authorization: Bearer <token>

# Begin authentication
POST /api/auth/passkey/login-start

# Complete authentication
POST /api/auth/passkey/login-finish

# List user passkeys
GET /api/auth/passkey/list
Authorization: Bearer <token>

# Rename passkey
PATCH /api/auth/passkey/{credential_id}
Authorization: Bearer <token>

# Delete passkey
DELETE /api/auth/passkey/{credential_id}
Authorization: Bearer <token>
```

**Tests**: 12 tests covering registration, authentication, and management

### CAPTCHA Protection

hCaptcha integration to prevent automated attacks.

**Trigger Conditions**:
- Triggered after 3 failed login attempts
- Automatic counter reset after 1 hour
- Counter reset on successful login

**Configuration**:
```bash
HCAPTCHA_SECRET=your_secret_key
HCAPTCHA_SITE_KEY=your_site_key
```

**Tests**: 30 tests covering CAPTCHA integration and failed login tracking

---

## Authorization (RBAC)

Role-Based Access Control (RBAC) with five hierarchical roles and granular permissions.

### Roles

AgentGate implements five roles with hierarchical permissions:

#### 1. Admin
**Full system access** - User management, configuration, all features

**Permissions**:
- All user management (create, read, update, delete)
- All trace operations (read all users, delete)
- Approve/deny tool execution requests
- Full audit log access and export
- All dataset operations
- Cost limit configuration
- System configuration

**Use Cases**: System administrators, DevOps engineers

#### 2. Approver
**Human-in-the-loop decision making**

**Permissions**:
- Read user information
- Read all traces
- Approve/deny tool execution requests
- Read approval queue
- Read audit logs
- Read datasets

**Use Cases**: Operations managers, compliance officers

#### 3. Auditor
**Read-only access for compliance and security monitoring**

**Permissions**:
- Read user information
- Read all traces
- Read all approvals
- Full audit log access and export
- Read datasets
- Read cost information

**Use Cases**: Security teams, compliance officers, internal auditors

#### 4. Developer
**Development and testing capabilities**

**Permissions**:
- Read user information
- Read own traces
- Create, read, update, run datasets
- Read cost information

**Use Cases**: Engineers, QA teams, data scientists

#### 5. Viewer
**Read-only access to own data**

**Permissions**:
- Read user information
- Read own traces only
- Read own cost information

**Use Cases**: End users, read-only access accounts

### Permission System

Granular permissions for fine-grained access control:

**User Management**:
- `user:create` - Create new users
- `user:read` - Read user information
- `user:update` - Update user profiles
- `user:delete` - Delete users

**Trace Management**:
- `trace:read` - Read own traces
- `trace:read_all` - Read all users' traces
- `trace:delete` - Delete traces

**Approval Management**:
- `approval:read` - View approval queue
- `approval:decide` - Approve/deny requests

**Audit Logs**:
- `audit:read` - Read audit logs
- `audit:export` - Export audit logs (CSV, JSON)

**Dataset Management**:
- `dataset:create` - Create datasets
- `dataset:read` - Read datasets
- `dataset:update` - Update datasets
- `dataset:delete` - Delete datasets
- `dataset:run` - Run dataset tests

**Cost Management**:
- `cost:read` - View cost information
- `cost:limit` - Set cost limits

**System Configuration**:
- `config:read` - Read configuration
- `config:update` - Update configuration

### User Isolation

Complete data isolation between users enforced at multiple levels:

**Database Level**:
- All queries filtered by `user_id`
- Foreign key constraints
- Row-level security

**Application Level**:
- Authorization middleware on all endpoints
- JWT token validation
- Permission checks before every operation

**API Level**:
- User context extracted from JWT
- Automatic filtering in database queries
- Cross-user access attempts logged and blocked

**Tests**: 51 tests covering role restrictions, user isolation, and privilege escalation prevention

### Authorization Bugs Fixed

All 12 authorization vulnerabilities have been resolved:

1. ✅ Viewer role restricted to own traces only
2. ✅ User isolation enforced at database level
3. ✅ Permission checks on all sensitive endpoints
4. ✅ Role elevation prevention implemented
5. ✅ Token tampering detection active
6. ✅ JWT role claims validated on every request
7. ✅ Database-level user_id filtering enforced
8. ✅ Approval endpoints restricted to approvers
9. ✅ Audit log export restricted to auditors
10. ✅ Configuration endpoints admin-only
11. ✅ Dataset creation requires developer role
12. ✅ Cross-user data access blocked and logged

---

## Security Features

### Rate Limiting

Distributed rate limiting using Redis with moving-window strategy.

**Configuration**:
- Default limit: 100 requests/minute per IP
- Moving-window algorithm (more accurate than fixed-window)
- Graceful degradation if Redis unavailable
- Per-endpoint configurable limits

**Rate Limit Headers**:
- `X-RateLimit-Limit` - Maximum requests per window
- `X-RateLimit-Remaining` - Requests remaining
- `X-RateLimit-Reset` - Unix timestamp when limit resets

**Implementation**:
```python
redis:
  image: redis:7-alpine
  volumes:
    - redis_data:/data
  command: redis-server --appendonly yes
```

**Tests**: 49 tests covering rate limiting enforcement and headers

### Automated Backup System

Hourly automated backups with encryption and integrity verification.

**Features**:
- Automated hourly PostgreSQL backups
- S3 upload with server-side encryption (AES-256)
- Optional client-side encryption (AES-256-CBC)
- Compression (70-90% size reduction)
- 30-day retention policy
- Weekly automated restore testing
- Integrity verification with checksums

**Disaster Recovery**:
- RTO (Recovery Time Objective): <15 minutes
- RPO (Recovery Point Objective): <1 hour

**Compliance Ready**:
- SOC 2 Type II ready
- HIPAA §164.312 compliant
- GDPR Article 32 compliant
- ISO 27001 ready

**Tests**: 32 tests covering backup, restore, and integrity verification

### PII Protection

Bi-directional PII anonymization for SOC 2 and HIPAA compliance.

**Supported PII Types**:
- PERSON - Personal names
- EMAIL - Email addresses
- PHONE - Phone numbers
- SSN - Social Security Numbers
- CREDIT_CARD - Credit card numbers
- IP_ADDRESS - IP addresses
- DOB - Dates of birth
- Custom regex patterns

**Features**:
- Automatic detection and redaction
- Bi-directional rehydration
- AES-256-GCM encryption at rest
- HMAC-SHA256 integrity verification
- Role-based access control
- Tamper-evident audit logging
- Secure deletion with memory overwrite
- 6-year retention for HIPAA compliance

**Compliance Mapping**:
- HIPAA §164.312(a)(2)(iv) - Encryption
- HIPAA §164.312(b) - Audit controls
- HIPAA §164.312(c)(1) - Integrity controls
- HIPAA §164.530(j)(1) - Secure deletion
- SOC 2 CC6.1 - Access control
- SOC 2 CC7.2 - System monitoring

---

## Security Headers

All HTTP responses include comprehensive security headers:

### Content Security Policy (CSP)
```
Content-Security-Policy: default-src 'self';
  script-src 'self' 'unsafe-inline' 'unsafe-eval';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self' data:;
  connect-src 'self' http://localhost:8000
```

### XSS Protection
```
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

### HSTS (HTTP Strict Transport Security)
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### Permissions Policy
```
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### Referrer Policy
```
Referrer-Policy: strict-origin-when-cross-origin
```

**Tests**: 40 XSS/CSRF tests validating header effectiveness

---

## Threat Detection

Real-time threat detection system monitoring for suspicious activity.

### Detection Patterns

#### Brute Force Attacks
- **Detection**: 10+ failed login attempts per hour
- **Severity**: HIGH (10+ failures), CRITICAL (20+ failures)
- **Response**: Account lockout, IP blocking, alert generation

#### Privilege Escalation
- **Detection**: Unauthorized role modification attempts
- **Severity**: CRITICAL
- **Response**: Immediate alert, request blocking, audit log

#### Data Exfiltration
- **Detection**: Abnormal data access patterns
- **Metrics**: 100+ requests/minute, >10MB response size
- **Severity**: HIGH (rate), MEDIUM (volume)
- **Response**: Rate limiting, alerts, audit logging

#### New Location Detection
- **Detection**: First login from unknown IP address
- **Severity**: MEDIUM
- **Response**: Email notification, MFA challenge, audit log

### Alert Integration

Support for multiple alert channels:
- **Datadog**: Metrics and events
- **Slack**: Real-time notifications
- **PagerDuty**: Critical incident management
- **Email**: Security team notifications

### Threat Response

Automated responses to detected threats:
1. Immediate request blocking
2. IP address temporary ban
3. Account security notifications
4. Security team alerts
5. Detailed audit logging

**Tests**: 40 tests covering all threat detection patterns and responses

---

## Compliance

### SOC 2 Type II Readiness

AgentGate implements controls aligned with SOC 2 Trust Service Criteria:

**CC6.1 - Logical and Physical Access Controls**:
- Multi-factor authentication
- Role-based access control
- Principle of least privilege
- Session management

**CC7.2 - System Monitoring**:
- Comprehensive audit logging
- Real-time threat detection
- Alert integration
- Security metrics

### HIPAA Compliance

Features supporting HIPAA §164.312 requirements:

**§164.312(a)(2)(iv) - Encryption**:
- AES-256-GCM encryption at rest
- TLS 1.3 encryption in transit

**§164.312(b) - Audit Controls**:
- Tamper-evident audit logging
- Optional async audit pipeline via Redis Streams for high-throughput deployments
- User activity tracking
- System access logs

**§164.312(c)(1) - Integrity**:
- HMAC-SHA256 integrity verification
- Checksum validation
- Backup integrity checks

**§164.530(j)(1) - Secure Deletion**:
- Secure deletion with memory overwrite
- 6-year retention policy
- Compliance audit trails

### GDPR Article 32

Security of processing implementation:

- Pseudonymisation and encryption of personal data
- Ongoing confidentiality, integrity, availability
- Regular testing and evaluation
- Restoration of availability and access

---

## Best Practices

### Development

1. **Authentication**: Always use JWT tokens for API requests
2. **Authorization**: Implement least-privilege principle
3. **Input Validation**: Validate all user inputs at API boundaries
4. **Output Encoding**: Use framework-provided escaping (automatic in FastAPI)
5. **Error Handling**: Never expose sensitive information in error messages

### Production Deployment

1. **Secrets Management**:
   - Change `JWT_SECRET` to strong random value
   - Use environment variables, never commit secrets
   - Rotate secrets regularly

2. **HTTPS Configuration**:
   - Enable HTTPS for all traffic
   - Use HSTS headers
   - Valid SSL certificates

3. **Database Security**:
   - Use strong database passwords
   - Enable SSL connections
   - Regular security updates
   - Automated backups

4. **Monitoring**:
   - Enable threat detection alerts
   - Monitor audit logs regularly
   - Set up security dashboards
   - Regular security reviews

5. **Rate Limiting**:
   - Use Redis for distributed rate limiting
   - Configure appropriate limits per endpoint
   - Monitor rate limit violations

### Security Checklist

Before production deployment:

- [ ] Change JWT_SECRET to strong random value
- [ ] Change NEXTAUTH_SECRET to strong random value
- [ ] Enable HTTPS with valid certificates
- [ ] Configure CORS origins properly
- [ ] Set up Redis for rate limiting
- [ ] Enable automated backups
- [ ] Configure threat detection alerts
- [ ] Review and test RBAC permissions
- [ ] Enable audit logging
- [ ] Set up security monitoring
- [ ] Document incident response procedures
- [ ] Perform security testing

---

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

### Reporting Process

1. **Do NOT open a public issue**
2. **Email security concerns to**: security@agentgate.io (or maintainer)
3. **Include**:
   - Detailed description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)
4. **Allow reasonable time** for a fix before public disclosure (typically 90 days)

### What to Expect

- Acknowledgment within 48 hours
- Regular updates on fix progress
- Credit in security advisories (if desired)
- Coordinated disclosure timeline

### Security Response Timeline

- **Critical**: Fix within 24-48 hours
- **High**: Fix within 7 days
- **Medium**: Fix within 30 days
- **Low**: Fix in next regular release

---

## Supported Versions

| Version | Supported | Security Updates |
|---------|-----------|------------------|
| 0.2.x   | ✅ Yes    | Active support   |
| 0.1.x   | ❌ No     | End of life      |

---

## Additional Resources

- [Runtime Enforcement and SDK Alignment](runtime-enforcement-and-sdk-alignment.md)
- [Security Setup Guide](security-setup-guide.md)
- [MFA Setup Guide](mfa-setup-guide.md)
- [PII Encryption Flow](pii-encryption-flow.md)

---

**Last Updated**: 2026-01-28
**Security Score**: 9.5/10
**Next Audit**: Q2 2026
