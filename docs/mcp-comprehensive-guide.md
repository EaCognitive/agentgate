# AgentGate MCP Security Server - Comprehensive Guide

**Version:** 1.0.0
**Protocol:** MCP 2025-11-25
**Last Updated:** February 2026

> Canonical quality baseline: [`docs/mcp-gold-standard.md`](mcp-gold-standard.md)

---

## Table of Contents

1. [What is AgentGate MCP?](#what-is-agentgate-mcp)
2. [Key Features](#key-features)
3. [Installation](#installation)
4. [Platform Integration](#platform-integration)
5. [Quick Start](#quick-start)
6. [Resources Reference](#resources-reference)
7. [Tools Reference](#tools-reference)
8. [Prompts Reference](#prompts-reference)
9. [Security Model](#security-model)
10. [Usage Examples](#usage-examples)
11. [Troubleshooting](#troubleshooting)
12. [Best Practices](#best-practices)

---

## What is AgentGate MCP?

AgentGate MCP Security Server is a **Model Context Protocol (MCP)** implementation that exposes enterprise-grade security operations as resources and tools for AI assistants. It enables conversational security workflows, threat analysis, policy management, and red-team testing through any MCP-compatible AI platform.

### What is MCP?

The Model Context Protocol (MCP) is an open standard that enables AI assistants to:
- **Read Resources:** Access live data (logs, metrics, documents)
- **Execute Tools:** Perform actions (block IPs, create incidents, run tests)
- **Use Prompts:** Follow guided workflows for complex tasks

MCP standardizes how AI assistants interact with external systems, making them more capable and context-aware.

### Why AgentGate MCP?

Traditional security tools require:
- Manual command-line operations
- Complex scripting
- Context switching between systems
- Deep technical knowledge

**AgentGate MCP enables:**
```
Natural language → Security operations

"Block all IPs from 10.0.0.0/8 and escalate SQL injection to CRITICAL"
    ↓
1. Parse policy from natural language
2. Simulate policy against test scenarios
3. Preview changes with signed token
4. Apply policy after confirmation
5. Verify policy is active
```

---

## Key Features

### Real-Time Security Resources (6)

Access live security data through standardized URIs:

| Resource | URI | Description |
|----------|-----|-------------|
| Recent Threats | `security://threats/recent` | Last 50 security threats with optional severity filter |
| Threat Statistics | `security://threats/stats` | 24-hour aggregated stats with trend analysis |
| Threat Timeline | `security://threats/timeline` | Hourly bucketed threat counts for visualization |
| Blocked IPs | `security://blocked-ips` | Currently blocked IPs with TTL and reason |
| Detector Stats | `security://detector/stats` | Detection engine performance metrics |
| Alert Summary | `security://alerts/summary` | Alert manager statistics and channel status |

### Security Automation Tools (10)

Execute security operations with built-in safety:

**Operational Tools:**
- `block_ip_temp` - Temporarily block IP addresses (1h-24h TTL)
- `unblock_ip` - Remove IP from block list
- `revoke_token` - Revoke all tokens/sessions for a user
- `create_incident` - Create security incident records

**AI-Enhanced Tools:**
- `score_threat` - Run AI risk scoring on historical threats
- `generate_redteam_payloads` - Generate attack payloads for testing

**Governance Tools:**
- `parse_nl_policy` - Convert natural language to security policies
- `apply_policy` - Apply security policies with preview-confirm
- `simulate_policy` - Dry-run policy evaluation
- `unlock_policy` - Unlock MCP-created policies for editing

### Guided Workflows (5 Prompts)

- `governance_workflow` - 5-step security policy change workflow

### Enterprise Security

- **Preview-Confirm Flow:** Destructive operations require two-step approval
- **HMAC-Signed Tokens:** 5-minute TTL, parameter-bound, tamper-proof
- **RBAC Integration:** Permission checks via JWT tokens
- **Audit Logging:** All operations logged with user attribution

### Operation-Class Enforcement Model

Runtime MCP execution is classified and enforced by `server/mcp/execution_policy.py`.

| Operation Class | Typical Methods | Enforcement Path |
|---|---|---|
| `read` | `GET` and read-only overrides | Auth + policy evaluation; no mutation guardrail block |
| `mutating` | `POST`, `PUT`, `PATCH`, `DELETE` | Auth + policy + formal guardrail enforcement |
| `high_impact_mutating` | Preview-confirm security operations | Auth + policy + formal guardrail + preview-confirm + MFA |

Additional constraints:

- `mcp_settings_update` is hardwired to require human approval.
- In `staging` and `production`, missing active policy set is fail-closed.
- Formal MCP tools route through canonical API endpoints and return `runtime_solver` metadata.
- Long-running MCP operations use async job envelopes (`JobResponse` / `ToolEnvelope`).

---

## Installation

### Prerequisites

```bash
# Python 3.13+ required
python3 --version

# PostgreSQL database
# Redis (optional, for multi-worker deployments)
```

### Install AgentGate

```bash
# Clone repository
git clone https://github.com/EaCognitive/agentgate.git
cd agentgate

# Install with MCP support
pip install -e ".[server]"

# Or using uv (recommended)
uv pip install -e ".[server]"
```

### Verify Installation

```bash
# Check MCP is available
python3 -c "import mcp; print(f'MCP version: {mcp.__version__}')"

# Test MCP server
python3 -m server.mcp --help
```

### Environment Configuration

Create `.env` file:

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost/agentgate

# Security
SECRET_KEY=your-secret-key-min-32-chars
JWT_ALGORITHM=HS256

# MCP Features
ENABLE_MCP=true                    # Enable MCP server
ENABLE_AI_SCORING=true             # Enable AI risk scorer
ENABLE_REDTEAM_GENERATOR=true      # Enable red-team generator

# Optional
REDIS_URL=redis://localhost:6379   # For distributed deployments
MCP_STDIO_TRUSTED=false            # Require preview-confirm in stdio
```

---

## Platform Integration

### Claude Desktop (Anthropic)

**Best for:** Individual security analysts, SOC operators

#### Installation

1. **Install Claude Desktop:** Download from https://claude.ai/download

2. **Configure MCP Server:**

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%/Claude/claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "agentgate-security": {
      "command": "python3",
      "args": ["-m", "server.mcp"],
      "cwd": "/path/to/agentgate",
      "env": {
        "DATABASE_URL": "postgresql://user:pass@localhost/agentgate",
        "SECRET_KEY": "your-secret-key",
        "ENABLE_REDTEAM_GENERATOR": "true"
      }
    }
  }
}
```

3. **Restart Claude Desktop**

4. **Verify Connection:**
   - Open Claude Desktop
   - Look for the hammer icon in the sidebar
   - Click to see "agentgate-security" server
   - Verify 17 capabilities (6 resources, 10 tools, 1 prompt)

#### Usage Example

```
You: "Show me recent critical threats"

Claude: [Reads security://threats/recent with severity filter]
Here are the recent critical threats:
- SQL injection attempt from 203.0.113.45
- Path traversal from 198.51.100.23
...

You: "Block the first IP for 2 hours"

Claude: [Calls block_ip_temp with preview]
I'll block 203.0.113.45 for 2 hours. Here's the preview:
- IP: 203.0.113.45
- Duration: 7200 seconds
- Impact: All requests from this IP will be blocked

Shall I proceed? [Waiting for confirmation]

You: "Yes, proceed"

Claude: [Calls block_ip_temp with confirm=true + token]
✅ IP 203.0.113.45 blocked successfully until [timestamp]
```

---

### Cursor IDE

**Best for:** Security engineers working in code

#### Installation

1. **Install Cursor:** Download from https://cursor.sh

2. **Configure MCP:**

Create `.cursor/mcp.json` in your workspace:

```json
{
  "mcpServers": {
    "agentgate-security": {
      "command": "python3",
      "args": ["-m", "server.mcp"],
      "cwd": "${workspaceFolder}",
      "env": {
        "DATABASE_URL": "${env:DATABASE_URL}",
        "SECRET_KEY": "${env:SECRET_KEY}",
        "ENABLE_REDTEAM_GENERATOR": "true"
      }
    }
  }
}
```

3. **Reload Cursor:** Cmd/Ctrl + Shift + P → "Reload Window"

4. **Verify:** Check bottom status bar for MCP connection status

#### Usage Example

```
You: @agentgate-security Generate 10 SQL injection payloads and show detection rate

Cursor: [Calls generate_redteam_payloads]
Generated 10 SQL injection payloads:
- Detection rate: 80%
- Missed payloads: 2

Here are the missed ones that need pattern updates:
1. %27%20OR%20%31%3D%31--
2. %2527%2520OR%2520%2531%253D%2531--

Suggested pattern fix:
```python
# Add double URL encoding detection
pattern = r'%25[0-9A-Fa-f]{2}%25[0-9A-Fa-f]{2}'
```
```

---

### VS Code (with Continue extension)

**Best for:** Developers integrating security checks into workflows

#### Installation

1. **Install Continue Extension:**
   - Open VS Code
   - Extensions → Search "Continue"
   - Install "Continue - AI Code Assistant"

2. **Configure MCP:**

Edit `~/.continue/config.json`:

```json
{
  "models": [...],
  "mcpServers": {
    "agentgate-security": {
      "command": "python3",
      "args": ["-m", "server.mcp"],
      "cwd": "/path/to/agentgate",
      "env": {
        "DATABASE_URL": "postgresql://localhost/agentgate",
        "SECRET_KEY": "your-secret-key"
      }
    }
  }
}
```

3. **Reload Continue:** Cmd/Ctrl + Shift + P → "Continue: Reload"

#### Usage Example

```
You: Check if my API has any active threats

Continue: [Reads security://threats/stats]
Current threat status:
- Total threats (24h): 3
- Critical: 0
- High: 1
- Medium: 2

The high-severity threat is a SQL injection attempt
from 198.51.100.45 at /api/users endpoint.

Would you like me to block this IP?
```

---

### OpenAI Responses API (ChatGPT)

**Best for:** Programmatic integration, custom dashboards

#### Installation

1. **Start HTTP MCP Server:**

```bash
python3 -m server.mcp --http --port 8102
```

2. **Expose Publicly** (required for OpenAI):

```bash
# Option 1: Cloudflare Tunnel
cloudflared tunnel --url http://127.0.0.1:8102 --no-autoupdate

# Option 2: ngrok
ngrok http 8102

# Option 3: Production reverse proxy (nginx, Caddy)
```

3. **Use in OpenAI API:**

```python
from openai import OpenAI

client = OpenAI()

response = client.responses.create(
    model="gpt-4.1-mini",
    input="List recent security threats and suggest actions",
    tools=[
        {
            "type": "mcp",
            "server_label": "agentgate-security",
            "server_url": "https://your-public-url.com/mcp",
            "require_approval": "never",
        }
    ],
)

print(response.output_text)
```

#### Usage Example

```python
# Block suspicious IPs
response = client.responses.create(
    model="gpt-4.1-mini",
    input="Block all IPs with more than 5 failed login attempts in the last hour",
    tools=[{"type": "mcp", "server_label": "agentgate-security", ...}],
)
```

---

### Cline (VS Code Extension)

**Best for:** Autonomous coding agents with security awareness

#### Installation

1. **Install Cline Extension:**
   - VS Code → Extensions → "Cline"
   - Install and configure API keys

2. **Configure MCP:**

Cline reads from `.continue/config.json` or create `.cline/mcp.json`:

```json
{
  "mcpServers": {
    "agentgate-security": {
      "command": "python3",
      "args": ["-m", "server.mcp"],
      "env": {
        "DATABASE_URL": "${env:DATABASE_URL}",
        "SECRET_KEY": "${env:SECRET_KEY}"
      }
    }
  }
}
```

3. **Restart VS Code**

#### Usage Example

```
You: Add rate limiting to the login endpoint and verify it blocks attacks

Cline:
1. [Reads security://threats/stats to check current brute force attempts]
2. [Implements rate limiting code]
3. [Calls generate_redteam_payloads to test]
4. [Verifies detection rate improved from 60% to 95%]
5. [Creates incident if any payloads bypass protection]
```

---

### Gemini Code Assist

**Best for:** Google Cloud environments

#### Installation

1. **Setup Gemini Code Assist:** Follow Google Cloud setup

2. **Deploy MCP Server to Cloud Run:**

```bash
# Build container
docker build -f Dockerfile.server -t agentgate-mcp .

# Deploy to Cloud Run
gcloud run deploy agentgate-mcp \
  --image agentgate-mcp \
  --platform managed \
  --set-env-vars ENABLE_MCP=true
```

3. **Configure MCP Client:**

```json
{
  "mcpServers": {
    "agentgate-security": {
      "url": "https://agentgate-mcp-xxx.run.app/mcp",
      "auth": {
        "type": "bearer",
        "token": "${env:CLOUD_RUN_TOKEN}"
      }
    }
  }
}
```

---

## Quick Start

### 5-Minute Setup

```bash
# 1. Start MCP server (stdio mode for desktop AI)
python3 -m server.mcp

# 2. Or start HTTP mode for OpenAI/webhooks
python3 -m server.mcp --http --port 8102

# 3. Or mount in FastAPI
ENABLE_MCP=true uvicorn server.main:app
```

### First Commands

```
# In any MCP-enabled AI:

"Show me detector stats"
→ Reads security://detector/stats

"Generate 5 XSS payloads and test them"
→ Calls generate_redteam_payloads(category="xss", count=5)

"Parse this policy: block IPs from 10.0.0.0/8"
→ Calls parse_nl_policy(description="...")

"Simulate blocking that IP range against my API"
→ Calls simulate_policy(policy_rules="...", test_inputs="...")
```

---

## Resources Reference

### security://threats/recent

**Type:** Resource (read-only)
**Returns:** JSON array of threat summaries

**Schema:**
```typescript
interface ThreatSummary {
  id: number
  event_id: string
  event_type: string
  severity: "critical" | "high" | "medium" | "low"
  status: "pending" | "acknowledged" | "resolved" | "dismissed"
  source_ip: string | null
  target: string | null
  description: string | null
  detected_at: string (ISO 8601)
  user_email: string | null
}
```

**Example Response:**
```json
[
  {
    "id": 123,
    "event_id": "evt_abc123",
    "event_type": "SQL_INJECTION",
    "severity": "high",
    "status": "pending",
    "source_ip": "203.0.113.45",
    "target": "/api/users",
    "description": "SQL injection attempt detected",
    "detected_at": "2026-02-09T14:30:00Z",
    "user_email": "attacker@example.com"
  }
]
```

**Usage:**
```
"Show me recent critical threats from the last hour"
```

---

### security://threats/stats

**Type:** Resource (read-only)
**Returns:** JSON object with aggregated statistics

**Schema:**
```typescript
interface ThreatStatsResponse {
  total_threats: number
  critical: number
  high: number
  medium: number
  low: number
  resolved: number
  pending: number
  trend: number  // Change vs previous 24h
  period_hours: number
}
```

**Example Response:**
```json
{
  "total_threats": 47,
  "critical": 2,
  "high": 8,
  "medium": 22,
  "low": 15,
  "resolved": 30,
  "pending": 17,
  "trend": +5,
  "period_hours": 24
}
```

**Usage:**
```
"What's the current threat level?"
"Show me security trends for the last 24 hours"
```

---

### security://threats/timeline

**Type:** Resource (read-only)
**Returns:** JSON array of hourly buckets

**Schema:**
```typescript
interface TimelineBucket {
  timestamp: string (ISO 8601)
  critical: number
  high: number
  medium: number
  low: number
}
```

**Example Response:**
```json
[
  {
    "timestamp": "2026-02-09T14:00:00Z",
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2
  },
  {
    "timestamp": "2026-02-09T15:00:00Z",
    "critical": 0,
    "high": 2,
    "medium": 4,
    "low": 1
  }
]
```

**Usage:**
```
"Show me a timeline of threats today"
"Plot threat distribution over the last 6 hours"
```

---

### security://blocked-ips

**Type:** Resource (read-only)
**Returns:** JSON array of blocked IP details

**Schema:**
```typescript
interface BlockedIPDetail {
  ip: string
  reason: string
  expires_at: number  // Unix timestamp
  remaining_seconds: number
}
```

**Example Response:**
```json
[
  {
    "ip": "203.0.113.45",
    "reason": "Brute force attack detected",
    "expires_at": 1707491400,
    "remaining_seconds": 3456
  }
]
```

**Usage:**
```
"Which IPs are currently blocked?"
"Show me IPs blocked for brute force"
```

---

### security://detector/stats

**Type:** Resource (read-only)
**Returns:** JSON object with detection engine metrics

**Schema:**
```typescript
interface DetectorStatsResponse {
  total_checks: number
  threats_detected: number
  ips_blocked: number
  brute_force_detected: number
  injection_detected: number
}
```

**Example Response:**
```json
{
  "total_checks": 15420,
  "threats_detected": 47,
  "ips_blocked": 12,
  "brute_force_detected": 8,
  "injection_detected": 23
}
```

**Usage:**
```
"What's the detection rate today?"
"Show me how many threats were caught"
```

---

### security://alerts/summary

**Type:** Resource (read-only)
**Returns:** JSON object with alert manager stats

**Schema:**
```typescript
interface AlertStatsResponse {
  total_sent: number
  total_suppressed: number
  total_deduplicated: number
  channels_configured: number
}
```

**Example Response:**
```json
{
  "total_sent": 45,
  "total_suppressed": 12,
  "total_deduplicated": 8,
  "channels_configured": 3
}
```

**Usage:**
```
"How many alerts were sent today?"
"Show me alert statistics"
```

---

## Tools Reference

### generate_redteam_payloads

**Type:** Tool (read-only)
**Purpose:** Generate attack payloads for testing detection capabilities

**Parameters:**
```typescript
{
  category: "all" | "sql_injection" | "xss" | "path_traversal"
            | "command_injection" | "ldap_injection" | "ssrf"
            | "header_injection"
  count: number (1-100, default: 20)
}
```

**Returns:**
```typescript
interface RedTeamReport {
  categories: Array<{
    category: string
    total_payloads: number
    detected_count: number
    missed_count: number
    detection_rate: number
    missed_payloads: string[]
  }>
  global_total: number
  global_detected: number
  global_detection_rate: number
  warnings: string[]
}
```

**Example:**
```json
// Input
{
  "category": "xss",
  "count": 10
}

// Output
{
  "categories": [{
    "category": "xss",
    "total_payloads": 10,
    "detected_count": 8,
    "missed_count": 2,
    "detection_rate": 0.8,
    "missed_payloads": [
      "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
      "＜ｓｃｒｉｐｔ＞ａｌｅｒｔ（１）＜／ｓｃｒｉｐｔ＞"
    ]
  }],
  "global_total": 10,
  "global_detected": 8,
  "global_detection_rate": 0.8,
  "warnings": []
}
```

**Mutations Applied:**
- Case alternation
- URL encoding
- Double URL encoding
- Unicode fullwidth
- Comment injection
- Whitespace manipulation
- Null byte injection
- Concatenation splitting

**Usage:**
```
"Generate 20 SQL injection payloads and test detection"
"Test XSS protection with 10 payloads"
"What's our detection rate for path traversal?"
```

---

### parse_nl_policy

**Type:** Tool (read-only)
**Purpose:** Convert natural language to structured security policy

**Parameters:**
```typescript
{
  description: string  // Natural language policy description
}
```

**Supported Patterns:**
- `"block IPs from <CIDR>"` → `ip_deny` rule
- `"allow IPs from <CIDR>"` → `ip_allow` rule
- `"escalate all <type> to <severity>"` → `severity_override` rule
- `"skip detection for <endpoint>"` → `endpoint_allow` rule

**Returns:**
```typescript
interface ParsedPolicy {
  success: boolean
  parsed_policy: {
    pre_rules: Array<Rule>
    post_rules: Array<Rule>
  }
  warnings: string[]
}
```

**Example:**
```json
// Input
{
  "description": "block IPs from 10.0.0.0/8 and escalate all sql injection to CRITICAL"
}

// Output
{
  "success": true,
  "parsed_policy": {
    "pre_rules": [
      {
        "type": "ip_deny",
        "cidr": "10.0.0.0/8"
      }
    ],
    "post_rules": [
      {
        "type": "severity_override",
        "pattern_type": "sql_injection",
        "new_severity": "CRITICAL"
      }
    ]
  },
  "warnings": []
}
```

**Usage:**
```
"Parse this policy: block all traffic from 10.0.0.0/8"
"Convert to policy: escalate SQL injection to critical"
"Create policy: allow 192.168.1.0/24 and skip /health"
```

---

### simulate_policy

**Type:** Tool (read-only)
**Purpose:** Dry-run policy evaluation without applying changes

**Parameters:**
```typescript
{
  policy_rules: string  // JSON string of policy
  test_inputs: string   // JSON array of test scenarios
}
```

**Test Input Schema:**
```typescript
interface TestInput {
  ip: string
  endpoint: string
  severity: string
  pattern_type: string
}
```

**Returns:**
```typescript
interface PolicySimulationResult {
  success: boolean
  simulation_results: Array<{
    input: TestInput
    pre_detector: { action: string, reason: string }
    post_detector: { action: string, reason: string }
  }>
  total_tests: number
}
```

**Example:**
```json
// Input
{
  "policy_rules": "{\"pre_rules\": [{\"type\": \"ip_deny\", \"cidr\": \"10.0.0.0/8\"}], \"post_rules\": []}",
  "test_inputs": "[{\"ip\": \"10.0.0.5\", \"endpoint\": \"/api\", \"severity\": \"high\", \"pattern_type\": \"sql_injection\"}]"
}

// Output
{
  "success": true,
  "simulation_results": [{
    "input": { "ip": "10.0.0.5", ... },
    "pre_detector": {
      "action": "deny",
      "reason": "IP 10.0.0.5 is in denylist 10.0.0.0/8"
    },
    "post_detector": {
      "action": "continue",
      "reason": "No matching post-rules"
    }
  }],
  "total_tests": 1
}
```

**Usage:**
```
"Simulate blocking 10.0.0.0/8 against my test traffic"
"Test this policy before applying it"
"What would happen if I block this IP range?"
```

---

### block_ip_temp

**Type:** Tool (destructive, requires preview-confirm)
**Purpose:** Temporarily block an IP address

**Parameters:**
```typescript
{
  ip: string             // IP address to block
  reason: string         // Reason for blocking
  duration_seconds?: number  // Duration (default: 3600)
  confirm?: boolean      // Confirmation flag
  preview_token?: string // Token from preview step
}
```

**Preview Response (confirm=false):**
```json
{
  "action": "block_ip_temp",
  "preview": {
    "ip": "203.0.113.45",
    "reason": "Brute force attack",
    "duration_seconds": 7200,
    "impact": "IP 203.0.113.45 will be blocked for 7200 seconds"
  },
  "preview_token": "block_ip_temp|hash|expiry|signature",
  "expires_in_seconds": 300,
  "message": "Review the preview and confirm with the token."
}
```

**Confirmed Response (confirm=true):**
```json
{
  "action": "block_ip_temp",
  "success": true,
  "detail": "Action 'block_ip_temp' completed successfully",
  "metadata": {
    "ip": "203.0.113.45",
    "blocked_until": 1707491400
  }
}
```

**Usage:**
```
"Block 203.0.113.45 for 2 hours due to brute force"
"Temporarily block this IP that's attacking the API"
```

---

### unblock_ip

**Type:** Tool (destructive, requires preview-confirm)
**Purpose:** Remove IP from block list

**Parameters:**
```typescript
{
  ip: string             // IP address to unblock
  confirm?: boolean
  preview_token?: string
}
```

**Usage:**
```
"Unblock 203.0.113.45"
"Remove block on this IP"
```

---

### revoke_token

**Type:** Tool (destructive, requires preview-confirm)
**Purpose:** Revoke all tokens and sessions for a user

**Parameters:**
```typescript
{
  user_id: number        // User ID
  reason: string         // Revocation reason
  confirm?: boolean
  preview_token?: string
}
```

**Usage:**
```
"Revoke all tokens for user 123 due to compromise"
"Force logout user 456 immediately"
```

---

### create_incident

**Type:** Tool (destructive, requires preview-confirm)
**Purpose:** Create security incident record

**Parameters:**
```typescript
{
  title: string          // Incident title
  severity: "critical" | "high" | "medium" | "low"
  description: string    // Detailed description
  source_ip?: string     // Optional source IP
  related_threat_ids?: string  // Comma-separated IDs
  confirm?: boolean
  preview_token?: string
}
```

**Usage:**
```
"Create incident for the SQL injection from 203.0.113.45"
"Log this attack as a critical incident"
```

---

### score_threat

**Type:** Tool (read-only)
**Purpose:** Run AI risk scoring on historical threat

**Parameters:**
```typescript
{
  threat_id: number  // Threat ID from database
}
```

**Returns:**
```typescript
interface RiskScore {
  score: number           // 0.0-1.0
  confidence: number      // 0.0-1.0
  reasoning: string
  recommended_action: "block" | "monitor" | "allow"
  provider: string
  timed_out: boolean
}
```

**Example:**
```json
{
  "score": 0.85,
  "confidence": 0.9,
  "reasoning": "Highest severity: high; Multiple threats detected: 3; Repeat offender IP: 203.0.113.45",
  "recommended_action": "block",
  "provider": "heuristic",
  "timed_out": false
}
```

**Usage:**
```
"Score threat ID 123"
"What's the risk level for this attack?"
```

---

### apply_policy

**Type:** Tool (destructive, requires preview-confirm)
**Purpose:** Apply security policy to system

**Parameters:**
```typescript
{
  policy_json: string    // JSON policy from parse_nl_policy
  confirm?: boolean
  preview_token?: string
}
```

**Usage:**
```
"Apply the policy we just created"
"Activate this security policy"
```

---

### unlock_policy

**Type:** Tool (destructive, requires preview-confirm)
**Purpose:** Unlock MCP-created policy for manual editing

**Parameters:**
```typescript
{
  policy_id: string      // Policy UUID
  reason: string         // Unlock reason
  confirm?: boolean
  preview_token?: string
}
```

**Usage:**
```
"Unlock policy abc123 for editing"
"Make policy xyz789 editable"
```

---

## Prompts Reference

### governance_workflow

**Type:** Prompt
**Purpose:** Guide user through 5-step policy change workflow

**Parameters:** None

**Returns:** Multi-step workflow guide

**Output:**
```
# Security Policy Governance Workflow

Follow these steps to make a policy change:

## Step 1: Describe your policy change
Describe what you want to change in plain language...

## Step 2: Parse the policy
Use the `parse_nl_policy` tool...

## Step 3: Simulate
Use the `simulate_policy` tool...

## Step 4: Apply
Use the `apply_policy` tool...

## Step 5: Verify
Check the `security://blocked-ips` resource...
```

**Usage:**
```
"Show me the governance workflow"
"How do I change security policies?"
"Guide me through a policy update"
```

---

## Security Model

### Preview-Confirm Flow

All destructive tools follow a two-step safety pattern:

```
Step 1: Preview (confirm=false)
├─ Generate signed token
├─ Show impact preview
└─ Return token (5-min TTL)

Step 2: Confirm (confirm=true + token)
├─ Verify HMAC signature
├─ Check token expiry
├─ Validate parameters match
└─ Execute if valid
```

### Token Structure

```
action|params_hash|expiry|signature
  │        │         │       │
  │        │         │       └─ HMAC-SHA256 signature
  │        │         └─────────── Unix timestamp (TTL: 300s)
  │        └─────────────────────── SHA256 hash of parameters
  └──────────────────────────────── Tool name
```

**Example Token:**
```
block_ip_temp|ad1e6296a03b919e531b0062392c1a08eeccaf5de32a676e80e8e6d9d068c50c|1770667331|1c86c96af55d373094642ea76549e285f05673fe84d10993cf8272f8a5138cab
```

### RBAC Permission Matrix

| Tool | Required Permission | Bypass in stdio? |
|------|-------------------|------------------|
| generate_redteam_payloads | `security_threat:read` | Yes |
| score_threat | `security_threat:update` | Yes |
| parse_nl_policy | `security_threat:read` | Yes |
| simulate_policy | `security_threat:read` | Yes |
| block_ip_temp | `security_threat:update` | Only if `MCP_STDIO_TRUSTED=true` |
| unblock_ip | `security_threat:update` | Only if `MCP_STDIO_TRUSTED=true` |
| revoke_token | `security_threat:update` + `user:update` | No |
| create_incident | `security_threat:update` | Only if `MCP_STDIO_TRUSTED=true` |
| apply_policy | `config:update` + `security_threat:update` | No |
| unlock_policy | `config:update` + `security_threat:update` | No |

---

## Usage Examples

### Example 1: Investigate and Block Attack

```
Analyst: "Show me recent high-severity threats"

AI: [Reads security://threats/recent?severity=high]
Found 3 high-severity threats:
1. SQL injection from 203.0.113.45 targeting /api/users
2. Path traversal from 198.51.100.23 targeting /etc/passwd
3. XSS attempt from 192.0.2.100 targeting /api/policies

Analyst: "Block the first IP for 24 hours"

AI: [Calls block_ip_temp with confirm=false]
Preview of blocking 203.0.113.45:
- Duration: 86400 seconds (24 hours)
- Reason: SQL injection attack
- Impact: All requests blocked until 2026-02-10 14:30

Confirm? [yes/no]

Analyst: "yes"

AI: [Calls block_ip_temp with confirm=true + token]
✅ IP 203.0.113.45 blocked until 2026-02-10 14:30
```

### Example 2: Test and Improve Detection

```
Engineer: "Test our XSS detection with 20 payloads"

AI: [Calls generate_redteam_payloads(category="xss", count=20)]
Generated 20 XSS payloads:
- Detected: 16 (80%)
- Missed: 4 (20%)

Missed payloads using techniques:
1. Double URL encoding
2. Unicode fullwidth characters

Suggested improvements:
- Add double-encoding detector
- Add Unicode normalization

Would you like me to show the specific patterns?

Engineer: "Yes, show me the missed ones"

AI: [Shows missed_payloads array]
1. %25%33%43%73%63%72%69%70%74%25%33%45
2. ＜ｓｃｒｉｐｔ＞ａｌｅｒｔ（１）＜／ｓｃｒｉｐｔ＞
...
```

### Example 3: Natural Language Policy

```
Manager: "I want to block all traffic from China and Russia except for our
          partner companies in Moscow and Beijing. Also escalate any SQL
          injection to critical immediately."

AI: Let me break this down:

1. Parse policy:
   [Calls parse_nl_policy]
   Parsed rules:
   - ip_deny: 223.0.0.0/8 (China CIDR)
   - ip_deny: 77.0.0.0/8 (Russia CIDR)
   - ip_allow: <partner CIDRs>
   - severity_override: sql_injection → CRITICAL

2. Simulate against your traffic:
   [Calls simulate_policy]
   Test results:
   - Blocked: 1,234 requests (89% from targeted regions)
   - Allowed: 45 requests (partner IPs)
   - SQL injection escalations: 0 (no recent attacks)

Manager: "Apply it"

AI: [Calls apply_policy with preview-confirm]
✅ Policy applied successfully
- Policy ID: pol_abc123
- Version: 1
- Active: true
- HMAC signature verified
```

### Example 4: Incident Response

```
SOC: "We detected a credential stuffing attack. Create an incident and block
      all IPs that failed login more than 10 times"

AI: [Reads security://threats/stats and security://blocked-ips]

Found 5 IPs with excessive failures:
1. 203.0.113.45 (23 failures)
2. 198.51.100.23 (18 failures)
3. 192.0.2.100 (15 failures)
4. 203.0.113.67 (12 failures)
5. 198.51.100.89 (11 failures)

Creating incident...
[Calls create_incident]

Blocking IPs...
[Calls block_ip_temp for each IP]

✅ Actions completed:
- Incident created: INC-2026-0209-001
- Blocked 5 IPs for 12 hours
- Alert sent to security team
```

---

## Troubleshooting

### MCP Server Won't Start

**Symptom:** `ModuleNotFoundError: No module named 'mcp'`

**Solution:**
```bash
pip install "mcp[cli]>=1.26.0,<2"
```

---

**Symptom:** `Database connection failed`

**Solution:**
```bash
# Check DATABASE_URL is set
echo $DATABASE_URL

# Test connection
psql $DATABASE_URL -c "SELECT 1"

# Init database if needed
python3 -c "from server.models import init_db; import asyncio; asyncio.run(init_db())"
```

---

### Claude Desktop Not Showing MCP

**Symptom:** No hammer icon in sidebar

**Solution:**
1. Check `claude_desktop_config.json` syntax (valid JSON)
2. Verify `command` and `args` point to correct Python
3. Check `cwd` is absolute path to agentgate
4. Restart Claude Desktop completely
5. Check logs: `~/Library/Logs/Claude/mcp.log`

---

### Preview-Confirm Token Expired

**Symptom:** "Token has expired" when confirming

**Solution:**
- Tokens have 5-minute TTL
- Get new preview token and confirm immediately
- For testing, tokens are not reusable (one-time use)

---

### OpenAI MCP Connection Failed

**Symptom:** `external_connector_error` HTTP 424

**Solution:**
```bash
# 1. Verify MCP is running
curl http://localhost:8102/mcp

# 2. Check tunnel is working
curl https://your-tunnel-url.com/mcp

# 3. Ensure URL ends with /mcp
# ✅ Correct: https://xyz.trycloudflare.com/mcp
# ❌ Wrong: https://xyz.trycloudflare.com
```

---

### Detection Rate Too Low

**Symptom:** `generate_redteam_payloads` shows <80% detection

**Solution:**
```bash
# 1. Enable real generator
export ENABLE_REDTEAM_GENERATOR=true

# 2. Check missed payloads
# AI will show specific evasion techniques

# 3. Update patterns in server/policy_governance/kernel/threat_patterns.py

# 4. Re-test
python3 -c "
from server.mcp.ai_redteam import RedTeamGenerator
g = RedTeamGenerator()
report = g.generate_and_test('all', 50)
print(f'Detection rate: {report.global_detection_rate:.1%}')
"
```

---

## Best Practices

### 1. Always Use Preview-Confirm for Destructive Operations

✅ **Do:**
```
"Block this IP" → Preview → Review → Confirm
```

❌ **Don't:**
```
"Block this IP immediately without review"
```

### 2. Test Policies Before Applying

✅ **Do:**
```
Parse → Simulate → Review results → Apply
```

❌ **Don't:**
```
Parse → Apply directly
```

### 3. Use Specific Resource Queries

✅ **Do:**
```
"Show me critical threats from the last hour"
"Get blocked IPs that expire in the next 30 minutes"
```

❌ **Don't:**
```
"Show me everything"
"Get all data"
```

### 4. Regularly Test Detection

```bash
# Weekly detection check
ENABLE_REDTEAM_GENERATOR=true python3 << EOF
from server.mcp.ai_redteam import RedTeamGenerator
g = RedTeamGenerator()
report = g.generate_and_test('all', 100)

if report.global_detection_rate < 0.9:
    print(f"⚠️  Detection rate: {report.global_detection_rate:.1%}")
    print("Action required: Review missed payloads")
else:
    print(f"✅ Detection rate: {report.global_detection_rate:.1%}")
EOF
```

### 5. Monitor MCP Usage

```sql
-- Track MCP tool executions
SELECT
  event_type,
  COUNT(*) as count,
  AVG(EXTRACT(EPOCH FROM (updated_at - created_at))) as avg_duration_seconds
FROM audit_entries
WHERE event_type LIKE 'mcp_%'
GROUP BY event_type
ORDER BY count DESC;
```

### 6. Keep Policies Version-Controlled

```bash
# Export current policy
python3 << EOF
from server.models import SecurityPolicy, get_session_context
import asyncio
import json

async def export():
    async with get_session_context() as session:
        result = await session.execute(
            "SELECT policy_json FROM security_policies WHERE is_active = true"
        )
        policy = result.scalar()
        print(json.dumps(policy, indent=2))

asyncio.run(export())
EOF > policies/active-policy-$(date +%Y%m%d).json
```

### 7. Set Up Alerts for Low Detection Rates

```python
# In monitoring/detection_check.py
from server.mcp.ai_redteam import RedTeamGenerator

def check_detection_rate():
    g = RedTeamGenerator()
    report = g.generate_and_test('all', 50)

    if report.global_detection_rate < 0.8:
        send_alert(
            title="Low Detection Rate",
            message=f"Rate: {report.global_detection_rate:.1%}",
            severity="high"
        )

    return report
```

---

## Advanced Topics

### Custom Tool Development

See [the advanced section in this guide](#advanced-topics) for:
- Creating custom tools
- Extending resource types
- Building new prompt templates

### Scaling MCP

See [the scaling section in this guide](#scaling-mcp) for:
- Multi-instance deployments
- Load balancing
- Caching strategies

### Enterprise Integration

See [the enterprise integration section](#enterprise-integration) for:
- SSO integration
- Custom RBAC rules
- Audit log forwarding

---

## Support and Resources

### Documentation
- **Architecture:** [System Architecture](architecture.md)
- **API Reference:** [AgentGate API Reference](overview.md#api-reference)
- **Security Model:** [Security Model](security.md)

### Testing
- **Validation Contract:** [mcp-ground-truth-schema.md](mcp-ground-truth-schema.md)
- **Security Runtime Model:** [mcp-security-model.md](mcp-security-model.md)

### Community
- **GitHub Issues:** https://github.com/EaCognitive/agentgate/issues
- **Discussions:** https://github.com/EaCognitive/agentgate/discussions
- **Changelog:** [CHANGELOG.md](../CHANGELOG.md)

---

**Last Updated:** February 2026
**MCP Protocol Version:** 2025-11-25
**AgentGate Version:** 1.0.0

---

**Erick Aleman | AI Architect | AI Engineer | erick@eacognitive.com**
