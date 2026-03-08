# AgentGate Overview

AgentGate is an AI governance layer that sits between your applications,
agents, and model providers. It enforces security, policy, and runtime
controls before requests leave your boundary.

## What You Get

- PII detection, redaction, and controlled restoration
- Threat blocking for prompt injection, SQL injection, XSS, and shell payloads
- Policy evaluation and approval workflows for sensitive actions
- Audit trails, traces, cost visibility, and formal verification artifacts
- A dashboard, REST API, MCP server, and Python SDK aligned to the same controls

## Recommended Local Flow

1. Run `./run demo --fresh` for a deterministic first launch.
2. Open the dashboard at `http://localhost:3000`.
3. Use the docs hub at `http://localhost:3000/docs`.
4. Use the live API reference at `http://localhost:3000/docs/api-reference`.

Use `./run demo` when you want to keep local state. Use `./run dev` only for
hot-reload development.

## Core Components

1. API server (`/api/*`)
   Authentication, governance, PII protection, traces, costs, approvals, and
   operational APIs.
2. Dashboard (`/`)
   Operator UI for login, traces, threats, approvals, playground, and docs.
3. MCP server (`/mcp`)
   Authenticated tool and resource bridge into the REST API.
4. Data services
   PostgreSQL and Redis for persistence, sessions, rate limiting, and runtime
   coordination.

## Runtime Route Model

- Dashboard docs hub: `/docs`
- Dashboard API reference: `/docs/api-reference`
- Raw backend Scalar endpoint: `/api/reference`
- Backend OpenAPI source: `/openapi.json`

The backend does not expose a duplicate `/docs` route.

## Read Next

- [`demo-guide.md`](demo-guide.md) for the local demo and validation path
- [`mcp-server.md`](mcp-server.md) for MCP integration and operator access
- [`command-reference.md`](command-reference.md) for the canonical `./run` entry
- [`docker-deployment.md`](docker-deployment.md) for container deployment
