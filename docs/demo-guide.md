# Demo Guide

Use this guide for the portfolio-ready local demo, shareable demo links, and
the distinction between the production-like runtime and developer hot reload.

## Launch Modes

| Goal | Command | Result |
|---|---|---|
| First clean demo run | `./run demo --fresh` | Rebuilds the Docker stack, resets local state, and starts the production dashboard on `localhost:3000` |
| Repeat demo run | `./run demo` | Reuses existing local data and restarts the stack |
| Developer-only hot reload | `./run dev` | Starts `uvicorn --reload` and `next dev`; use this only when actively editing code |

## Portfolio Validation Path

After `./run demo` completes:

1. Open the dashboard at `http://localhost:3000/login`.
2. Open the docs hub at `http://localhost:3000/docs`.
3. Open the API reference at `http://localhost:3000/docs/api-reference`.
4. Confirm backend health at `http://localhost:8000/api/health`.

If you need the raw backend reference for debugging, use
`http://localhost:8000/api/reference`.

## Demo Account and Share Links

AgentGate supports time-limited demo links backed by real demo accounts.

Required server variables:

| Variable | Required | Description |
|---|---|---|
| `DEMO_LINK_SECRET` | Yes | HMAC-SHA256 signing key for demo tokens |
| `DEMO_ACCOUNT_EMAIL` | Yes | Primary demo account email |
| `DEMO_ACCOUNT_PASSWORD` | Yes | Primary demo account password |
| `DEMO_ACCOUNT_EMAIL_1`..`_9` | No | Additional demo accounts |
| `DEMO_ACCOUNT_PASSWORD_1`..`_9` | No | Passwords for additional demo accounts |

Generate a share link:

```bash
python3 scripts/generate_demo_link.py --days 7
python3 scripts/generate_demo_link.py --days 2 --user 1
```

The script returns a `/d/<token>` URL. Tokens are signed, time-limited, and
bound to the selected demo account index.

## Demo Link Flow

1. Viewer opens `/d/<token>`.
2. The dashboard validates the token signature and expiry.
3. The token maps to a configured demo account.
4. The backend authenticates that account through `POST /api/auth/login`.
5. The viewer lands in the dashboard with a valid session.

All demo logins are recorded in the audit log with `provider_hint=demo_link`.

## Content Protection Mode

Set `NEXT_PUBLIC_DEMO_MODE=true` to harden live demos against casual copying.

Enabled protections:

- blocks save, print, and DevTools keyboard shortcuts
- blocks the context menu
- disables text selection through the `demo-protected` body class

This mode is presentation hardening only. It is not a substitute for access
control or backend policy enforcement.

## Reset and Cleanup

Use `./run demo --fresh` whenever you need a clean presentation state.

For a full destructive reset outside the guided demo path:

```bash
docker compose down --volumes --remove-orphans
docker compose up -d --build
```

Run destructive resets only in local or non-production environments.
