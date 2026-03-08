# AgentGate

AgentGate is a source-available security and governance layer for AI agents. It adds PII protection,
injection defense, approvals, rate limits, audit evidence, and formal verification around model
and tool calls without forcing teams to rebuild their application stack.

## Why Teams Use AgentGate

- Redact PII before prompts leave your infrastructure.
- Block common attack classes such as SQL injection, shell injection, XSS, and prompt attacks.
- Enforce human approvals, rate limits, and budget controls around sensitive operations.
- Capture tamper-evident audit logs and signed decision certificates.
- Run the same project as an SDK, API service, dashboard, CLI, and MCP security server.

## Installation

```bash
pip install ea-agentgate
```

Install the full server profile when you want the local API, dashboard, auth, and governance
surfaces:

```bash
pip install "ea-agentgate[server]"
```

## Minimal SDK Example

```python
from ea_agentgate import Agent
from ea_agentgate.middleware import PIIVault, Validator

agent = Agent(
    middleware=[
        PIIVault(mask_ssn=True, mask_email=True, mask_credit_card=True),
        Validator(block_sql_injection=True, block_shell_injection=True),
    ]
)
```

## Project Links

- Repository: [github.com/eacognitive/agentgate](https://github.com/EaCognitive/agentgate)
- Full README: [GitHub README](https://github.com/EaCognitive/agentgate#readme)
- Issues: [github.com/eacognitive/agentgate/issues](https://github.com/EaCognitive/agentgate/issues)

## Local Demo Note

The repository demo stack includes a dashboard playground. To get real model responses in that
playground, set `OPENAI_API_KEY` in the root `.env` file before running `./run demo --fresh`.
