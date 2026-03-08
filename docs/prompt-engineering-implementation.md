# Prompt Engineering Implementation (Current State)

## Status

This document reflects the current repository state as of 2026-02-16.

Prompt engineering is implemented in the SDK/library layer. A REST
`/api/prompt-templates` router is **not** mounted in the active FastAPI app.

## Implemented Components

### 1. Prompt schema models

- `server/models/prompt_schemas.py`
- `server/models/__init__.py`

These define `PromptTemplate` SQLModel structures and related request/response
schemas.

### 2. Prompt template manager

- `ea_agentgate/prompts/manager.py`
- `ea_agentgate/prompts/filters.py`
- `ea_agentgate/prompts/__init__.py`

Core capabilities:

- Variable substitution with template rendering
- Jinja2-backed advanced rendering (when available)
- Built-in prompt filters and safety validation
- Template loading from JSON files

### 3. Prompt middleware

- `ea_agentgate/middleware/prompt_template.py`

Middleware classes:

- `ChainOfThoughtMiddleware`
- `FewShotMiddleware`
- `RoleBasedMiddleware`

These inject prompt-structuring behavior into the agent call path.

### 4. Template library files

- `ea_agentgate/prompts/templates/chain_of_thought.json`
- `ea_agentgate/prompts/templates/few_shot.json`
- `ea_agentgate/prompts/templates/role_based.json`
- `ea_agentgate/prompts/templates/creative_steering.json`

## Verified Usage Pattern

```python
from ea_agentgate import Agent
from ea_agentgate.middleware.prompt_template import ChainOfThoughtMiddleware

agent = Agent(
    name="reasoning-assistant",
    middleware=[
        ChainOfThoughtMiddleware(auto_inject=True, show_steps=True),
    ],
)

result = agent.run(
    tool="generate_text",
    prompt="What is 15% of 200?",
)
```

## Tests Covering This Feature Set

- `tests/test_formal_api_contract.py`
- `tests/test_guardrail_integration.py`
- `tests/test_guardrail_policy.py`

## API Clarification

The following endpoints are documented in older notes and tests but are not
currently exposed by `server/main.py`:

- `GET api/prompt-templates`
- `POST api/prompt-templates`
- `GET api/prompt-templates/{id}`
- `PATCH api/prompt-templates/{id}`
- `DELETE api/prompt-templates/{id}`
- `POST api/prompt-templates/{id}/increment-usage`
- `GET api/prompt-templates/analytics/usage`

If API-backed prompt template management is required, add and mount a dedicated
router module and wire it in `server/main.py`.

## Migration Notes

If you previously depended on the removed/non-mounted prompt-template API:

1. Move calls to SDK middleware usage (`ea_agentgate/middleware/prompt_template.py`).
2. Load template files from `ea_agentgate/prompts/templates/`.
3. Keep schema compatibility via `server/models/prompt_schemas.py`.
