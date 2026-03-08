# Policy-as-Code Engine

The Policy-as-Code engine provides declarative, JSON-based security policies that can be hot-swapped without code deploys. Inspired by OPA/Rego, it decouples guardrail logic from Python code for easier governance and compliance.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Policy Schema](#policy-schema)
- [Operators](#operators)
- [Priority and Conflict Resolution](#priority-and-conflict-resolution)
- [Hot-Swapping Policies](#hot-swapping-policies)
- [Middleware Integration](#middleware-integration)
- [API Endpoints](#api-endpoints)
- [Examples](#examples)
- [Best Practices](#best-practices)

## Overview

### Key Features

- **Declarative JSON Policies**: Define security rules as JSON without writing Python code
- **Hot-Swapping**: Load/unload policies at runtime without restarting services
- **Priority-Based Resolution**: Conflict resolution using rule priorities
- **Rich Operators**: 14 condition operators including regex, comparisons, and existence checks
- **Thread-Safe**: Concurrent policy evaluation and management
- **HMAC Signatures**: Tamper-evident policy storage with integrity verification
- **Shadow Mode**: Test policies without blocking requests
- **Integration Ready**: Works with existing middleware chain

### When to Use

- **Compliance Requirements**: Audit-friendly governance with version-controlled policies
- **Dynamic Security**: Change security rules based on threat intelligence
- **Multi-Environment**: Different policies for dev/staging/production
- **A/B Testing**: Compare policy effectiveness with shadow mode
- **Separation of Concerns**: Security teams manage policies, engineers manage code

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PolicyEngine                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Thread-Safe Policy Registry                         │  │
│  │  - Load/unload policy sets                           │  │
│  │  - Validate policy schemas                           │  │
│  │  - Store compiled regex patterns                     │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Evaluation Engine                                    │  │
│  │  - Condition evaluation                              │  │
│  │  - Priority-based conflict resolution               │  │
│  │  - Dot-notation field access                        │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ PolicyDecision
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  PolicyMiddleware                           │
│  - Converts MiddlewareContext to request context           │
│  - Enforces or logs policy decisions                       │
│  - Stores decision metadata in context                     │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   Agent Tool Execution                      │
└─────────────────────────────────────────────────────────────┘
```

## Policy Schema

### PolicySet

A collection of rules with a default effect.

```json
{
  "policy_set_id": "unique_identifier",
  "version": "1.0.0",
  "description": "Human-readable description",
  "default_effect": "allow|deny",
  "rules": [...]
}
```

### PolicyRule

A single evaluable rule with conditions and effect.

```json
{
  "rule_id": "unique_rule_id",
  "description": "Human-readable description",
  "priority": 100,
  "effect": "allow|deny",
  "conditions": [...]
}
```

### PolicyCondition

A single condition to evaluate.

```json
{
  "field": "request.tool",
  "operator": "eq|neq|in|not_in|contains|matches|gt|lt|...",
  "value": "expected_value"
}
```

## Operators

### Equality Operators

- **`eq`**: Field equals value (exact match)
- **`neq`**: Field does not equal value

```json
{
  "field": "request.tool",
  "operator": "eq",
  "value": "delete_file"
}
```

### List Operators

- **`in`**: Field value is in list
- **`not_in`**: Field value is not in list

```json
{
  "field": "request.tool",
  "operator": "in",
  "value": ["rm", "delete", "drop"]
}
```

### String Operators

- **`contains`**: Field contains substring or list contains value
- **`not_contains`**: Field does not contain substring

```json
{
  "field": "request.inputs.path",
  "operator": "contains",
  "value": "../"
}
```

### Regex Operator

- **`matches`**: Field matches regex pattern

```json
{
  "field": "request.tool",
  "operator": "matches",
  "value": "^delete_.*"
}
```

### Comparison Operators

- **`gt`**: Greater than (numeric)
- **`lt`**: Less than (numeric)
- **`gte`**: Greater than or equal (numeric)
- **`lte`**: Less than or equal (numeric)

```json
{
  "field": "request.inputs.count",
  "operator": "gt",
  "value": 1000
}
```

### Existence Operators

- **`exists`**: Field exists (not None)
- **`not_exists`**: Field does not exist (is None)

```json
{
  "field": "request.user.id",
  "operator": "not_exists",
  "value": null
}
```

## Priority and Conflict Resolution

### How Priority Works

- Rules are evaluated in **priority order** (highest first)
- When multiple rules match, the **highest priority** wins
- Priority is an integer (default: 0, higher = more important)

### Example: Priority Conflict

```json
{
  "rules": [
    {
      "rule_id": "general_allow",
      "priority": 10,
      "effect": "allow",
      "conditions": [
        {"field": "request.tool", "operator": "matches", "value": "^read_.*"}
      ]
    },
    {
      "rule_id": "block_sensitive",
      "priority": 100,
      "effect": "deny",
      "conditions": [
        {"field": "request.tool", "operator": "eq", "value": "read_secrets"}
      ]
    }
  ]
}
```

For `read_secrets`:
- Both rules match
- `block_sensitive` has priority 100 > `general_allow` priority 10
- **Result: DENY**

### Default Effect

When **no rules match**, the `default_effect` is applied.

```json
{
  "default_effect": "deny"
}
```

Recommended: Use `"deny"` for security-first policies.

## Hot-Swapping Policies

### Loading a Policy

```python
from ea_agentgate.security.policy_engine import PolicyEngine

engine = PolicyEngine()
policy_set = engine.load_policy_from_file("policies/default.json")
engine.load_policy_set(policy_set)
```

### Unloading a Policy

```python
engine.unload_policy_set("policy_set_id")
```

### Hot-Swap Without Downtime

```python
# Load new version
new_policy = engine.load_policy_from_file("policies/v2.json")

# Atomic swap
engine.unload_policy_set("my_policy")
engine.load_policy_set(new_policy)
```

Thread-safe operations ensure no race conditions during swaps.

## Middleware Integration

### Basic Setup

```python
from ea_agentgate.middleware.policy_middleware import PolicyMiddleware
from ea_agentgate.security.policy_engine import PolicyEngine

engine = PolicyEngine()
policy_set = engine.load_policy_from_file("policies/default.json")
engine.load_policy_set(policy_set)

middleware = PolicyMiddleware(
    engine=engine,
    policy_set_id="default",
    mode="enforce",
    on_deny="block",
)

agent = Agent(middleware=[middleware])
```

### Modes

#### Enforce Mode

Blocks requests that violate policies.

```python
middleware = PolicyMiddleware(
    engine=engine,
    mode="enforce",
    on_deny="block",
)
```

#### Shadow Mode

Logs violations without blocking (useful for testing).

```python
middleware = PolicyMiddleware(
    engine=engine,
    mode="shadow",
)
```

### On Deny Actions

- **`"block"`**: Raise `GuardrailViolationError`
- **`"log"`**: Log error without raising exception

### Evaluate All Policy Sets

Pass `policy_set_id=None` to evaluate against all loaded policies:

```python
middleware = PolicyMiddleware(
    engine=engine,
    policy_set_id=None,  # Evaluate all sets
    mode="enforce",
)
```

## API Endpoints

### List Policies

```http
GET /api/policies
Authorization: Bearer <token>
```

**Response:**

```json
{
  "loaded_policies": ["default", "pii_protection"],
  "db_policies": [
    {
      "policy_set_id": "default",
      "version": "1.0.0",
      "description": "Default guardrails",
      "default_effect": "allow",
      "rule_count": 7,
      "loaded": true,
      "db_id": 1,
      "origin": "manual",
      "locked": false
    }
  ]
}
```

### Create Policy

```http
POST /api/policies
Authorization: Bearer <token>
Content-Type: application/json

{
  "policy_json": {
    "policy_set_id": "custom_policy",
    "version": "1.0.0",
    "description": "Custom rules",
    "default_effect": "deny",
    "rules": [...]
  },
  "origin": "manual",
  "locked": false
}
```

### Delete Policy

```http
DELETE /api/policies/{policy_set_id}
Authorization: Bearer <token>
```

### Evaluate Policy (Testing)

```http
POST /api/policies/evaluate
Authorization: Bearer <token>
Content-Type: application/json

{
  "policy_set_id": "default",
  "request_context": {
    "request": {
      "tool": "delete_file",
      "inputs": {"path": "/etc/passwd"}
    }
  }
}
```

**Response:**

```json
{
  "allowed": false,
  "effect": "deny",
  "matched_rules": ["block_dangerous_paths"],
  "reason": "Matched rules: block_dangerous_paths, effect: deny",
  "policy_set_id": "default",
  "evaluation_time_ms": 1.23
}
```

### Load Policy from Database

```http
POST /api/policies/{db_id}/load
Authorization: Bearer <token>
```

Loads a stored policy into the engine with HMAC verification.

## Examples

### Example 1: Block Dangerous Tools

```json
{
  "policy_set_id": "basic_security",
  "version": "1.0.0",
  "description": "Basic security guardrails",
  "default_effect": "allow",
  "rules": [
    {
      "rule_id": "block_dangerous_commands",
      "description": "Block dangerous system commands",
      "priority": 100,
      "effect": "deny",
      "conditions": [
        {
          "field": "request.tool",
          "operator": "in",
          "value": ["rm", "exec", "eval", "delete"]
        }
      ]
    }
  ]
}
```

### Example 2: Require Authentication

```json
{
  "rule_id": "require_auth_for_pii",
  "description": "Require user ID for PII access",
  "priority": 90,
  "effect": "deny",
  "conditions": [
    {
      "field": "request.tool",
      "operator": "contains",
      "value": "pii"
    },
    {
      "field": "request.user.id",
      "operator": "not_exists",
      "value": null
    }
  ]
}
```

### Example 3: Path Traversal Protection

```json
{
  "rule_id": "block_path_traversal",
  "description": "Block path traversal attempts",
  "priority": 95,
  "effect": "deny",
  "conditions": [
    {
      "field": "request.inputs.path",
      "operator": "contains",
      "value": "../"
    }
  ]
}
```

### Example 4: Rate Limiting via Metadata

```json
{
  "rule_id": "block_high_frequency_users",
  "description": "Block users with high request frequency",
  "priority": 80,
  "effect": "deny",
  "conditions": [
    {
      "field": "request.metadata.request_count",
      "operator": "gt",
      "value": 100
    }
  ]
}
```

### Example 5: Multi-Condition Rules

```json
{
  "rule_id": "block_sensitive_file_delete",
  "description": "Block deletion of sensitive files",
  "priority": 100,
  "effect": "deny",
  "conditions": [
    {
      "field": "request.tool",
      "operator": "matches",
      "value": "^(delete|rm)_.*"
    },
    {
      "field": "request.inputs.path",
      "operator": "matches",
      "value": "^(/etc|/bin|/secrets/)"
    }
  ]
}
```

All conditions must match (AND logic).

## Best Practices

### Policy Design

1. **Use High Priorities for Security Rules**
   - Security-critical rules: 90-100
   - Normal rules: 10-50
   - Default/fallback rules: 1-9

2. **Prefer Deny-by-Default**
   ```json
   {
     "default_effect": "deny"
   }
   ```

3. **Be Specific with Regex**
   ```json
   // Good: Anchored pattern
   {"operator": "matches", "value": "^delete_file$"}

   // Bad: Overly broad
   {"operator": "matches", "value": "delete"}
   ```

4. **Use Descriptive IDs and Descriptions**
   ```json
   {
     "rule_id": "block_root_filesystem_access",
     "description": "Prevent access to root filesystem directories"
   }
   ```

### Security

1. **Validate Policies Before Production**
   ```python
   errors = validate_policy_set(policy_set)
   if errors:
       raise ValueError(f"Invalid policy: {errors}")
   ```

2. **Use Shadow Mode for Testing**
   ```python
   # Test new policy in shadow mode first
   middleware = PolicyMiddleware(engine=engine, mode="shadow")
   ```

3. **Lock Critical Policies**
   ```json
   {
     "locked": true
   }
   ```

4. **Version Your Policies**
   - Use semantic versioning: `"1.0.0"`, `"1.1.0"`, `"2.0.0"`
   - Store in version control (Git)
   - Tag releases

### Performance

1. **Compile Regex at Load Time**
   - The engine pre-compiles regex patterns during validation
   - Validation errors caught early

2. **Use Specific Field Paths**
   ```json
   // Good
   {"field": "request.inputs.path"}

   // Avoid deep nesting
   {"field": "request.metadata.extra.nested.field"}
   ```

3. **Monitor Evaluation Time**
   ```python
   decision = engine.evaluate(...)
   print(f"Eval time: {decision.evaluation_time_ms}ms")
   ```

### Governance

1. **Separate Policies by Domain**
   - `default_guardrails.json`: General security
   - `pii_protection.json`: PII-specific rules
   - `compliance_hipaa.json`: HIPAA requirements

2. **Document Rule Intent**
   ```json
   {
     "rule_id": "gdpr_data_deletion",
     "description": "GDPR Article 17: Right to erasure. Blocks PII deletion without consent.",
     "priority": 100
   }
   ```

3. **Audit Policy Changes**
   - Log all policy loads/unloads
   - Store HMAC signatures
   - Review changes before deployment

4. **Use Policy Evaluation Endpoint for Testing**
   ```bash
   curl -X POST /api/policies/evaluate \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"policy_set_id": "default", "request_context": {...}}'
   ```

## Related Documentation

- [Resilience Features](./resilience-features.md) - Stateful and reliability-focused controls
- [System Architecture](./architecture.md) - Middleware and execution architecture
- [Security](./security.md) - Security best practices
- [API Reference](overview.md#api-reference) - Complete API documentation

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/agentgate/issues
- Documentation: https://docs.agentgate.io
- Examples: `ea_agentgate/examples/policy_engine_demo.py`
