"""Policy definitions for the dashboard demo seed script.

Each policy document follows the PolicyJsonDocument schema and is
submitted to the backend via POST /api/policies.
"""

from __future__ import annotations

POLICY_DOCS: list[dict] = [
    {
        "policy_set_id": "pci-dss-cardholder",
        "version": "2.1",
        "description": "PCI DSS cardholder data protection rules",
        "default_effect": "deny",
        "rules": [
            {
                "rule_id": "block-card-exfil",
                "effect": "deny",
                "description": "Block cardholder data extraction",
                "priority": 10,
                "conditions": [
                    {
                        "field": "tool",
                        "operator": "eq",
                        "value": "db_query",
                    },
                    {
                        "field": "input.query",
                        "operator": "contains",
                        "value": "credit_card",
                    },
                ],
            },
            {
                "rule_id": "allow-masked-read",
                "effect": "allow",
                "description": "Allow masked reads for reporting",
                "priority": 20,
                "conditions": [
                    {
                        "field": "input.masked",
                        "operator": "eq",
                        "value": True,
                    },
                ],
            },
        ],
    },
    {
        "policy_set_id": "hipaa-phi-access",
        "version": "1.0",
        "description": ("HIPAA protected health information access controls"),
        "default_effect": "deny",
        "rules": [
            {
                "rule_id": "deny-phi-export",
                "effect": "deny",
                "description": "Prevent bulk PHI export",
                "priority": 5,
                "conditions": [
                    {
                        "field": "tool",
                        "operator": "in",
                        "value": ["email_send", "slack_post"],
                    },
                ],
            },
            {
                "rule_id": "allow-authorized-clinician",
                "effect": "allow",
                "description": ("Allow read access for authenticated clinical staff"),
                "priority": 10,
                "conditions": [
                    {
                        "field": "action",
                        "operator": "eq",
                        "value": "read",
                    },
                    {
                        "field": "context.role",
                        "operator": "in",
                        "value": [
                            "physician",
                            "nurse",
                            "pharmacist",
                        ],
                    },
                ],
            },
        ],
    },
    {
        "policy_set_id": "prompt-injection-guard",
        "version": "3.0",
        "description": ("Prompt injection and jailbreak prevention rules"),
        "default_effect": "allow",
        "rules": [
            {
                "rule_id": "block-ignore-instructions",
                "effect": "deny",
                "description": ("Block ignore-previous-instructions attacks"),
                "priority": 1,
                "conditions": [
                    {
                        "field": "input.message",
                        "operator": "contains",
                        "value": "ignore",
                    },
                ],
            },
            {
                "rule_id": "block-system-prompt-leak",
                "effect": "deny",
                "description": ("Prevent system prompt extraction"),
                "priority": 2,
                "conditions": [
                    {
                        "field": "input.message",
                        "operator": "contains",
                        "value": "system prompt",
                    },
                ],
            },
            {
                "rule_id": "block-sql-injection",
                "effect": "deny",
                "description": "Block SQL injection payloads",
                "priority": 3,
                "conditions": [
                    {
                        "field": "input.message",
                        "operator": "matches",
                        "value": "DROP|DELETE|TRUNCATE",
                    },
                ],
            },
        ],
    },
    {
        "policy_set_id": "prod-write-guard",
        "version": "1.2",
        "description": ("Require human approval for production database writes and deletes"),
        "default_effect": "allow",
        "rules": [
            {
                "rule_id": "block-prod-write",
                "effect": "deny",
                "description": ("Block direct writes to production databases"),
                "priority": 1,
                "conditions": [
                    {
                        "field": "action",
                        "operator": "in",
                        "value": [
                            "write",
                            "delete",
                            "update",
                        ],
                    },
                    {
                        "field": "resource",
                        "operator": "contains",
                        "value": "production",
                    },
                ],
            },
            {
                "rule_id": "block-prod-drop",
                "effect": "deny",
                "description": ("Block destructive DDL on production"),
                "priority": 2,
                "conditions": [
                    {
                        "field": "input.query",
                        "operator": "matches",
                        "value": ("DROP|TRUNCATE|ALTER.*DROP"),
                    },
                    {
                        "field": "context.environment",
                        "operator": "eq",
                        "value": "production",
                    },
                ],
            },
            {
                "rule_id": "allow-staging-write",
                "effect": "allow",
                "description": ("Allow writes to staging environments"),
                "priority": 10,
                "conditions": [
                    {
                        "field": "context.environment",
                        "operator": "in",
                        "value": ["staging", "development"],
                    },
                ],
            },
        ],
    },
    {
        "policy_set_id": "external-api-rate-limit",
        "version": "1.0",
        "description": ("Rate limiting and access control for external API calls"),
        "default_effect": "allow",
        "rules": [
            {
                "rule_id": "block-high-volume-api",
                "effect": "deny",
                "description": ("Block API calls exceeding 100 requests per minute"),
                "priority": 1,
                "conditions": [
                    {
                        "field": "tool",
                        "operator": "eq",
                        "value": "web_search",
                    },
                    {
                        "field": "context.requests_per_minute",
                        "operator": "gt",
                        "value": 100,
                    },
                ],
            },
            {
                "rule_id": "block-unapproved-endpoints",
                "effect": "deny",
                "description": ("Block calls to endpoints not on the approved list"),
                "priority": 5,
                "conditions": [
                    {
                        "field": "input.url",
                        "operator": "not_contains",
                        "value": "api.approved-vendor.com",
                    },
                    {
                        "field": "context.endpoint_approved",
                        "operator": "eq",
                        "value": False,
                    },
                ],
            },
        ],
    },
    {
        "policy_set_id": "data-residency-eu",
        "version": "2.0",
        "description": ("GDPR data residency enforcement for EU citizen data"),
        "default_effect": "deny",
        "rules": [
            {
                "rule_id": "block-cross-border-transfer",
                "effect": "deny",
                "description": ("Block data transfers outside EU jurisdiction"),
                "priority": 1,
                "conditions": [
                    {
                        "field": "context.data_classification",
                        "operator": "in",
                        "value": [
                            "pii",
                            "sensitive",
                            "restricted",
                        ],
                    },
                    {
                        "field": "context.target_region",
                        "operator": "not_in",
                        "value": [
                            "eu-west-1",
                            "eu-central-1",
                            "eu-north-1",
                        ],
                    },
                ],
            },
            {
                "rule_id": "allow-anonymized-transfer",
                "effect": "allow",
                "description": ("Allow cross-border transfer for anonymized datasets"),
                "priority": 10,
                "conditions": [
                    {
                        "field": "context.anonymized",
                        "operator": "eq",
                        "value": True,
                    },
                ],
            },
            {
                "rule_id": "allow-eu-internal",
                "effect": "allow",
                "description": ("Allow transfers within EU regions"),
                "priority": 5,
                "conditions": [
                    {
                        "field": "context.target_region",
                        "operator": "in",
                        "value": [
                            "eu-west-1",
                            "eu-central-1",
                            "eu-north-1",
                        ],
                    },
                ],
            },
        ],
    },
    {
        "policy_set_id": "privilege-escalation-guard",
        "version": "1.1",
        "description": (
            "Prevent agents from escalating their own permissions or modifying access controls"
        ),
        "default_effect": "allow",
        "rules": [
            {
                "rule_id": "block-self-escalation",
                "effect": "deny",
                "description": ("Block agents from modifying their own permission grants"),
                "priority": 1,
                "conditions": [
                    {
                        "field": "resource",
                        "operator": "contains",
                        "value": "iam/permissions",
                    },
                    {
                        "field": "action",
                        "operator": "in",
                        "value": [
                            "write",
                            "update",
                            "create",
                        ],
                    },
                ],
            },
            {
                "rule_id": "block-role-assignment",
                "effect": "deny",
                "description": ("Prevent agents from assigning admin roles"),
                "priority": 2,
                "conditions": [
                    {
                        "field": "input.role",
                        "operator": "in",
                        "value": [
                            "admin",
                            "superadmin",
                            "root",
                        ],
                    },
                    {
                        "field": "resource",
                        "operator": "contains",
                        "value": "roles",
                    },
                ],
            },
        ],
    },
    {
        "policy_set_id": "model-output-filter",
        "version": "2.3",
        "description": ("Content safety filters for model-generated outputs before delivery"),
        "default_effect": "allow",
        "rules": [
            {
                "rule_id": "block-toxic-output",
                "effect": "deny",
                "description": ("Block outputs flagged as toxic or harmful by content classifier"),
                "priority": 1,
                "conditions": [
                    {
                        "field": "context.toxicity_score",
                        "operator": "gt",
                        "value": 0.85,
                    },
                ],
            },
            {
                "rule_id": "block-pii-in-output",
                "effect": "deny",
                "description": ("Block model outputs containing detected PII entities"),
                "priority": 2,
                "conditions": [
                    {
                        "field": "context.pii_detected",
                        "operator": "eq",
                        "value": True,
                    },
                    {
                        "field": "context.output_redacted",
                        "operator": "eq",
                        "value": False,
                    },
                ],
            },
            {
                "rule_id": "block-code-execution-output",
                "effect": "deny",
                "description": ("Block outputs containing executable code patterns"),
                "priority": 3,
                "conditions": [
                    {
                        "field": "context.contains_executable",
                        "operator": "eq",
                        "value": True,
                    },
                    {
                        "field": "context.sandbox_enabled",
                        "operator": "eq",
                        "value": False,
                    },
                ],
            },
        ],
    },
    {
        "policy_set_id": "financial-data-access",
        "version": "1.4",
        "description": ("SOX-compliant access controls for financial records and trading data"),
        "default_effect": "deny",
        "rules": [
            {
                "rule_id": "allow-read-authorized",
                "effect": "allow",
                "description": ("Allow read access for authorized finance agents"),
                "priority": 10,
                "conditions": [
                    {
                        "field": "action",
                        "operator": "eq",
                        "value": "read",
                    },
                    {
                        "field": "context.clearance",
                        "operator": "in",
                        "value": [
                            "finance-l2",
                            "finance-l3",
                            "audit",
                        ],
                    },
                ],
            },
            {
                "rule_id": "deny-bulk-export",
                "effect": "deny",
                "description": ("Deny bulk exports of financial records exceeding 1000 rows"),
                "priority": 1,
                "conditions": [
                    {
                        "field": "context.row_count",
                        "operator": "gt",
                        "value": 1000,
                    },
                    {
                        "field": "tool",
                        "operator": "in",
                        "value": [
                            "db_query",
                            "file_read",
                        ],
                    },
                ],
            },
            {
                "rule_id": "deny-after-hours",
                "effect": "deny",
                "description": ("Deny access outside business hours without override"),
                "priority": 5,
                "conditions": [
                    {
                        "field": "context.business_hours",
                        "operator": "eq",
                        "value": False,
                    },
                    {
                        "field": "context.override_token",
                        "operator": "not_exists",
                        "value": "",
                    },
                ],
            },
        ],
    },
    {
        "policy_set_id": "secret-detection-guard",
        "version": "1.0",
        "description": (
            "Prevent agents from exposing secrets, API keys, or credentials in outputs"
        ),
        "default_effect": "allow",
        "rules": [
            {
                "rule_id": "block-secret-leak",
                "effect": "deny",
                "description": ("Block outputs containing detected secret patterns"),
                "priority": 1,
                "conditions": [
                    {
                        "field": "context.secret_detected",
                        "operator": "eq",
                        "value": True,
                    },
                ],
            },
            {
                "rule_id": "block-env-dump",
                "effect": "deny",
                "description": ("Block attempts to dump environment variables"),
                "priority": 2,
                "conditions": [
                    {
                        "field": "input.message",
                        "operator": "matches",
                        "value": ("env|ENV|environment|printenv|os\\.environ"),
                    },
                    {
                        "field": "tool",
                        "operator": "eq",
                        "value": "code_interpreter",
                    },
                ],
            },
        ],
    },
]

# Policies to load into the runtime engine during demo seeding.
LOAD_POLICIES = [
    "prompt-injection-guard",
    "prod-write-guard",
    "secret-detection-guard",
    "model-output-filter",
]

# Compliance-critical policies to lock (prevent modification).
LOCK_POLICIES = [
    "pci-dss-cardholder",
    "hipaa-phi-access",
    "data-residency-eu",
    "financial-data-access",
]

# Policies to mark as active via DB ID endpoint.
ACTIVATE_POLICIES = {
    "prompt-injection-guard",
    "prod-write-guard",
    "secret-detection-guard",
    "model-output-filter",
    "privilege-escalation-guard",
}
