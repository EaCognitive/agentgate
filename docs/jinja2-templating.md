# Jinja2 Dynamic Prompt Templating

This guide covers the advanced Jinja2 templating system for prompt engineering in AgentGate.

## Overview

The Jinja2 templating system provides enterprise-grade prompt engineering capabilities:

- **Variable Substitution**: Simple `{{variable}}` replacement
- **Conditionals**: Dynamic prompt adaptation based on context
- **Loops**: Iterate over examples, constraints, or data
- **Custom Filters**: Prompt-specific text transformations
- **Macros**: Reusable template components
- **Validation**: Syntax checking before rendering
- **Security**: Sandboxed execution environment

## Quick Start

### Basic Variable Substitution

```python
from ea_agentgate.prompts import Jinja2TemplateEngine

engine = Jinja2TemplateEngine()

template = "Hello {{name}}, you are {{age}} years old."
result = engine.render(template, {"name": "Alice", "age": 30})
# Output: "Hello Alice, you are 30 years old."
```

### Using PromptTemplateManager

```python
from ea_agentgate.prompts import PromptTemplateManager

manager = PromptTemplateManager()

result = manager.apply_template(
    "Hello {{name}}",
    {"name": "Bob"}
)
```

## Advanced Features

### 1. Conditionals

Adapt prompts based on context:

```python
template = """
You are a {% if context.audience == "technical" %}senior engineer
{% elif context.audience == "business" %}business analyst
{% else %}team member{% endif %}.

{% if context.urgent %}URGENT: {% endif %}Please review this proposal.
"""

result = engine.render(template, {
    "context": {
        "audience": "technical",
        "urgent": True
    }
})
```

### 2. Loops

Iterate over collections:

```python
template = """
Review Checklist:
{% for item in checklist -%}
{{ loop.index }}. {{ item }}
{% endfor %}
"""

result = engine.render(template, {
    "checklist": [
        "Verify code correctness",
        "Check security vulnerabilities",
        "Review performance impact"
    ]
})
```

### 3. Custom Filters

Transform text with prompt-specific filters:

```python
# Escape potentially dangerous input
template = "Task: {{user_input|escape_prompt}}"

# Format lists
template = "Items:\n{{items|format_list(style='bulleted')}}"

# Truncate to approximate token count
template = "Summary: {{text|truncate_tokens(100)}}"

# Convert to uppercase
template = "{{name|uppercase}}"

# Wrap in XML tags
template = "{{content|wrap_xml(tag='task')}}"

# Pretty-print JSON
template = "Config:\n{{config|format_json}}"

# Sanitize text
template = "{{text|sanitize}}"
```

### 4. Macros

Create reusable components:

```python
template = """
{%- macro format_example(input, output) -%}
Input: {{ input }}
Output: {{ output }}
{%- endmacro -%}

Example 1:
{{ format_example("What is 2+2?", "4") }}

Example 2:
{{ format_example("What is 3+3?", "6") }}
"""

result = engine.render(template, {})
```

### 5. Template Validation

Validate syntax before rendering:

```python
engine = Jinja2TemplateEngine()

is_valid, error = engine.validate("Hello {{name}}")
if not is_valid:
    print(f"Invalid template: {error}")
```

## Available Custom Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `escape_prompt` | Escape prompt injection patterns | `{{text|escape_prompt}}` |
| `truncate_tokens(n)` | Truncate to ~n tokens | `{{text|truncate_tokens(100)}}` |
| `format_list(style)` | Format list as numbered/bulleted | `{{items|format_list(style='numbered')}}` |
| `format_json(indent)` | Pretty-print JSON | `{{data|format_json}}` |
| `sanitize` | Remove dangerous characters | `{{text|sanitize}}` |
| `wrap_xml(tag)` | Wrap in XML tags | `{{content|wrap_xml(tag='message')}}` |
| `uppercase` | Convert to uppercase | `{{text|uppercase}}` |
| `lowercase` | Convert to lowercase | `{{text|lowercase}}` |

## Security Features

The Jinja2TemplateEngine uses a sandboxed environment that prevents:

- File system access
- Network operations
- Arbitrary code execution
- Access to private attributes
- Dangerous built-in functions

```python
# Safe - will render normally
template = "Hello {{name}}"

# Safe - will raise SecurityError
template = "{{__import__('os').system('ls')}}"
```

## JSON Template Format

Templates can be stored in JSON files and loaded dynamically:

```json
{
  "name": "Technical Writer",
  "category": "role_based",
  "system_prompt": "You are a Technical Writer.",
  "user_prompt_prefix": "{% if context.audience == 'beginner' %}
Explain in simple terms.
{% else %}
Be concise and technical.
{% endif %}",
  "variables": {
    "feature": "The feature to document",
    "context": {
      "audience": "beginner | intermediate | expert"
    }
  }
}
```

Load with:

```python
manager = PromptTemplateManager()
template_str = manager.load_template_from_file("templates/role_based.json")
```

## Real-World Example

Comprehensive prompt with multiple features:

```python
from ea_agentgate.prompts import Jinja2TemplateEngine

engine = Jinja2TemplateEngine()

template = """
You are a {{role.name}}.
{{role.description}}

{% if role.expertise -%}
Areas of Expertise:
{{ role.expertise|format_list(style='bulleted') }}
{% endif %}

Communication Style: {% if context.formal %}Formal{% else %}Casual{% endif %}

{% if examples -%}
Examples:
{% for example in examples[:3] -%}
Example {{loop.index}}:
Input: {{example.input|truncate_tokens(30)}}
Output: {{example.output|truncate_tokens(30)}}

{% endfor %}
{%- endif %}

Task: {{task|wrap_xml(tag='task')|escape_prompt}}

{% if priority == "high" -%}
PRIORITY: HIGH
{% endif %}
"""

context = {
    "role": {
        "name": "Senior Security Engineer",
        "description": "Expert in application security.",
        "expertise": ["OWASP Top 10", "Penetration Testing"]
    },
    "context": {"formal": True},
    "examples": [
        {
            "input": "Review authentication flow",
            "output": "Found SQL injection vulnerability"
        }
    ],
    "task": "Audit payment processing module",
    "priority": "high"
}

result = engine.render(template, context)
```

## Backward Compatibility

The system maintains full backward compatibility:

```python
manager = PromptTemplateManager()

# Old style - still works
result = manager.apply_template(
    "Hello {{name}}",
    {"name": "Alice"}
)

# New style - advanced features
result = manager.apply_template(
    "{% if premium %}VIP{% endif %} {{name|uppercase}}",
    {"premium": True, "name": "alice"}
)

# Disable advanced engine if needed
result = manager.apply_template(
    "Hello {{name}}",
    {"name": "Bob"},
    use_advanced_engine=False
)
```

## Best Practices

1. **Validate Templates**: Always validate templates before production use:
   ```python
   is_valid, error = engine.validate(template)
   if not is_valid:
       raise ValueError(f"Invalid template: {error}")
   ```

2. **Escape User Input**: Use `escape_prompt` filter for user-provided content:
   ```python
   template = "Task: {{user_input|escape_prompt}}"
   ```

3. **Limit Loop Iterations**: Prevent excessive token usage:
   ```python
   template = "{% for item in items[:5] %}{{ item }}{% endfor %}"
   ```

4. **Use Truncation**: Control output length:
   ```python
   template = "{{description|truncate_tokens(100)}}"
   ```

5. **Sanitize Text**: Remove dangerous characters:
   ```python
   template = "{{content|sanitize}}"
   ```

## Integration with Middleware

Use with prompt template middleware:

```python
from ea_agentgate import Agent
from ea_agentgate.middleware import RoleBasedMiddleware

agent = Agent(
    name="assistant",
    middleware=[
        RoleBasedMiddleware(
            role_name="Code Reviewer",
            role_description="Expert in code quality",
        )
    ]
)
```

## Error Handling

Handle template errors gracefully:

```python
try:
    result = engine.render(template, context)
except ValueError as e:
    if "Missing required variable" in str(e):
        print("Required variable not provided")
    elif "Invalid template" in str(e):
        print("Template syntax error")
    else:
        print(f"Rendering error: {e}")
```

## Performance Considerations

- Template compilation is cached by Jinja2
- Complex templates with many loops may increase latency
- Use `truncate_tokens` to control prompt length
- Validate templates once at startup, not per request

## Additional Resources

- Demo script: `ea_agentgate/examples/jinja2_templating_demo.py`
- Template examples: `ea_agentgate/prompts/templates/`
- Filter documentation: `ea_agentgate/prompts/filters.py`
- Engine source: `ea_agentgate/prompts/manager.py`

## API Reference

### Jinja2TemplateEngine

```python
class Jinja2TemplateEngine:
    def __init__(self):
        """Initialize sandboxed Jinja2 environment."""

    def validate(self, template_str: str) -> tuple[bool, str | None]:
        """Validate template syntax."""

    def render(
        self,
        template_str: str,
        context: dict[str, Any] | None = None,
        validate_first: bool = True
    ) -> str:
        """Render template with context."""

    def get_available_filters(self) -> list[str]:
        """Get list of available filter names."""
```

### PromptTemplateManager

```python
class PromptTemplateManager:
    def apply_template(
        self,
        template: str,
        variables: dict[str, Any] | None = None,
        use_advanced_engine: bool = True
    ) -> str:
        """Apply template with variables."""

    def create_chain_of_thought_prompt(...) -> str:
        """Create chain-of-thought prompt."""

    def create_few_shot_prompt(...) -> str:
        """Create few-shot learning prompt."""

    def create_role_prompt(...) -> str:
        """Create role-based prompt."""
```
