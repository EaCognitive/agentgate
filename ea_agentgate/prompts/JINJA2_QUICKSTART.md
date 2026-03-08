# Jinja2 Templating Quick Reference

## Basic Usage

```python
from ea_agentgate.prompts import Jinja2TemplateEngine

engine = Jinja2TemplateEngine()
result = engine.render("Hello {{name}}", {"name": "Alice"})
```

## Conditionals

```jinja2
{% if condition %}
  Text when true
{% elif other_condition %}
  Text when other is true
{% else %}
  Text when false
{% endif %}
```

## Loops

```jinja2
{% for item in items %}
  {{ loop.index }}. {{ item }}
{% endfor %}
```

Loop variables:
- `loop.index`: 1-indexed counter
- `loop.index0`: 0-indexed counter
- `loop.first`: True on first iteration
- `loop.last`: True on last iteration

## Custom Filters

```jinja2
{{ text|escape_prompt }}              # Escape injection patterns
{{ text|truncate_tokens(100) }}       # Truncate to ~100 tokens
{{ items|format_list(style='numbered') }}  # Format as list
{{ data|format_json }}                # Pretty-print JSON
{{ text|sanitize }}                   # Remove dangerous chars
{{ content|wrap_xml(tag='task') }}    # Wrap in XML tags
{{ text|uppercase }}                  # Convert to uppercase
{{ text|lowercase }}                  # Convert to lowercase
```

## Macros

```jinja2
{% macro format_example(input, output) -%}
Input: {{ input }}
Output: {{ output }}
{%- endmacro %}

{{ format_example("test", "result") }}
```

## Whitespace Control

```jinja2
{%- if condition -%}     # Strip before and after
  Text
{%- endif %}
```

## Validation

```python
is_valid, error = engine.validate(template_str)
if not is_valid:
    print(f"Error: {error}")
```

## Common Patterns

### Role-Based Prompting
```jinja2
You are a {{ role.name }}.

{% if role.expertise -%}
Expertise: {{ role.expertise|format_list(style='bulleted') }}
{% endif %}
```

### Few-Shot Learning
```jinja2
{% for example in examples[:5] -%}
Example {{ loop.index }}:
Input: {{ example.input }}
Output: {{ example.output }}
{% endfor %}

Now process: {{ query }}
```

### Context-Aware Prompts
```jinja2
{% if context.audience == "technical" %}
Technical details: Use precise terminology.
{% else %}
Simple explanation: Avoid jargon.
{% endif %}
```

## Security

The engine uses sandboxed execution:
- No file system access
- No network operations
- No dangerous built-ins
- Always use `escape_prompt` for user input

## Performance Tips

1. Limit loop iterations: `{% for item in items[:10] %}`
2. Use `truncate_tokens` to control length
3. Validate templates at startup, not per request
4. Cache rendered results when possible
