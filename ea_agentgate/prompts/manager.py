"""Prompt template manager for creative AI prompt engineering.

This module provides sophisticated prompt engineering capabilities:
- Variable substitution with Jinja2 templates
- Chain-of-thought reasoning injection
- Few-shot learning example formatting
- Role-based persona prompting
- Template composition and chaining

Implements Phase 1 of Generative AI Engineer feedback response.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import filters

# Runtime imports with availability flag
jinja2_available = False
try:
    from jinja2 import Environment, StrictUndefined, select_autoescape
    from jinja2 import TemplateError
    from jinja2.sandbox import SandboxedEnvironment

    jinja2_available = True
except ImportError:
    pass

_JINJA_ERRORS = (
    (TemplateError, TypeError, ValueError) if jinja2_available else (TypeError, ValueError)
)


@dataclass
class ChainOfThoughtPrompt:
    """Chain-of-thought prompt structure for step-by-step reasoning.

    Injects reasoning scaffolding into prompts to guide LLMs through
    structured problem-solving steps.

    Attributes:
        problem: The problem statement or query
        reasoning_steps: List of intermediate reasoning steps
        conclusion: Final answer or conclusion
        show_steps: Whether to explicitly show step labels
    """

    problem: str
    reasoning_steps: list[str] = field(default_factory=list)
    conclusion: str = ""
    show_steps: bool = True

    def format(self) -> str:
        """Format as chain-of-thought prompt text.

        Returns:
            Formatted prompt with reasoning structure.
        """
        lines = [f"Problem: {self.problem}", ""]

        if self.reasoning_steps:
            lines.append("Let's solve this step-by-step:")
            for idx, step in enumerate(self.reasoning_steps, 1):
                if self.show_steps:
                    lines.append(f"Step {idx}: {step}")
                else:
                    lines.append(f"- {step}")
            lines.append("")

        if self.conclusion:
            lines.append(f"Therefore: {self.conclusion}")

        return "\n".join(lines)


@dataclass
class FewShotPrompt:
    """Few-shot learning prompt with input/output examples.

    Provides context through examples to guide model behavior
    without explicit instruction.

    Attributes:
        task_description: Brief description of the task
        examples: List of (input, output) example pairs
        query: The actual query to process
        format_template: Optional custom formatting template
    """

    task_description: str
    examples: list[tuple[str, str]] = field(default_factory=list)
    query: str = ""
    format_template: str | None = None

    def format(self) -> str:
        """Format as few-shot prompt with examples.

        Returns:
            Formatted prompt with task description and examples.
        """
        if self.format_template and jinja2_available:
            # At runtime when HAS_JINJA2 is True, these are real jinja2 types
            assert Environment is not None and StrictUndefined is not None
            assert select_autoescape is not None
            env = Environment(
                undefined=StrictUndefined,
                autoescape=select_autoescape(
                    default=True,
                    default_for_string=True,
                ),
            )
            template = env.from_string(self.format_template)
            return str(
                template.render(
                    task_description=self.task_description,
                    examples=self.examples,
                    query=self.query,
                )
            )

        lines = [self.task_description, ""]

        if self.examples:
            lines.append("Examples:")
            for idx, (inp, out) in enumerate(self.examples, 1):
                lines.append(f"\nExample {idx}:")
                lines.append(f"Input: {inp}")
                lines.append(f"Output: {out}")
            lines.append("")

        if self.query:
            lines.append(f"Now process this:\nInput: {self.query}\nOutput:")

        return "\n".join(lines)


@dataclass
class RolePrompt:
    """Role-based persona prompt for behavior steering.

    Assigns a specific role/persona to guide model behavior,
    tone, and expertise level.

    Attributes:
        role_name: Name of the role/persona
        role_description: Detailed description of role behavior
        task: The task to perform in this role
        constraints: Optional constraints or guidelines
        tone: Desired communication tone
    """

    role_name: str
    role_description: str
    task: str = ""
    constraints: list[str] = field(default_factory=list)
    tone: str = "professional"

    def format(self) -> str:
        """Format as role-based prompt.

        Returns:
            Formatted prompt with role assignment.
        """
        lines = [
            f"You are {self.role_name}.",
            self.role_description,
            "",
        ]

        if self.constraints:
            lines.append("Guidelines:")
            for constraint in self.constraints:
                lines.append(f"- {constraint}")
            lines.append("")

        lines.append(f"Communication tone: {self.tone}")
        lines.append("")

        if self.task:
            lines.append(f"Task: {self.task}")

        return "\n".join(lines)


class Jinja2TemplateEngine:
    """Advanced Jinja2 template engine with security and validation.

    Provides enterprise-grade template rendering with:
    - Sandboxed execution environment (prevents dangerous operations)
    - Custom filters for prompt engineering
    - Template syntax validation
    - Support for conditionals, loops, macros, and inheritance
    - Backward compatibility with simple variable substitution

    This engine uses Jinja2's SandboxedEnvironment to prevent:
    - File system access
    - Network operations
    - Arbitrary code execution
    - Access to private attributes

    Example:
        engine = Jinja2TemplateEngine()

        # Simple variable substitution
        result = engine.render("Hello {{name}}", {"name": "Alice"})

        # Conditionals
        template = "{% if premium %}Premium{% else %}Basic{% endif %}"
        result = engine.render(template, {"premium": True})

        # Loops with custom filters
        template = "{% for item in items %}{{ item|uppercase }}{% endfor %}"
        result = engine.render(template, {"items": ["a", "b", "c"]})

        # Validate before rendering
        is_valid, error = engine.validate("Hello {{name}}")
    """

    def __init__(self):
        """Initialize sandboxed Jinja2 environment with custom filters."""
        if not jinja2_available:
            raise ImportError(
                "Jinja2 is required for Jinja2TemplateEngine. Install with: pip install jinja2"
            )

        # At runtime when HAS_JINJA2 is True, these are real jinja2 types
        assert SandboxedEnvironment is not None and StrictUndefined is not None
        assert select_autoescape is not None
        self._env = SandboxedEnvironment(
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
            autoescape=select_autoescape(
                default=True,
                default_for_string=True,
            ),
        )

        custom_filters = filters.get_all_filters()
        self._env.filters.update(custom_filters)

    def validate(self, template_str: str) -> tuple[bool, str | None]:
        """Validate template syntax without rendering.

        Args:
            template_str: Template string to validate

        Returns:
            Tuple of (is_valid, error_message). error_message is None if valid.

        Example:
            >>> engine = Jinja2TemplateEngine()
            >>> is_valid, error = engine.validate("Hello {{name}}")
            >>> assert is_valid
            >>> is_valid, error = engine.validate("Hello {{name")
            >>> assert not is_valid
        """
        try:
            self._env.from_string(template_str)
            return (True, None)
        except _JINJA_ERRORS as exc:
            # Check if it's a TemplateSyntaxError (when jinja2 is available)
            if jinja2_available and exc.__class__.__name__ == "TemplateSyntaxError":
                # Safe to access these attributes on TemplateSyntaxError
                lineno = getattr(exc, "lineno", "unknown")
                message = getattr(exc, "message", str(exc))
                return (False, f"Syntax error at line {lineno}: {message}")
            return (False, f"Validation error: {exc}")

    def render(
        self,
        template_str: str,
        context: dict[str, Any] | None = None,
        validate_first: bool = True,
    ) -> str:
        """Render template with provided context variables.

        Args:
            template_str: Jinja2 template string
            context: Dictionary of variables for template
            validate_first: Whether to validate syntax before rendering

        Returns:
            Rendered template string.

        Raises:
            ValueError: If template is invalid or rendering fails.

        Example:
            >>> engine = Jinja2TemplateEngine()
            >>> engine.render("Hello {{name}}", {"name": "Bob"})
            "Hello Bob"
        """
        if validate_first:
            is_valid, error = self.validate(template_str)
            if not is_valid:
                raise ValueError(f"Invalid template: {error}")

        try:
            template = self._env.from_string(template_str)
            return str(template.render(**(context or {})))
        except Exception as exc:
            # Check if it's an UndefinedError (when jinja2 is available)
            if jinja2_available and exc.__class__.__name__ == "UndefinedError":
                raise ValueError(f"Missing required variable: {exc}") from exc
            raise ValueError(f"Template rendering failed: {exc}") from exc

    def render_with_macros(
        self,
        template_str: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        """Render template that may contain macro definitions.

        Macros are reusable template fragments defined with:
        {% macro name(args) %}...{% endmacro %}

        Args:
            template_str: Template with macro definitions
            context: Context variables

        Returns:
            Rendered template.

        Example:
            >>> template = '''
            ... {% macro format_example(input, output) -%}
            ... Input: {{ input }}
            ... Output: {{ output }}
            ... {%- endmacro %}
            ... {{ format_example("test", "result") }}
            ... '''
            >>> engine.render_with_macros(template)
            "Input: test\\nOutput: result"
        """
        return self.render(template_str, context, validate_first=True)

    def get_available_filters(self) -> list[str]:
        """Get list of available custom filter names.

        Returns:
            List of filter names that can be used in templates.
        """
        return sorted(self._env.filters.keys())


class PromptTemplateManager:
    """Manager for prompt template operations and transformations.

    Provides methods for applying templates, variable substitution,
    and composing complex prompts from simpler components.

    Uses Jinja2 for template rendering when available, falls back
    to simple string substitution.

    Example:
        manager = PromptTemplateManager()

        # Apply template with variables
        prompt = manager.apply_template(
            template="Hello {{name}}, you are {{age}} years old.",
            variables={"name": "Alice", "age": 30}
        )

        # Create chain-of-thought prompt
        cot_prompt = manager.create_chain_of_thought_prompt(
            problem="What is 15% of 200?",
            steps=["Convert 15% to decimal: 0.15", "Multiply 200 by 0.15"],
            conclusion="30"
        )
    """

    def __init__(self):
        """Initialize template manager with Jinja2 environment if available."""
        self._jinja_available = jinja2_available
        if self._jinja_available:
            # At runtime when HAS_JINJA2 is True, these are real jinja2 types
            assert Environment is not None and StrictUndefined is not None
            assert select_autoescape is not None
            self._env = Environment(
                undefined=StrictUndefined,
                trim_blocks=True,
                lstrip_blocks=True,
                autoescape=select_autoescape(
                    default=True,
                    default_for_string=True,
                ),
            )
            try:
                self._engine = Jinja2TemplateEngine()
            except ImportError:
                self._engine = None
        else:
            self._engine = None

    def apply_template(
        self,
        template: str,
        variables: dict[str, Any] | None = None,
        use_advanced_engine: bool = True,
    ) -> str:
        """Apply variable substitution to template.

        Supports both simple {{variable}} substitution and advanced Jinja2
        features (conditionals, loops, filters, macros).

        Args:
            template: Template string with {{variable}} placeholders
            variables: Dictionary of variable names to values
            use_advanced_engine: Use sandboxed Jinja2 engine with filters

        Returns:
            Rendered template with variables substituted.

        Raises:
            ValueError: If required variables are missing.

        Example:
            manager = PromptTemplateManager()

            # Simple substitution
            result = manager.apply_template(
                "Hello {{name}}", {"name": "Alice"}
            )

            # Advanced features
            result = manager.apply_template(
                "{% if premium %}VIP{% endif %} {{name|uppercase}}",
                {"premium": True, "name": "alice"}
            )
        """
        if not variables:
            return template

        if use_advanced_engine and self._engine:
            try:
                return str(self._engine.render(template, variables))
            except _JINJA_ERRORS as exc:
                raise ValueError(f"Template rendering failed: {exc}") from exc

        if self._jinja_available:
            try:
                tmpl = self._env.from_string(template)
                return str(tmpl.render(**variables))
            except _JINJA_ERRORS as exc:
                raise ValueError(f"Template rendering failed: {exc}") from exc

        result = template
        for key, value in variables.items():
            placeholder = f"{{{{{key}}}}}"
            result = result.replace(placeholder, str(value))
        return result

    def create_chain_of_thought_prompt(
        self,
        problem: str,
        steps: list[str] | None = None,
        conclusion: str = "",
        show_steps: bool = True,
    ) -> str:
        """Create chain-of-thought reasoning prompt.

        Args:
            problem: Problem statement or query
            steps: Optional list of reasoning steps
            conclusion: Optional final conclusion
            show_steps: Whether to show step numbers

        Returns:
            Formatted chain-of-thought prompt.
        """
        cot = ChainOfThoughtPrompt(
            problem=problem,
            reasoning_steps=steps or [],
            conclusion=conclusion,
            show_steps=show_steps,
        )
        return cot.format()

    def create_few_shot_prompt(
        self,
        task_description: str,
        examples: list[tuple[str, str]],
        query: str = "",
        format_template: str | None = None,
    ) -> str:
        """Create few-shot learning prompt with examples.

        Args:
            task_description: Description of the task
            examples: List of (input, output) example pairs
            query: Query to process after examples
            format_template: Optional Jinja2 template for custom formatting

        Returns:
            Formatted few-shot prompt.
        """
        few_shot = FewShotPrompt(
            task_description=task_description,
            examples=examples,
            query=query,
            format_template=format_template,
        )
        return few_shot.format()

    def create_role_prompt(
        self,
        role_name: str,
        role_description: str,
        *,
        task: str = "",
        constraints: list[str] | None = None,
        tone: str = "professional",
    ) -> str:
        """Create role-based persona prompt.

        Args:
            role_name: Name of the role/persona
            role_description: Detailed role description
            task: Task to perform in this role
            constraints: Optional behavioral constraints
            tone: Communication tone

        Returns:
            Formatted role-based prompt.
        """
        role = RolePrompt(
            role_name=role_name,
            role_description=role_description,
            task=task,
            constraints=constraints or [],
            tone=tone,
        )
        return role.format()

    def load_template_from_file(self, template_path: str | Path) -> str:
        """Load template from JSON file.

        Expected JSON format:
        {
            "system_prompt": "...",
            "user_prompt_prefix": "...",
            "user_prompt_suffix": "...",
            "variables": {"var": "description"},
            "examples": [{"input": "...", "output": "..."}]
        }

        Args:
            template_path: Path to template JSON file

        Returns:
            Combined template string.

        Raises:
            FileNotFoundError: If template file doesn't exist
            ValueError: If template file is malformed
        """
        path = Path(template_path)
        if not path.exists():
            raise FileNotFoundError(f"Template file not found: {template_path}")

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Failed to load template: {exc}") from exc

        parts = []
        if "system_prompt" in data and data["system_prompt"]:
            parts.append(data["system_prompt"])
        if "user_prompt_prefix" in data and data["user_prompt_prefix"]:
            parts.append(data["user_prompt_prefix"])

        return "\n\n".join(parts)

    def compose_prompts(self, *prompts: str, separator: str = "\n\n") -> str:
        """Compose multiple prompts into a single prompt.

        Args:
            *prompts: Variable number of prompt strings
            separator: Separator between prompts

        Returns:
            Combined prompt string.
        """
        return separator.join(p for p in prompts if p)


__all__ = [
    "Jinja2TemplateEngine",
    "PromptTemplateManager",
    "ChainOfThoughtPrompt",
    "FewShotPrompt",
    "RolePrompt",
]
