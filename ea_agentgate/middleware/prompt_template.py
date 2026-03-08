"""Prompt template middleware for creative AI prompt engineering.

This middleware injects prompt templates into tool execution flow,
enabling sophisticated prompt engineering techniques like chain-of-thought,
few-shot learning, and role-based prompting.

Implements positive steering (enhancing prompts) rather than negative
filtering (blocking prompts).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .base import Middleware, MiddlewareContext
from ..prompts.manager import PromptTemplateManager

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class PromptTemplateMiddleware(Middleware):
    """Base class for prompt template injection middleware.

    Subclasses implement specific prompt engineering techniques:
    - ChainOfThoughtMiddleware: Injects reasoning structure
    - FewShotMiddleware: Adds example demonstrations
    - RoleBasedMiddleware: Assigns persona/role

    This is positive steering - we enhance prompts to improve model
    behavior rather than blocking problematic inputs.

    Example:
        from ea_agentgate import Agent
        from ea_agentgate.middleware.prompt_template import ChainOfThoughtMiddleware

        agent = Agent(
            name="reasoning-assistant",
            middleware=[
                ChainOfThoughtMiddleware(
                    auto_inject=True,
                    show_steps=True,
                ),
            ],
        )
    """

    def __init__(self):
        """Initialize template middleware with manager."""
        super().__init__()
        self.manager = PromptTemplateManager()

    @property
    def name(self) -> str:
        """Return middleware name."""
        return "PromptTemplate"

    def _extract_prompt_field(self, inputs: dict[str, Any]) -> tuple[str, str | None]:
        """Extract prompt field from inputs.

        Supports common patterns:
        - inputs["prompt"]
        - inputs["text"]
        - inputs["message"]
        - inputs["messages"][-1]["content"] (chat format)

        Returns:
            Tuple of (field_name, prompt_text) or (None, None) if not found.
        """
        if "prompt" in inputs and inputs["prompt"]:
            return ("prompt", str(inputs["prompt"]))
        if "text" in inputs and inputs["text"]:
            return ("text", str(inputs["text"]))
        if "message" in inputs and inputs["message"]:
            return ("message", str(inputs["message"]))
        if "messages" in inputs and isinstance(inputs["messages"], list):
            if inputs["messages"] and isinstance(inputs["messages"][-1], dict):
                if "content" in inputs["messages"][-1]:
                    return ("messages", str(inputs["messages"][-1]["content"]))
        return ("", None)

    def _update_prompt_field(
        self,
        inputs: dict[str, Any],
        field_name: str,
        new_value: str,
    ) -> None:
        """Update prompt field in inputs dict.

        Args:
            inputs: Input dictionary to modify
            field_name: Name of field to update
            new_value: New prompt value
        """
        if field_name == "messages":
            if isinstance(inputs["messages"], list) and inputs["messages"]:
                inputs["messages"][-1]["content"] = new_value
        else:
            inputs[field_name] = new_value


class ChainOfThoughtMiddleware(PromptTemplateMiddleware):
    """Middleware for injecting chain-of-thought reasoning structure.

    Enhances prompts with explicit reasoning scaffolding to guide
    step-by-step problem solving.

    This is positive steering - we improve model reasoning by adding
    structure, not blocking inputs.

    Args:
        auto_inject: Automatically add "Let's think step by step" prefix
        show_steps: Show explicit step numbers in reasoning
        custom_prefix: Custom reasoning prefix (overrides auto_inject)
    """

    def __init__(
        self,
        *,
        auto_inject: bool = True,
        show_steps: bool = True,
        custom_prefix: str = "",
    ):
        super().__init__()
        self.auto_inject = auto_inject
        self.show_steps = show_steps
        self.custom_prefix = custom_prefix

    @property
    def name(self) -> str:
        """Return the middleware identifier."""
        return "ChainOfThought"

    def before(self, ctx: MiddlewareContext) -> None:
        """Inject chain-of-thought reasoning structure before execution."""
        field_name, original_prompt = self._extract_prompt_field(ctx.inputs)
        if not original_prompt:
            return

        if self.custom_prefix:
            enhanced_prompt = f"{self.custom_prefix}\n\n{original_prompt}"
        elif self.auto_inject:
            step_text = " step by step" if self.show_steps else ""
            enhanced_prompt = (
                f"{original_prompt}\n\n"
                f"Let's approach this{step_text}, thinking through "
                f"each part carefully:"
            )
        else:
            return

        self._update_prompt_field(ctx.inputs, field_name, enhanced_prompt)
        ctx.metadata["prompt_template"] = {
            "type": "chain_of_thought",
            "original_length": len(original_prompt),
            "enhanced_length": len(enhanced_prompt),
        }


class FewShotMiddleware(PromptTemplateMiddleware):
    """Middleware for injecting few-shot learning examples.

    Enhances prompts with example demonstrations to guide model
    behavior through context rather than explicit instructions.

    This is positive steering - we teach by example rather than blocking.

    Args:
        examples: List of (input, output) example pairs
        task_description: Optional task description to prepend
        max_examples: Maximum number of examples to inject
    """

    def __init__(
        self,
        *,
        examples: list[tuple[str, str]] | None = None,
        task_description: str = "",
        max_examples: int = 5,
    ):
        super().__init__()
        self.examples = examples or []
        self.task_description = task_description
        self.max_examples = max_examples

    @property
    def name(self) -> str:
        """Return the middleware identifier."""
        return "FewShot"

    def before(self, ctx: MiddlewareContext) -> None:
        """Inject few-shot examples before execution."""
        if not self.examples:
            return

        field_name, original_prompt = self._extract_prompt_field(ctx.inputs)
        if not original_prompt:
            return

        examples_to_use = self.examples[: self.max_examples]
        enhanced_prompt = self.manager.create_few_shot_prompt(
            task_description=self.task_description or "Process the following input:",
            examples=examples_to_use,
            query=original_prompt,
        )

        self._update_prompt_field(ctx.inputs, field_name, enhanced_prompt)
        ctx.metadata["prompt_template"] = {
            "type": "few_shot",
            "num_examples": len(examples_to_use),
            "original_length": len(original_prompt),
            "enhanced_length": len(enhanced_prompt),
        }


class RoleBasedMiddleware(PromptTemplateMiddleware):
    """Middleware for injecting role-based persona prompts.

    Enhances prompts by assigning a specific role/persona to guide
    model behavior, tone, and expertise level.

    This is positive steering - we shape behavior through identity
    rather than blocking unwanted outputs.

    Args:
        role_name: Name of the role/persona
        role_description: Detailed description of role behavior
        constraints: Optional behavioral guidelines
        tone: Communication tone (professional, casual, formal, etc)
    """

    def __init__(
        self,
        *,
        role_name: str,
        role_description: str,
        constraints: list[str] | None = None,
        tone: str = "professional",
    ):
        super().__init__()
        self.role_name = role_name
        self.role_description = role_description
        self.constraints = constraints or []
        self.tone = tone

    @property
    def name(self) -> str:
        """Return the middleware identifier including role name."""
        return f"Role:{self.role_name}"

    def before(self, ctx: MiddlewareContext) -> None:
        """Inject role-based prompt before execution."""
        field_name, original_prompt = self._extract_prompt_field(ctx.inputs)
        if not original_prompt:
            return

        role_prompt = self.manager.create_role_prompt(
            role_name=self.role_name,
            role_description=self.role_description,
            task=original_prompt,
            constraints=self.constraints,
            tone=self.tone,
        )

        self._update_prompt_field(ctx.inputs, field_name, role_prompt)
        ctx.metadata["prompt_template"] = {
            "type": "role_based",
            "role": self.role_name,
            "original_length": len(original_prompt),
            "enhanced_length": len(role_prompt),
        }


__all__ = [
    "PromptTemplateMiddleware",
    "ChainOfThoughtMiddleware",
    "FewShotMiddleware",
    "RoleBasedMiddleware",
]
