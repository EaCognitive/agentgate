"""Prompt template schemas for creative AI prompt engineering.

This module provides database models and schemas for managing reusable
prompt templates with variable substitution, examples, and metadata.
Implements Phase 1 of the Generative AI Engineer feedback response.
"""

from datetime import datetime, timezone
from typing import ClassVar

from sqlalchemy import Column, JSON
from sqlmodel import SQLModel, Field


def utc_now() -> datetime:
    """Get current UTC time as timezone-naive."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class PromptCategory(str):
    """Standard categories for organizing prompt templates."""

    CHAIN_OF_THOUGHT = "chain_of_thought"
    FEW_SHOT = "few_shot"
    ROLE_BASED = "role_based"
    CREATIVE_STEERING = "creative_steering"
    SYSTEM = "system"
    CUSTOM = "custom"


class PromptTemplate(SQLModel, table=True):
    """Database model for reusable prompt templates.

    Stores structured prompt templates with variable substitution support,
    examples for few-shot learning, and metadata for analytics.

    Attributes:
        id: Primary key
        name: Human-readable template name
        category: Template category for organization
        description: Detailed explanation of template purpose
        system_prompt: Base system instructions for the LLM
        user_prompt_prefix: Text prepended to user input
        user_prompt_suffix: Text appended to user input
        variables: JSON dict of variable definitions with descriptions
        examples: JSON list of few-shot examples
        tags: Tags for filtering and search
        metadata: Additional metadata (model preferences, temperature, etc)
        usage_count: Number of times template has been applied
        created_by: User ID who created the template
        is_active: Whether template is available for use
        created_at: Creation timestamp
        updated_at: Last modification timestamp
    """

    __tablename__: ClassVar[str] = "prompt_templates"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(max_length=255, index=True)
    category: str = Field(max_length=100, index=True)
    description: str | None = Field(default=None, max_length=1000)

    # Template components
    system_prompt: str | None = Field(default=None)
    user_prompt_prefix: str | None = Field(default=None)
    user_prompt_suffix: str | None = Field(default=None)

    # Variable definitions: {"var_name": "description"}
    variables: dict | None = Field(default=None, sa_column=Column(JSON))

    # Few-shot examples: [{"input": "...", "output": "..."}]
    examples: list[dict] | None = Field(default=None, sa_column=Column(JSON))

    # Organization
    tags: list[str] | None = Field(default=None, sa_column=Column(JSON))

    # Additional metadata (model settings, etc)
    template_metadata: dict | None = Field(default=None, sa_column=Column(JSON))

    # Analytics
    usage_count: int = Field(default=0, index=True)

    # Ownership and lifecycle
    created_by: int | None = Field(default=None, foreign_key="users.id", index=True)
    is_active: bool = Field(default=True, index=True)
    created_at: datetime = Field(default_factory=utc_now, index=True)
    updated_at: datetime = Field(default_factory=utc_now, index=True)


class PromptTemplateCreate(SQLModel):
    """Schema for creating new prompt templates."""

    name: str = Field(max_length=255, min_length=1)
    category: str = Field(max_length=100)
    description: str | None = Field(default=None, max_length=1000)
    system_prompt: str | None = None
    user_prompt_prefix: str | None = None
    user_prompt_suffix: str | None = None
    variables: dict | None = None
    examples: list[dict] | None = None
    tags: list[str] | None = None
    template_metadata: dict | None = None


class PromptTemplateUpdate(SQLModel):
    """Schema for updating existing prompt templates."""

    name: str | None = Field(default=None, max_length=255)
    category: str | None = Field(default=None, max_length=100)
    description: str | None = Field(default=None, max_length=1000)
    system_prompt: str | None = None
    user_prompt_prefix: str | None = None
    user_prompt_suffix: str | None = None
    variables: dict | None = None
    examples: list[dict] | None = None
    tags: list[str] | None = None
    template_metadata: dict | None = None
    is_active: bool | None = None


class PromptTemplateRead(SQLModel):
    """Schema for reading prompt template information from API endpoints."""

    id: int
    name: str
    category: str
    description: str | None
    system_prompt: str | None
    user_prompt_prefix: str | None
    user_prompt_suffix: str | None
    variables: dict | None
    examples: list[dict] | None
    tags: list[str] | None
    template_metadata: dict | None
    usage_count: int
    created_by: int | None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class PromptTemplateUsageStats(SQLModel):
    """Analytics response for template usage tracking."""

    template_id: int
    template_name: str
    category: str
    total_uses: int
    last_used: datetime | None
    avg_success_rate: float | None


__all__ = [
    "PromptCategory",
    "PromptTemplate",
    "PromptTemplateCreate",
    "PromptTemplateUpdate",
    "PromptTemplateRead",
    "PromptTemplateUsageStats",
]
