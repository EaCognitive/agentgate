"""
Shared utilities for dataset operations across routers.

Provides common helper functions for dataset validation and access control.

@author Erick | Founding Principal AI Architect
"""

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Dataset, User
from ..utils.db import get as db_get


async def get_dataset_or_404(
    session: AsyncSession,
    dataset_id: int,
) -> Dataset:
    """
    Retrieve a dataset by ID or raise 404 HTTPException.

    Args:
        session: Database session
        dataset_id: ID of the dataset to retrieve

    Returns:
        The Dataset object if found

    Raises:
        HTTPException: 404 if dataset not found
    """
    dataset = await db_get(session, Dataset, dataset_id)
    if not isinstance(dataset, Dataset):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found",
        )
    return dataset


async def get_dataset_or_404_with_ownership_check(
    session: AsyncSession,
    dataset_id: int,
    current_user: User,
) -> Dataset:
    """
    Retrieve a dataset by ID with ownership validation.

    Non-admin/auditor users can only access their own datasets.
    Returns 404 for both missing datasets and ownership violations.

    Args:
        session: Database session
        dataset_id: ID of the dataset to retrieve
        current_user: Current authenticated user

    Returns:
        The Dataset object if found and accessible

    Raises:
        HTTPException: 404 if dataset not found or user lacks access
    """
    dataset = await db_get(session, Dataset, dataset_id)
    if not isinstance(dataset, Dataset):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found",
        )

    # Non-admin/auditor users can only access their own datasets
    if current_user.role not in ["admin", "auditor"]:
        if dataset.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Dataset not found",
            )

    return dataset
