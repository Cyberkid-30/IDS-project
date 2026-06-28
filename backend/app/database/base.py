"""
SQLAlchemy declarative base and common model utilities.

This module provides the base class for all database models
and common model mixins for shared functionality.
"""

from datetime import datetime
from sqlalchemy import Column, DateTime, String
from sqlalchemy.orm import DeclarativeBase
from uuid import uuid4


# Create the declarative base for all models
class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy models.
    """

    pass


class TimestampMixin:
    """
    Mixin that adds created_at and updated_at timestamp columns.

    Automatically sets created_at on insert and updates updated_at
    on every update operation.
    """

    created_at = Column(
        DateTime,
        default=datetime.now,
        nullable=False,
        doc="Timestamp when record was created",
    )
    updated_at = Column(
        DateTime,
        default=datetime.now,
        onupdate=datetime.now,
        nullable=False,
        doc="Timestamp when record was last updated",
    )


class IDMixin:
    """
    Mixin that adds auto-incrementing primary key ID.
    """

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
        index=True,
        doc="Unique identifier",
    )
