"""
Schemas package initialization.

Exports all Pydantic schemas for API validation.
"""

from app.schemas.signature import (
    SignatureBase,
    SignatureCreate,
    SignatureUpdate,
    SignatureResponse,
    SignatureList,
    SeverityLevel as SignatureSeverity,
    ProtocolType,
)
from app.schemas.alert import (
    AlertBase,
    AlertResponse,
    AlertStatusUpdate,
    AlertList,
    AlertStats,
    AlertFilter,
    AlertStatus,
    SeverityLevel as AlertSeverity,
)
from app.schemas.user import (
    UserCreate,
    UserResponse,
    Token,
    TokenData,
)

__all__ = [
    # Signature schemas
    "SignatureBase",
    "SignatureCreate",
    "SignatureUpdate",
    "SignatureResponse",
    "SignatureList",
    "SignatureSeverity",
    "ProtocolType",
    # Alert schemas
    "AlertBase",
    "AlertResponse",
    "AlertStatusUpdate",
    "AlertList",
    "AlertStats",
    "AlertFilter",
    "AlertStatus",
    "AlertSeverity",
    # User schemas
    "UserCreate",
    "UserResponse",
    "Token",
    "TokenData",
]
