"""
Pydantic schemas for Signature API validation.

These schemas define the structure for API requests and responses
related to signature management.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    """Severity levels for signatures."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProtocolType(str, Enum):
    """Supported network protocols."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class SignatureBase(BaseModel):
    """
    Base schema with common signature fields.

    Used as a foundation for create and update schemas.
    """

    name: str = Field(
        ..., min_length=1, max_length=255, description="Unique signature name"
    )
    description: Optional[str] = Field(
        None, max_length=1000, description="Detailed description of the threat"
    )
    protocol: ProtocolType = Field(
        default=ProtocolType.ANY, description="Protocol to match"
    )
    source_ip: Optional[str] = Field(
        None, max_length=50, description="Source IP/CIDR pattern (null = any)"
    )
    source_port: Optional[str] = Field(
        None, max_length=50, description="Source port(s) to match"
    )
    dest_ip: Optional[str] = Field(
        None, max_length=50, description="Destination IP/CIDR pattern"
    )
    dest_port: Optional[str] = Field(
        None, max_length=50, description="Destination port(s) to match"
    )
    pattern: Optional[str] = Field(
        None, description="Regex pattern for payload matching"
    )
    severity: SeverityLevel = Field(
        default=SeverityLevel.MEDIUM, description="Threat severity level"
    )
    enabled: bool = Field(default=True, description="Whether signature is active")
    category: Optional[str] = Field(None, max_length=100, description="Threat category")
    reference: Optional[str] = Field(
        None, max_length=500, description="External reference (CVE, URL)"
    )

    @field_validator("pattern")
    @classmethod
    def validate_regex_pattern(cls, v: Optional[str]) -> Optional[str]:
        """Validate that pattern is a valid regex."""
        if v is not None:
            import re

            try:
                re.compile(v)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")
        return v


class SignatureCreate(SignatureBase):
    """
    Schema for creating a new signature.

    Inherits all fields from SignatureBase.
    """

    pass


class SignatureUpdate(BaseModel):
    """
    Schema for updating an existing signature.

    All fields are optional - only provided fields will be updated.
    """

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    protocol: Optional[ProtocolType] = None
    source_ip: Optional[str] = Field(None, max_length=50)
    source_port: Optional[str] = Field(None, max_length=50)
    dest_ip: Optional[str] = Field(None, max_length=50)
    dest_port: Optional[str] = Field(None, max_length=50)
    pattern: Optional[str] = None
    severity: Optional[SeverityLevel] = None
    enabled: Optional[bool] = None
    category: Optional[str] = Field(None, max_length=100)
    reference: Optional[str] = Field(None, max_length=500)

    @field_validator("pattern")
    @classmethod
    def validate_regex_pattern(cls, v: Optional[str]) -> Optional[str]:
        """Validate that pattern is a valid regex if provided."""
        if v is not None:
            import re

            try:
                re.compile(v)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")
        return v


class SignatureResponse(SignatureBase):
    """
    Schema for signature API responses.

    Includes database-generated fields like ID and timestamps.
    """

    id: int = Field(..., description="Unique signature ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    class Config:
        from_attributes = True  # Enable ORM mode


class SignatureList(BaseModel):
    """Schema for paginated signature list response."""

    total: int = Field(..., description="Total number of signatures")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Number of items per page")
    signatures: list[SignatureResponse] = Field(..., description="List of signatures")
