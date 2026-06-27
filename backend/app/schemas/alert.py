"""
Pydantic schemas for Alert API validation.

These schemas define the structure for API requests and responses
related to alert management and querying.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    """Severity levels matching the signature severity."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """Possible alert status values."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertBase(BaseModel):
    """Base schema with common alert fields."""

    source_ip: str = Field(..., description="Source IP address")
    source_port: Optional[int] = Field(None, description="Source port")
    dest_ip: str = Field(..., description="Destination IP address")
    dest_port: Optional[int] = Field(None, description="Destination port")
    protocol: str = Field(..., description="Network protocol")
    severity: SeverityLevel = Field(..., description="Alert severity")


class AlertResponse(AlertBase):
    """
    Schema for alert API responses.

    Contains full alert information including signature details.
    """

    id: int = Field(..., description="Unique alert ID")
    signature_id: int = Field(..., description="Triggering signature ID")
    signature_name: Optional[str] = Field(
        None, description="Name of triggering signature"
    )
    payload_snippet: Optional[str] = Field(
        None, description="Excerpt of packet payload"
    )
    status: AlertStatus = Field(..., description="Alert status")
    timestamp: datetime = Field(..., description="When alert was triggered")
    packet_count: int = Field(default=1, description="Number of matching packets")
    created_at: datetime = Field(..., description="Record creation time")

    class Config:
        from_attributes = True


class AlertStatusUpdate(BaseModel):
    """Schema for updating alert status."""

    status: AlertStatus = Field(..., description="New status value")


class AlertList(BaseModel):
    """Schema for paginated alert list response."""

    total: int = Field(..., description="Total number of alerts")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Number of items per page")
    alerts: list[AlertResponse] = Field(..., description="List of alerts")


class AlertStats(BaseModel):
    """Schema for alert statistics."""

    total_alerts: int = Field(..., description="Total alert count")
    new_alerts: int = Field(..., description="Unacknowledged alerts")
    critical_alerts: int = Field(..., description="Critical severity count")
    high_alerts: int = Field(..., description="High severity count")
    medium_alerts: int = Field(..., description="Medium severity count")
    low_alerts: int = Field(..., description="Low severity count")
    alerts_today: int = Field(..., description="Alerts in last 24 hours")
    top_source_ips: list[dict] = Field(..., description="Most frequent source IPs")
    top_signatures: list[dict] = Field(..., description="Most triggered signatures")


class AlertFilter(BaseModel):
    """Schema for filtering alerts in queries."""

    severity: Optional[SeverityLevel] = None
    status: Optional[AlertStatus] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    signature_id: Optional[int] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
