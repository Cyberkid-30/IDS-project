from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class FirewallBlockRequest(BaseModel):
    ip_address: str = Field(
        ...,
        min_length=7,
        max_length=50,
        description="IP address to block",
    )
    reason: Optional[str] = Field(
        None,
        max_length=500,
        description="Reason for blocking",
    )


class FirewallBlockResponse(BaseModel):
    id: str
    ip_address: str
    reason: Optional[str] = None
    alert_count: int
    blocked_at: datetime = Field(..., validation_alias="created_at")

    model_config = {"from_attributes": True}


class FirewallBlockList(BaseModel):
    total: int
    blocked_ips: list[FirewallBlockResponse]


class FirewallUnblockResponse(BaseModel):
    ip_address: str
    status: str
    message: str