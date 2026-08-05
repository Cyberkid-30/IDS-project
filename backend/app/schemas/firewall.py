from datetime import datetime
from typing import Optional
import ipaddress
from pydantic import BaseModel, Field, field_validator, field_serializer


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

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, ip: str) -> str:
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError("Invalid IP address") from exc
        return ip


class FirewallBlockResponse(BaseModel):
    id: str
    ip_address: str
    reason: Optional[str] = None
    alert_count: int
    blocked_at: datetime = Field(..., validation_alias="created_at")

    model_config = {"from_attributes": True}

    @field_serializer("blocked_at")
    def _serialize_blocked_at(self, value: datetime) -> str:
        return value.isoformat()


class FirewallBlockList(BaseModel):
    total: int
    blocked_ips: list[FirewallBlockResponse]


class FirewallUnblockResponse(BaseModel):
    ip_address: str
    status: str
    message: str
