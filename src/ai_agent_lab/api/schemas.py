"""Pydantic schemas exposed by the versioned API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StrictSchema(BaseModel):
    """Reject accidental public fields and keep response schemas strict."""

    model_config = ConfigDict(extra="forbid")


class HealthResponse(StrictSchema):
    status: str
    service: str = "ai-agent-security-lab"
    version: str


class ErrorBody(StrictSchema):
    code: str
    message: str
    request_id: str
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorEnvelope(StrictSchema):
    error: ErrorBody


__all__ = ["ErrorBody", "ErrorEnvelope", "HealthResponse", "StrictSchema"]
