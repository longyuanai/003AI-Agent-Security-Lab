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


class ProjectCreate(StrictSchema):
    name: str = Field(min_length=1, max_length=200)
    target_policy: dict[str, Any] = Field(default_factory=dict)


class ProjectResponse(StrictSchema):
    id: str
    name: str
    target_policy: dict[str, Any]
    version: int


class RunCreate(StrictSchema):
    project_id: str = Field(min_length=1, max_length=128)
    suite_version: str = Field(default="built-in-v1", min_length=1, max_length=128)
    seed: int = Field(default=0, ge=0)
    idempotency_key: str = Field(min_length=8, max_length=128)


class RunResponse(StrictSchema):
    id: str
    project_id: str
    suite_version: str
    seed: int
    status: str
    attempt: int
    version: int


__all__ = [
    "ErrorBody",
    "ErrorEnvelope",
    "HealthResponse",
    "ProjectCreate",
    "ProjectResponse",
    "RunCreate",
    "RunResponse",
    "StrictSchema",
]
