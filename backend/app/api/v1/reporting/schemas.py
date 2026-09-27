"""Pydantic DTO schemas for Stage 9 reporting API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class CreateReportRequestDTO(BaseModel):
    """Payload to trigger server-side report generation."""

    report_type: Literal["EXECUTIVE", "TECHNICAL"] = Field(
        default="EXECUTIVE",
        description="Type of report to compile: 'EXECUTIVE' or 'TECHNICAL'",
    )

    @field_validator("report_type", mode="before")
    @classmethod
    def normalize_report_type(cls, v: str) -> str:
        if isinstance(v, str):
            clean = v.strip().upper()
            if clean in ("EXECUTIVE", "TECHNICAL"):
                return clean
        return v


class ReportResponseDTO(BaseModel):
    """Metadata response for a generated report record."""

    id: uuid.UUID
    analysis_id: uuid.UUID
    report_type: str
    status: str
    format: str
    template_version: str
    engine_version: str
    html_sha256: str | None = None
    pdf_sha256: str | None = None
    snapshot_manifest_sha256: str | None = None
    generation_duration_ms: float | None = None
    created_at: datetime
    completed_at: datetime | None = None
    error_message: str | None = None
    artifact_integrity_status: str | None = None
    actual_html_sha256: str | None = None


class ReportListResponseDTO(BaseModel):
    """List of report generation records."""

    analysis_id: uuid.UUID
    total_reports: int
    items: list[ReportResponseDTO]
