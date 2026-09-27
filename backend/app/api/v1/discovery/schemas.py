"""Pydantic schemas for Stage 2 Authorized Asset Discovery API."""

from __future__ import annotations

import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class DiscoveryJobCreateRequest(BaseModel):
    job_name: str = Field(
        default="Authorized VPN Discovery",
        max_length=128,
        description="Descriptive name for this discovery run",
    )
    operator_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Authenticated operator or principal running the assessment",
        examples=["operator-admin"],
    )
    authorization_reference: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Formal change order, ticket, or authorization reference code",
        examples=["SEC-TICKET-2026-0924"],
    )
    authorization_attestation: str = Field(
        ...,
        min_length=10,
        description="Explicit attestation that the target scope has been authorized for active discovery",
        examples=["I attest that written authorization has been granted for active IPsec discovery."],
    )
    profile: str = Field(
        default="IKE_SERVICE_DISCOVERY",
        description="Allowlisted scan profile: IKE_SERVICE_DISCOVERY, VPN_MANAGEMENT_DISCOVERY, CUSTOM_BOUNDED",
    )
    requested_targets: list[str] = Field(
        ...,
        min_length=1,
        description="List of target IP addresses, bounded CIDR blocks, or resolvable hostnames",
        examples=[["127.0.0.1"]],
    )
    exclusions: list[str] | None = Field(
        default=None,
        description="Optional list of IPs or CIDR networks to exclude unconditionally",
    )
    permitted_ports: list[int] | None = Field(
        default=None,
        description="Explicit port allowlist; defaults to profile defaults if omitted",
    )
    simulate_demo: bool = Field(
        default=False,
        description="Run in simulated demo mode if Nmap binary is unavailable on the host",
    )


class DiscoveredServiceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    protocol: str
    port: int
    state: str
    state_reason: str | None = None
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    confidence: float | None = None


class DiscoveredHostResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ip_address: str
    ip_version: str
    state: str
    hostnames: list[str] | None = None
    services: list[DiscoveredServiceResponse] = []


class DiscoveryJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    job_name: str
    operator_id: str
    authorization_reference: str
    authorization_attestation: str
    authorized_at: datetime
    profile: str
    requested_targets: list[str]
    canonical_targets: list[str]
    exclusions: list[str]
    permitted_ports: list[int]
    status: str
    failure_reason: str | None = None
    raw_output_sha256: str | None = None
    output_bytes_count: int | None = None
    tool_version: str | None = None
    target_count: int
    hosts_up_count: int
    services_discovered_count: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    hosts: list[DiscoveredHostResponse] = []


class DiscoveryStatusResponse(BaseModel):
    enabled: bool
    nmap_available: bool
    nmap_version: str | None = None
    nmap_path: str | None = None
    max_targets: int
    max_ports: int
    timeout_sec: float
    rate_limit_pps: int
    available_profiles: list[dict[str, str]]

