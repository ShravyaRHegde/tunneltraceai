"""Data models and enums for deterministic IPsec protocol normalization."""

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EvidenceState(str, Enum):
    """Forensic evidence confidence state."""

    VERIFIED = "VERIFIED"  # Directly observed in packet dissection
    INFERRED = "INFERRED"  # Deduced from related facts
    UNKNOWN = "UNKNOWN"  # Not observed / absent
    MISCONFIGURATION_OBSERVED = "MISCONFIGURATION_OBSERVED"


class ObservationCategory(str, Enum):
    """Categorization of normalized protocol facts."""

    FRAME = "FRAME"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    UDP = "UDP"
    IKE_HEADER = "IKE_HEADER"
    IKE_EXCHANGE = "IKE_EXCHANGE"
    IKE_SA_PROPOSAL = "IKE_SA_PROPOSAL"
    IKE_TRANSFORM = "IKE_TRANSFORM"
    IKE_NOTIFY = "IKE_NOTIFY"
    IKE_TRAFFIC_SELECTOR = "IKE_TRAFFIC_SELECTOR"
    IKE_KEY_EXCHANGE = "IKE_KEY_EXCHANGE"
    ESP_HEADER = "ESP_HEADER"
    AH_HEADER = "AH_HEADER"
    NAT_T = "NAT_T"
    ICMP = "ICMP"
    TCP = "TCP"
    NON_IPSEC = "NON_IPSEC"
    PARSER_WARNING = "PARSER_WARNING"


@dataclass
class NormalizedObservation:
    """A discrete, normalized, packet-level protocol observation."""

    frame_number: int
    packet_time: float
    protocol: str  # IKEv1, IKEv2, ESP, AH, NAT-T, IPv4, IPv6, UDP
    category: ObservationCategory
    field_name: str
    normalized_value: str
    raw_value: str | None = None
    raw_numeric_id: int | None = None
    source_field: str = ""
    source_tool: str = "tshark"
    source_tool_version: str = "unknown"
    evidence_state: EvidenceState = EvidenceState.VERIFIED
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    extra_attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedFrame:
    """Aggregated protocol facts extracted from a single frame."""

    frame_number: int
    packet_time: float
    packet_len: int
    protocols: list[str] = field(default_factory=list)
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_version: str | None = None  # IPv4 or IPv6
    src_port: int | None = None
    dst_port: int | None = None
    observations: list[NormalizedObservation] = field(default_factory=list)


class ParserProvenance(BaseModel):
    """Version and execution provenance of the protocol engine."""

    engine: str = Field(default="tshark", description="Dissection engine used")
    actual_version: str = Field(..., description="Observed version of dissection engine")
    schema_version: str = Field(default="1.0.0", description="Normalization schema version")


class CryptoObservationDTO(BaseModel):
    """Observed proposal or transform in IKE negotiations."""

    frame_number: int
    proposal_number: int | None = None
    transform_type: str  # ENCR, PRF, INTEG, DH
    transform_id: int | None = None
    transform_name: str
    key_length_bits: int | None = None
    evidence_state: str = "VERIFIED"


class ProtocolSummaryDTO(BaseModel):
    """Authoritative Stage 3 deterministic protocol observations summary."""

    analysis_id: uuid.UUID
    capture_id: uuid.UUID
    ipsec_detected: bool
    outcome: str = Field(
        default="IPSEC_OBSERVED",
        description="Outcome code: IPSEC_OBSERVED or NO_IPSEC_FOUND",
    )
    protocols_observed: list[str]
    ip_versions_observed: list[str]
    natt_observed: bool
    packet_counts: dict[str, int] = Field(
        default_factory=lambda: {"total": 0, "ike": 0, "esp": 0, "ah": 0, "natt": 0}
    )
    ike_versions_observed: list[str]
    exchange_types_observed: list[str]
    crypto_observations: list[CryptoObservationDTO]
    transport_mode_notify_observed: bool | None = None
    parser: ParserProvenance

    # Canonical contract fields for UI and API compatibility
    total_packets_inspected: int = 0
    ipsec_packet_count: int = 0
    ikev1_packet_count: int = 0
    ikev2_packet_count: int = 0
    esp_packet_count: int = 0
    ah_packet_count: int = 0
    nat_t_detected: bool = False
    observed_initiator_spis: list[str] = Field(default_factory=list)
    observed_responder_spis: list[str] = Field(default_factory=list)
    observed_cipher_suites: list[str] = Field(default_factory=list)
    observed_dh_groups: list[str] = Field(default_factory=list)
    observed_exchange_types: list[str] = Field(default_factory=list)
    evidence_states: dict[str, str] = Field(default_factory=dict)
