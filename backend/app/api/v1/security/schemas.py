"""Data Transfer Objects and API Schemas for Stage 8 Security & Compliance."""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field


class PolicyProfileSummaryDTO(BaseModel):
    """Available Policy-as-Code profile overview."""

    profile_id: str
    name: str
    description: str
    active_bundle_id: str | None = None
    rule_count: int = 0


class ComplianceEvaluationDTO(BaseModel):
    """Itemized rule compliance evaluation record."""

    rule_id: str
    rule_version: str
    subject_type: str
    subject_id: str
    compliance_state: str  # PASS, FAIL, UNKNOWN, NOT_APPLICABLE
    evidence_state: str
    rationale: str


class ComplianceSummaryDTO(BaseModel):
    """Aggregate compliance status and itemized evaluations."""

    analysis_id: uuid.UUID
    profile_id: str
    bundle_id: str
    bundle_hash: str
    total_rules_evaluated: int
    pass_count: int
    fail_count: int
    unknown_count: int
    not_applicable_count: int
    evaluations: list[ComplianceEvaluationDTO]


class SecurityFindingDTO(BaseModel):
    """Structured security finding resulting from a FAIL compliance state."""

    finding_id: str
    analysis_id: uuid.UUID
    rule_id: str
    rule_version: str
    profile_id: str
    category: str
    severity: str
    title: str
    technical_description: str
    root_cause_key: str
    affected_entity_type: str
    affected_entity_id: str
    observed_value: Any
    expected_requirement: Any
    evidence_state: str
    remediation_guidance: str | None = None
    remediation_directive: str | None = None
    record_hash: str
    created_at: str


class ScoreDeductionDTO(BaseModel):
    """Audited score deduction trace item."""

    finding_id: str
    rule_id: str
    category: str
    severity: str
    root_cause_key: str
    raw_deduction: float
    applied_deduction: float
    is_deduplicated: bool
    rationale: str


class EvidenceCoverageDTO(BaseModel):
    """Transparent evidence coverage statistics."""

    applicable_rules: int
    evaluated_rules: int
    unknown_rules: int
    not_applicable_rules: int
    coverage_percentage: float


class SecurityScoreDTO(BaseModel):
    """Audited Security Posture Score breakdown."""

    analysis_id: uuid.UUID
    overall_score: float | None = None
    raw_score: float | None = None
    score_policy_id: str
    score_policy_version: str
    score_policy_hash: str
    status: str
    coverage_percentage: float
    category_scores: dict[str, float]
    deduction_audit: list[ScoreDeductionDTO]
    evidence_coverage: EvidenceCoverageDTO
    disclaimer: str = (
        "Internal product-defined security posture score. "
        "This is an automated analytical metric against the selected policy profile, "
        "NOT an official NIST, government, Common Criteria, or FIPS certification."
    )


class RiskFactorDetailDTO(BaseModel):
    """Inspectable individual factor contributing to finding risk."""

    factor_name: str
    factor_value: str
    scale: str
    evidence_state: str
    source: str
    source_time: str
    contributes_to_aggregate: bool
    aggregation_role: str
    rationale: str


class RiskItemDTO(BaseModel):
    """Deterministic risk evaluation per finding with factor-level transparency."""

    finding_id: str
    rule_id: str
    severity: str
    likelihood: str
    impact: str
    risk_tier: str
    evidence_state: str
    threat_mapped: bool
    rationale: str
    factors: list[RiskFactorDetailDTO] = []
    contributes_to_aggregate: bool = True
    aggregation_role: str = "PRIMARY_DRIVER"
    root_cause_key: str = ""
    policy_version: str = "1.0.0"
    policy_hash: str = ""
    methodology_type: str = "DETERMINISTIC_PRIORITIZATION_HEURISTIC"


class RiskAssessmentDTO(BaseModel):
    """Risk assessment summary with explicit evidence coverage and policy lineage."""

    analysis_id: uuid.UUID
    risk_policy_id: str
    risk_policy_version: str
    risk_policy_hash: str
    overall_risk_tier: str
    items: list[RiskItemDTO]
    evidence_coverage: float | None = None
    evidence_gaps_count: int = 0
    methodology_type: str = "DETERMINISTIC_PRIORITIZATION_HEURISTIC"
    disclaimer: str = (
        "Internal product-defined deterministic prioritization heuristic. "
        "Evaluated from protocol policy findings, evidence state, and rule mappings. "
        "NOT an empirically calibrated attack probability or official safety certification."
    )


class ThreatInstanceDTO(BaseModel):
    """Pre-authored threat scenario mapped to a finding with verified ATT&CK context."""

    finding_id: str
    threat_id: str
    threat_name: str
    attack_vector: str
    likelihood: str
    impact: str
    risk_tier: str
    mitre_attack_id: str | None = None
    mitre_attack_name: str | None = None
    mitre_attack_url: str | None = None
    mitre_attack_rationale: str | None = None
    catalog_hash: str | None = None


class ThreatIntelItemDTO(BaseModel):
    """Offline threat intelligence context for a specific CVE."""

    cve_id: str
    cisa_kev_status: str
    cisa_kev_record: dict[str, Any] | None = None
    cisa_kev_as_of: str | None = None
    cisa_kev_digest: str | None = None
    epss_status: str
    epss_record: dict[str, Any] | None = None
    epss_as_of: str | None = None
    epss_digest: str | None = None
    disclaimer: str


class ThreatIntelResponseDTO(BaseModel):
    """Aggregated threat intelligence context for an analysis run."""

    analysis_id: uuid.UUID
    intel_items: list[ThreatIntelItemDTO]
    source_freshness: str
    disclaimer: str


class FingerprintabilityComponentDTO(BaseModel):
    """Individual side-channel distinguishability component."""

    name: str
    score: float
    weight: float
    is_available: bool
    rationale: str


class FingerprintabilityDTO(BaseModel):
    """Side-channel behavioral distinguishability assessment."""

    analysis_id: uuid.UUID
    overall_index: float | None
    status: str
    methodology_version: str
    methodology_hash: str
    components: dict[str, FingerprintabilityComponentDTO]
    flow_count: int
    calibration_status: str
    ml_model_bundle_id: str | None = None
    disclaimer: str


class ReactFlowNodeDTO(BaseModel):
    """Node formatted for React Flow canvas."""

    id: str
    type: str
    position: dict[str, int]
    data: dict[str, Any]


class ReactFlowEdgeDTO(BaseModel):
    """Directed edge formatted for React Flow canvas."""

    id: str
    source: str
    target: str
    label: str
    animated: bool = False
    data: dict[str, Any] = Field(default_factory=dict)


class EvidenceGraphDTO(BaseModel):
    """Forensic provenance graph exportable to React Flow."""

    analysis_id: uuid.UUID
    capture_sha256: str
    nodes_count: int
    edges_count: int
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    react_flow: dict[str, Any] = {}
    manifest_sha256: str = ""

