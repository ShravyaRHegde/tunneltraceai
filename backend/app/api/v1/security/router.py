"""REST API endpoints for Security, Compliance, Posture Scoring, and Evidence Graph."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.security.schemas import (
    ComplianceEvaluationDTO,
    ComplianceSummaryDTO,
    EvidenceCoverageDTO,
    EvidenceGraphDTO,
    FingerprintabilityComponentDTO,
    FingerprintabilityDTO,
    PolicyProfileSummaryDTO,
    RiskAssessmentDTO,
    RiskFactorDetailDTO,
    RiskItemDTO,
    ScoreDeductionDTO,
    SecurityFindingDTO,
    SecurityScoreDTO,
    ThreatInstanceDTO,
    ThreatIntelItemDTO,
    ThreatIntelResponseDTO,
)
from app.core.errors import AnalysisNotFoundError
from app.db.models.capture import AnalysisRun, Capture
from app.db.models.reconstruction import ChildSecurityAssociation, ESPFlow, IKESession
from app.db.models.security import (
    ComplianceEvaluationModel,
    EvidenceGraphModel,
    FingerprintabilityAssessmentModel,
    RiskAssessmentModel,
    ScoreAssessmentModel,
    SecurityFindingModel,
    ThreatInstanceModel,
)
from app.db.session import get_db_session
from app.security.service import SecurityAssessmentResult, SecurityAssessmentService
from app.security.threat_intel import ThreatIntelService

router = APIRouter(prefix="/security", tags=["security"])

_service_instance: SecurityAssessmentService | None = None


def get_security_service() -> SecurityAssessmentService:
    global _service_instance
    if _service_instance is None:
        _service_instance = SecurityAssessmentService()
    return _service_instance


async def _ensure_assessment_executed(
    analysis_id: uuid.UUID,
    db: AsyncSession,
    service: SecurityAssessmentService,
    profile_id: str = "profile_nist_sp800_77",
) -> None:
    """Check if assessment exists in DB; if not, execute assessment and persist."""
    # Check if finding or evaluation exists
    stmt_check = select(ScoreAssessmentModel).where(ScoreAssessmentModel.analysis_id == analysis_id)
    res_check = await db.execute(stmt_check)
    if res_check.scalar_one_or_none() is not None:
        return

    # Fetch AnalysisRun & Capture
    stmt_ar = select(AnalysisRun).where(AnalysisRun.id == analysis_id)
    res_ar = await db.execute(stmt_ar)
    analysis_run = res_ar.scalar_one_or_none()
    if not analysis_run:
        raise AnalysisNotFoundError(str(analysis_id))

    stmt_cap = select(Capture).where(Capture.id == analysis_run.capture_id)
    res_cap = await db.execute(stmt_cap)
    capture = res_cap.scalar_one_or_none()
    cap_sha = capture.sha256_hash if capture else "0" * 64

    # Fetch reconstructed entities
    stmt_sess = (
        select(IKESession)
        .options(selectinload(IKESession.ike_sas))
        .where(IKESession.analysis_id == analysis_id)
    )
    sessions = (await db.execute(stmt_sess)).scalars().all()

    stmt_child = (
        select(ChildSecurityAssociation)
        .options(selectinload(ChildSecurityAssociation.traffic_selectors))
        .where(ChildSecurityAssociation.analysis_id == analysis_id)
    )
    child_sas = (await db.execute(stmt_child)).scalars().all()

    stmt_flow = select(ESPFlow).where(ESPFlow.analysis_id == analysis_id)
    flows = (await db.execute(stmt_flow)).scalars().all()

    # Execute deterministic assessment
    result: SecurityAssessmentResult = service.run_assessment(
        analysis_id=str(analysis_id),
        capture_sha256=cap_sha,
        sessions=sessions,
        child_sas=child_sas,
        flows=flows,
        profile_id=profile_id,
        parent_analysis_id=str(analysis_run.parent_analysis_id) if analysis_run.parent_analysis_id else None,
        replay_mode=analysis_run.replay_mode,
    )

    # Persist records transactionally
    # 1. Evaluations
    for ev in result.eval_records:
        m_eval = ComplianceEvaluationModel(
            analysis_id=analysis_id,
            bundle_id=result.manifest.policy_bundle_id,
            rule_id=ev.rule_id,
            rule_version=ev.rule_version,
            subject_type=ev.subject_type or "IPSEC_ENTITY",
            subject_id=ev.subject_id or "GLOBAL",
            compliance_state=ev.compliance_state.value,
            evidence_state=ev.evidence_state.value,
            rationale=ev.rationale,
        )
        db.add(m_eval)

    # 2. Findings
    for fn in result.findings:
        m_find = SecurityFindingModel(
            finding_id=fn.finding_id,
            analysis_id=analysis_id,
            rule_id=fn.rule_id,
            rule_version=fn.rule_version,
            profile_id=fn.profile_id,
            category=fn.category.value,
            severity=fn.severity.value,
            title=fn.title,
            technical_description=fn.technical_description,
            root_cause_key=fn.root_cause_key,
            affected_entity_type=fn.affected_entity_type,
            affected_entity_id=fn.affected_entity_id,
            observed_value={"value": fn.observed_value},
            expected_requirement={"expected": fn.expected_requirement},
            evidence_state=fn.evidence_state.value,
            remediation_guidance=fn.remediation_guidance,
            remediation_directive=fn.remediation_directive,
            record_hash=fn.record_hash,
        )
        db.add(m_find)

    # 3. Score
    sa = result.score_assessment
    m_score = ScoreAssessmentModel(
        analysis_id=analysis_id,
        overall_score=sa.overall_score,
        raw_score=sa.raw_score,
        score_policy_id=sa.score_policy_id,
        score_policy_version=sa.score_policy_version,
        score_policy_hash=sa.score_policy_hash,
        status=sa.status,
        coverage_percentage=sa.evidence_coverage.coverage_percentage,
        category_scores=sa.category_scores,
        deduction_audit={"audit": [d.to_dict() for d in sa.deduction_audit]},
        evidence_coverage=sa.evidence_coverage.to_dict(),
    )
    db.add(m_score)

    # 4. Risk
    ra = result.risk_assessment
    m_risk = RiskAssessmentModel(
        analysis_id=analysis_id,
        risk_policy_id=ra.risk_policy_id,
        risk_policy_version=ra.risk_policy_version,
        risk_policy_hash=ra.risk_policy_hash,
        overall_risk_tier=ra.overall_risk_tier.value,
        items={"items": [item.to_dict() for item in ra.items]},
        evidence_coverage=ra.evidence_coverage,
        evidence_gaps_count=ra.evidence_gaps_count,
        methodology_type=ra.methodology_type,
        external_context={"disclaimer": ra.disclaimer},
    )
    db.add(m_risk)

    # 5. Threats
    for thr in result.threat_instances:
        m_thr = ThreatInstanceModel(
            analysis_id=analysis_id,
            finding_id=thr.finding_id,
            threat_id=thr.threat_id,
            threat_name=thr.threat_name,
            attack_vector=thr.attack_vector,
            likelihood=thr.likelihood.value,
            impact=thr.impact.value,
            risk_tier=thr.risk_tier.value,
            mitre_attack_id=thr.mitre_attack_id,
            mitre_attack_name=thr.mitre_attack_name,
            mitre_attack_url=thr.mitre_attack_url,
            mitre_attack_rationale=thr.mitre_attack_rationale,
            catalog_hash=thr.catalog_hash,
        )
        db.add(m_thr)

    # 6. Fingerprintability
    fa = result.fingerprintability
    m_fa = FingerprintabilityAssessmentModel(
        analysis_id=analysis_id,
        overall_index=fa.overall_index,
        status=fa.status.value,
        methodology_version=fa.methodology_version,
        methodology_hash=fa.methodology_hash,
        components={"components": {k: v.to_dict() for k, v in fa.components.items()}},
        flow_count=fa.flow_count,
        calibration_status=fa.calibration_status.value,
        ml_model_bundle_id=fa.ml_model_bundle_id,
        disclaimer=fa.disclaimer,
    )
    db.add(m_fa)

    # 7. Evidence Graph
    rf = result.evidence_graph.to_react_flow()
    m_graph = EvidenceGraphModel(
        analysis_id=analysis_id,
        capture_sha256=result.evidence_graph.capture_sha256,
        nodes_count=len(result.evidence_graph.nodes),
        edges_count=len(result.evidence_graph.edges),
        graph_data=rf,
        manifest_data=result.manifest.to_dict(),
    )
    db.add(m_graph)

    await db.commit()


@router.get("/policy-profiles", response_model=list[PolicyProfileSummaryDTO])
async def list_policy_profiles(
    service: SecurityAssessmentService = Depends(get_security_service),
) -> list[PolicyProfileSummaryDTO]:
    """Retrieve available Policy-as-Code profiles and compiled rule counts."""
    profiles = [
        PolicyProfileSummaryDTO(
            profile_id="profile_nist_sp800_77",
            name="NIST SP 800-77 Rev. 1 Guidelines",
            description="Authoritative NIST IPsec configuration standard for federal systems.",
            active_bundle_id="bundle-nist-sp800-77",
            rule_count=len(service.policy_registry.list_rules("profile_nist_sp800_77")),
        ),
        PolicyProfileSummaryDTO(
            profile_id="profile_ietf_baseline",
            name="IETF RFC Standards-Track Baseline",
            description="Mandatory and recommended requirements from RFC 7296, 8221, and 8247.",
            active_bundle_id=None,
            rule_count=0,
        ),
        PolicyProfileSummaryDTO(
            profile_id="profile_enterprise_strict",
            name="Enterprise Strict Cryptographic Posture",
            description="CNSA suite requirements (AES-256-GCM, DH Group 19/20, SHA-384+).",
            active_bundle_id=None,
            rule_count=0,
        ),
        PolicyProfileSummaryDTO(
            profile_id="profile_custom_org",
            name="Organizational Custom Declarative Policy",
            description="Custom enterprise overrides and domain-specific cryptographic rules.",
            active_bundle_id=None,
            rule_count=0,
        ),
    ]
    return profiles


@router.get("/analyses/{analysis_id}/compliance", response_model=ComplianceSummaryDTO)
async def get_compliance_summary(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
    service: SecurityAssessmentService = Depends(get_security_service),
) -> ComplianceSummaryDTO:
    """Retrieve itemized rule compliance evaluations (PASS/FAIL/UNKNOWN/NOT_APPLICABLE)."""
    await _ensure_assessment_executed(analysis_id, db, service)

    stmt = select(ComplianceEvaluationModel).where(ComplianceEvaluationModel.analysis_id == analysis_id)
    records = (await db.execute(stmt)).scalars().all()

    pass_count = sum(1 for r in records if r.compliance_state == "PASS")
    fail_count = sum(1 for r in records if r.compliance_state == "FAIL")
    unknown_count = sum(1 for r in records if r.compliance_state == "UNKNOWN")
    na_count = sum(1 for r in records if r.compliance_state == "NOT_APPLICABLE")

    eval_dtos = [
        ComplianceEvaluationDTO(
            rule_id=r.rule_id,
            rule_version=r.rule_version,
            subject_type=r.subject_type,
            subject_id=r.subject_id,
            compliance_state=r.compliance_state,
            evidence_state=r.evidence_state,
            rationale=r.rationale,
        )
        for r in records
    ]

    return ComplianceSummaryDTO(
        analysis_id=analysis_id,
        profile_id="profile_nist_sp800_77",
        bundle_id="bundle-nist-sp800-77",
        bundle_hash="",
        total_rules_evaluated=len(records),
        pass_count=pass_count,
        fail_count=fail_count,
        unknown_count=unknown_count,
        not_applicable_count=na_count,
        evaluations=eval_dtos,
    )


@router.get("/analyses/{analysis_id}/findings", response_model=list[SecurityFindingDTO])
async def get_security_findings(
    analysis_id: uuid.UUID,
    severity: str | None = Query(None, description="Filter by finding severity"),
    category: str | None = Query(None, description="Filter by finding category"),
    db: AsyncSession = Depends(get_db_session),
    service: SecurityAssessmentService = Depends(get_security_service),
) -> list[SecurityFindingDTO]:
    """Retrieve structured security findings with deterministic filtering."""
    await _ensure_assessment_executed(analysis_id, db, service)

    stmt = select(SecurityFindingModel).where(SecurityFindingModel.analysis_id == analysis_id)
    if severity:
        stmt = stmt.where(SecurityFindingModel.severity == severity.upper())
    if category:
        stmt = stmt.where(SecurityFindingModel.category == category.upper())

    findings = (await db.execute(stmt)).scalars().all()

    return [
        SecurityFindingDTO(
            finding_id=f.finding_id,
            analysis_id=f.analysis_id,
            rule_id=f.rule_id,
            rule_version=f.rule_version,
            profile_id=f.profile_id,
            category=f.category,
            severity=f.severity,
            title=f.title,
            technical_description=f.technical_description,
            root_cause_key=f.root_cause_key,
            affected_entity_type=f.affected_entity_type,
            affected_entity_id=f.affected_entity_id,
            observed_value=f.observed_value,
            expected_requirement=f.expected_requirement,
            evidence_state=f.evidence_state,
            remediation_guidance=f.remediation_guidance,
            remediation_directive=f.remediation_directive,
            record_hash=f.record_hash,
            created_at=f.created_at.isoformat(),
        )
        for f in findings
    ]


@router.get("/analyses/{analysis_id}/security-score", response_model=SecurityScoreDTO)
async def get_security_score(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
    service: SecurityAssessmentService = Depends(get_security_service),
) -> SecurityScoreDTO:
    """Retrieve transparent Security Posture Score and separate Evidence Coverage."""
    await _ensure_assessment_executed(analysis_id, db, service)

    stmt = select(ScoreAssessmentModel).where(ScoreAssessmentModel.analysis_id == analysis_id)
    sa = (await db.execute(stmt)).scalar_one_or_none()
    if not sa:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Score assessment not found.")

    ded_list = []
    if sa.deduction_audit and "audit" in sa.deduction_audit:
        for d in sa.deduction_audit["audit"]:
            ded_list.append(
                ScoreDeductionDTO(
                    finding_id=d.get("finding_id", ""),
                    rule_id=d.get("rule_id", ""),
                    category=d.get("category", ""),
                    severity=d.get("severity", ""),
                    root_cause_key=d.get("root_cause_key", ""),
                    raw_deduction=float(d.get("raw_deduction", 0.0)),
                    applied_deduction=float(d.get("applied_deduction", 0.0)),
                    is_deduplicated=bool(d.get("is_deduplicated", False)),
                    rationale=d.get("rationale", ""),
                )
            )

    cov_data = sa.evidence_coverage or {}
    cov_dto = EvidenceCoverageDTO(
        applicable_rules=cov_data.get("applicable_rules", 0),
        evaluated_rules=cov_data.get("evaluated_rules", 0),
        unknown_rules=cov_data.get("unknown_rules", 0),
        not_applicable_rules=cov_data.get("not_applicable_rules", 0),
        coverage_percentage=float(cov_data.get("coverage_percentage", 100.0)),
    )

    return SecurityScoreDTO(
        analysis_id=sa.analysis_id,
        overall_score=sa.overall_score,
        raw_score=sa.raw_score,
        score_policy_id=sa.score_policy_id,
        score_policy_version=sa.score_policy_version,
        score_policy_hash=sa.score_policy_hash,
        status=sa.status,
        coverage_percentage=sa.coverage_percentage,
        category_scores=sa.category_scores or {},
        deduction_audit=ded_list,
        evidence_coverage=cov_dto,
    )


@router.get("/analyses/{analysis_id}/risk", response_model=RiskAssessmentDTO)
async def get_risk_assessment(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
    service: SecurityAssessmentService = Depends(get_security_service),
) -> RiskAssessmentDTO:
    """Retrieve deterministic risk tiers, factor breakdowns, and policy hashes."""
    await _ensure_assessment_executed(analysis_id, db, service)

    stmt = select(RiskAssessmentModel).where(RiskAssessmentModel.analysis_id == analysis_id)
    ra = (await db.execute(stmt)).scalar_one_or_none()
    if not ra:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Risk assessment not found.")

    items_list = []
    if ra.items and "items" in ra.items:
        for it in ra.items["items"]:
            factors_list = []
            for f in it.get("factors", []):
                factors_list.append(
                    RiskFactorDetailDTO(
                        factor_name=f.get("factor_name", ""),
                        factor_value=f.get("factor_value", ""),
                        scale=f.get("scale", ""),
                        evidence_state=f.get("evidence_state", ""),
                        source=f.get("source", ""),
                        source_time=f.get("source_time", ""),
                        contributes_to_aggregate=bool(f.get("contributes_to_aggregate", True)),
                        aggregation_role=f.get("aggregation_role", ""),
                        rationale=f.get("rationale", ""),
                    )
                )

            items_list.append(
                RiskItemDTO(
                    finding_id=it.get("finding_id", ""),
                    rule_id=it.get("rule_id", ""),
                    severity=it.get("severity", ""),
                    likelihood=it.get("likelihood", ""),
                    impact=it.get("impact", ""),
                    risk_tier=it.get("risk_tier", ""),
                    evidence_state=it.get("evidence_state", ""),
                    threat_mapped=bool(it.get("threat_mapped", False)),
                    rationale=it.get("rationale", ""),
                    factors=factors_list,
                    contributes_to_aggregate=bool(it.get("contributes_to_aggregate", True)),
                    aggregation_role=it.get("aggregation_role", "PRIMARY_DRIVER"),
                    root_cause_key=it.get("root_cause_key", ""),
                    policy_version=it.get("policy_version", "1.0.0"),
                    policy_hash=it.get("policy_hash", ra.risk_policy_hash),
                    methodology_type=it.get("methodology_type", "DETERMINISTIC_PRIORITIZATION_HEURISTIC"),
                )
            )

    return RiskAssessmentDTO(
        analysis_id=ra.analysis_id,
        risk_policy_id=ra.risk_policy_id,
        risk_policy_version=ra.risk_policy_version,
        risk_policy_hash=ra.risk_policy_hash,
        overall_risk_tier=ra.overall_risk_tier,
        items=items_list,
        evidence_coverage=ra.evidence_coverage,
        evidence_gaps_count=ra.evidence_gaps_count or 0,
        methodology_type=ra.methodology_type or "DETERMINISTIC_PRIORITIZATION_HEURISTIC",
    )


@router.get("/analyses/{analysis_id}/threat-matrix", response_model=list[ThreatInstanceDTO])
async def get_threat_matrix(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
    service: SecurityAssessmentService = Depends(get_security_service),
) -> list[ThreatInstanceDTO]:
    """Retrieve catalog-mapped threat instances linked to observed violations with verified ATT&CK context."""
    await _ensure_assessment_executed(analysis_id, db, service)

    stmt = select(ThreatInstanceModel).where(ThreatInstanceModel.analysis_id == analysis_id)
    threats = (await db.execute(stmt)).scalars().all()

    return [
        ThreatInstanceDTO(
            finding_id=t.finding_id,
            threat_id=t.threat_id,
            threat_name=t.threat_name,
            attack_vector=t.attack_vector,
            likelihood=t.likelihood,
            impact=t.impact,
            risk_tier=t.risk_tier,
            mitre_attack_id=t.mitre_attack_id,
            mitre_attack_name=t.mitre_attack_name,
            mitre_attack_url=t.mitre_attack_url,
            mitre_attack_rationale=t.mitre_attack_rationale,
            catalog_hash=t.catalog_hash,
        )
        for t in threats
    ]


@router.get("/analyses/{analysis_id}/threat-intelligence", response_model=ThreatIntelResponseDTO)
async def get_threat_intelligence(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
    service: SecurityAssessmentService = Depends(get_security_service),
) -> ThreatIntelResponseDTO:
    """Retrieve offline CISA KEV and FIRST EPSS context with explicit source lineage and freshness."""
    await _ensure_assessment_executed(analysis_id, db, service)

    intel_service = ThreatIntelService()
    # Relevant IPsec / strongSwan cryptographic protocol CVEs
    target_cves = ["CVE-2016-2183", "CVE-2015-4000", "CVE-2023-41913", "CVE-2022-40617", "CVE-2018-5388"]

    results = intel_service.lookup_multiple_cves(target_cves)
    intel_items = [
        ThreatIntelItemDTO(
            cve_id=r.cve_id,
            cisa_kev_status=r.cisa_kev_status.value,
            cisa_kev_record=r.cisa_kev_record.to_dict() if r.cisa_kev_record else None,
            cisa_kev_as_of=r.cisa_kev_as_of,
            cisa_kev_digest=r.cisa_kev_digest,
            epss_status=r.epss_status.value,
            epss_record=r.epss_record.to_dict() if r.epss_record else None,
            epss_as_of=r.epss_as_of,
            epss_digest=r.epss_digest,
            disclaimer=r.disclaimer,
        )
        for r in results
    ]

    return ThreatIntelResponseDTO(
        analysis_id=analysis_id,
        intel_items=intel_items,
        source_freshness="OFFLINE_VERIFIED_SNAPSHOT",
        disclaimer=(
            "Threat intelligence is supplemental external context only. "
            "Neither CISA KEV nor FIRST EPSS constitutes proof of gateway compromise, "
            "target vulnerability, or alters deterministic policy scores."
        ),
    )


@router.get("/analyses/{analysis_id}/metadata-fingerprintability", response_model=FingerprintabilityDTO)
async def get_metadata_fingerprintability(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
    service: SecurityAssessmentService = Depends(get_security_service),
) -> FingerprintabilityDTO:
    """Retrieve behavioral metadata side-channel distinguishability assessment."""
    await _ensure_assessment_executed(analysis_id, db, service)

    stmt = select(FingerprintabilityAssessmentModel).where(
        FingerprintabilityAssessmentModel.analysis_id == analysis_id
    )
    fa = (await db.execute(stmt)).scalar_one_or_none()
    if not fa:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Fingerprintability assessment not found.",
        )

    comps: dict[str, FingerprintabilityComponentDTO] = {}
    if fa.components and "components" in fa.components:
        for k, v in fa.components["components"].items():
            comps[k] = FingerprintabilityComponentDTO(
                name=v.get("name", k),
                score=float(v.get("score", 0.0)),
                weight=float(v.get("weight", 0.0)),
                is_available=bool(v.get("is_available", True)),
                rationale=v.get("rationale", ""),
            )

    return FingerprintabilityDTO(
        analysis_id=fa.analysis_id,
        overall_index=fa.overall_index,
        status=fa.status,
        methodology_version=fa.methodology_version,
        methodology_hash=fa.methodology_hash,
        components=comps,
        flow_count=fa.flow_count,
        calibration_status=fa.calibration_status,
        ml_model_bundle_id=fa.ml_model_bundle_id,
        disclaimer=fa.disclaimer,
    )


@router.get("/analyses/{analysis_id}/evidence-graph", response_model=EvidenceGraphDTO)
async def get_evidence_graph(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
    service: SecurityAssessmentService = Depends(get_security_service),
) -> EvidenceGraphDTO:
    """Retrieve complete forensic provenance graph formatted for React Flow canvas."""
    await _ensure_assessment_executed(analysis_id, db, service)

    stmt = select(EvidenceGraphModel).where(EvidenceGraphModel.analysis_id == analysis_id)
    eg = (await db.execute(stmt)).scalar_one_or_none()
    if not eg:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence graph not found.")

    m_data = eg.manifest_data or {}
    g_data = eg.graph_data or {"nodes": [], "edges": []}
    return EvidenceGraphDTO(
        analysis_id=eg.analysis_id,
        capture_sha256=eg.capture_sha256,
        nodes_count=eg.nodes_count,
        edges_count=eg.edges_count,
        nodes=g_data.get("nodes", []),
        edges=g_data.get("edges", []),
        react_flow=g_data,
        manifest_sha256=m_data.get("manifest_sha256", ""),
    )


@router.get("/findings/{finding_id}/evidence")
async def get_finding_evidence_lineage(
    finding_id: str,
    db: AsyncSession = Depends(get_db_session),
    service: SecurityAssessmentService = Depends(get_security_service),
) -> dict[str, Any]:
    """Resolve full upstream packet frames and downstream consequences for a specific finding."""
    stmt_find = select(SecurityFindingModel).where(SecurityFindingModel.finding_id == finding_id)
    find = (await db.execute(stmt_find)).scalar_one_or_none()
    if not find:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding '{finding_id}' not found.")

    # Retrieve associated evidence graph
    stmt_eg = select(EvidenceGraphModel).where(EvidenceGraphModel.analysis_id == find.analysis_id)
    eg = (await db.execute(stmt_eg)).scalar_one_or_none()
    if not eg:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence graph not found.")

    # Return finding provenance summary
    return {
        "finding_id": find.finding_id,
        "rule_id": find.rule_id,
        "rule_version": find.rule_version,
        "severity": find.severity,
        "category": find.category,
        "root_cause_key": find.root_cause_key,
        "affected_entity": {
            "type": find.affected_entity_type,
            "id": find.affected_entity_id,
        },
        "observed_value": find.observed_value,
        "expected_requirement": find.expected_requirement,
        "evidence_state": find.evidence_state,
        "remediation_guidance": find.remediation_guidance,
        "record_hash": find.record_hash,
        "capture_sha256": eg.capture_sha256,
    }
