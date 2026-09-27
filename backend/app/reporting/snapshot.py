"""Structured immutable analysis snapshot compiler for Stage 9 reporting."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models.capture import AnalysisRun, ProtocolObservation
from app.db.models.ml import FlowClassification, MLInferenceRun
from app.db.models.reconstruction import (
    ChildSecurityAssociation,
    ESPFlow,
    IKESession,
)
from app.db.models.security import (
    ComplianceEvaluationModel,
    FingerprintabilityAssessmentModel,
    RiskAssessmentModel,
    ScoreAssessmentModel,
    SecurityFindingModel,
    ThreatInstanceModel,
)


class AnalysisSnapshotBuilder:
    """Extracts, normalizes, and seals immutable forensic evidence snapshots for reporting."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def build_snapshot(self, analysis_id: uuid.UUID) -> dict[str, Any]:
        """Aggregate all analysis results across Stages 3-8 into a deterministic report dictionary."""
        # 1. Fetch AnalysisRun and Capture
        stmt_run = (
            select(AnalysisRun)
            .options(selectinload(AnalysisRun.capture))
            .where(AnalysisRun.id == analysis_id)
        )
        res_run = await self.db.execute(stmt_run)
        run = res_run.scalar_one_or_none()
        if not run:
            raise ValueError(f"Analysis '{analysis_id}' not found")

        capture = run.capture

        # 2. Fetch Protocol Observations
        stmt_obs = (
            select(ProtocolObservation)
            .where(ProtocolObservation.analysis_id == analysis_id)
            .order_by(ProtocolObservation.frame_number)
        )
        res_obs = await self.db.execute(stmt_obs)
        observations = res_obs.scalars().all()

        protocol_facts = {
            "total_observations": len(observations),
            "ike_versions": sorted(
                {
                    o.normalized_value
                    for o in observations
                    if o.category == "IKE_HEADER" and o.field_name == "version"
                }
                or {o.protocol for o in observations if o.protocol in ("IKEv1", "IKEv2")}
            ),
            "protocols_detected": sorted({o.protocol for o in observations if getattr(o, "protocol", None)}),
            "nat_detected": any(
                o.protocol == "NAT-T"
                or o.category == "NAT_T"
                or "nat" in getattr(o, "field_name", "").lower()
                for o in observations
            ),
            "transforms_observed": sorted(
                {
                    o.normalized_value
                    for o in observations
                    if o.category == "IKE_TRANSFORM"
                    or "cipher" in getattr(o, "field_name", "").lower()
                    or "encr" in getattr(o, "field_name", "").lower()
                }
            ),
            "dh_groups": sorted(
                {
                    o.normalized_value
                    for o in observations
                    if "dh" in getattr(o, "field_name", "").lower()
                    or "group" in getattr(o, "field_name", "").lower()
                }
            ),
        }

        # 3. Fetch SAs & Flows
        stmt_ike = (
            select(IKESession)
            .options(selectinload(IKESession.ike_sas))
            .where(IKESession.analysis_id == analysis_id)
        )
        res_ike = await self.db.execute(stmt_ike)
        ike_sessions = res_ike.scalars().all()

        stmt_csa = (
            select(ChildSecurityAssociation)
            .where(ChildSecurityAssociation.analysis_id == analysis_id)
        )
        res_csa = await self.db.execute(stmt_csa)
        child_sas = res_csa.scalars().all()

        stmt_flows = select(ESPFlow).where(ESPFlow.analysis_id == analysis_id)
        res_flows = await self.db.execute(stmt_flows)
        flows = res_flows.scalars().all()

        total_bytes = sum(f.byte_count for f in flows)
        total_packets = sum(f.packet_count for f in flows)

        sa_summary = {
            "ike_session_count": len(ike_sessions),
            "child_sa_count": len(child_sas),
            "flow_count": len(flows),
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "child_sas": [
                {
                    "id": str(c.id),
                    "protocol": c.protocol,
                    "inbound_spi": c.inbound_spi,
                    "outbound_spi": c.outbound_spi,
                    "mode": c.mode,
                    "pfs_status": c.pfs_status,
                    "encryption_algorithm": c.encryption_algorithm or "UNKNOWN",
                    "integrity_algorithm": c.integrity_algorithm or "UNKNOWN",
                    "lifecycle_state": c.lifecycle_state,
                    "evidence_state": c.evidence_state,
                }
                for c in child_sas
            ],
        }

        # 4. Fetch Stage 7/17 ML Classifications and Run Lifecycle
        stmt_run = (
            select(MLInferenceRun)
            .where(MLInferenceRun.analysis_id == analysis_id, MLInferenceRun.is_current == True)  # noqa: E712
            .order_by(MLInferenceRun.created_at.desc())
        )
        res_run = await self.db.execute(stmt_run)
        current_run = res_run.scalars().first()

        if current_run:
            stmt_ml = (
                select(FlowClassification)
                .where(FlowClassification.run_id == current_run.id)
            )
            res_ml = await self.db.execute(stmt_ml)
            ml_records = res_ml.scalars().all()
        else:
            # Fallback for unlinked legacy classifications: join ESPFlow
            stmt_ml = (
                select(FlowClassification)
                .join(ESPFlow, FlowClassification.flow_id == ESPFlow.id)
                .where(ESPFlow.analysis_id == analysis_id)
            )
            res_ml = await self.db.execute(stmt_ml)
            ml_records = res_ml.scalars().all()

        classified_records = [m for m in ml_records if m.input_status in ("VALID", "COMPLETE")]
        traffic_summary = {
            "ml_run_status": current_run.status if current_run else ("COMPLETED" if ml_records else "NOT_CONFIGURED"),
            "model_version": current_run.bundle_version if current_run else (getattr(ml_records[0].artifact, "version", None) if (ml_records and ml_records[0].artifact) else None),
            "model_bundle_id": current_run.bundle_id if current_run else (getattr(ml_records[0].artifact, "bundle_id", None) if (ml_records and ml_records[0].artifact) else None),
            "total_flows": len(ml_records),
            "classified_flows": len(classified_records),
            "skipped_flows": current_run.skipped_count if current_run else sum(1 for m in ml_records if m.input_status not in ("VALID", "COMPLETE")),
            "classes_detected": sorted({m.final_class for m in classified_records if m.final_class not in ["UNKNOWN", "UNAVAILABLE"]}),
            "avg_calibrated_confidence": (
                round(sum(m.calibrated_confidence for m in classified_records) / len(classified_records), 4)
                if classified_records
                else None
            ),
            "ood_count": sum(1 for m in classified_records if m.ood_status in ["OOD_REJECTED", "UNKNOWN_UNSEEN"]),
            "anomaly_count": sum(1 for m in classified_records if m.behavioral_anomaly_status in ["ANOMALOUS_BEHAVIOR", "STATISTICAL_BEHAVIORAL_ANOMALY"]),
            "class_distribution": {},
        }
        for m in classified_records:
            traffic_summary["class_distribution"][m.final_class] = (
                traffic_summary["class_distribution"].get(m.final_class, 0) + 1
            )

        # 5. Fetch Stage 8 Security Data
        stmt_evals = (
            select(ComplianceEvaluationModel)
            .where(ComplianceEvaluationModel.analysis_id == analysis_id)
        )
        res_evals = await self.db.execute(stmt_evals)
        evals = res_evals.scalars().all()

        compliance_summary = {
            "total_evaluations": len(evals),
            "pass_count": sum(1 for e in evals if e.compliance_state == "PASS"),
            "fail_count": sum(1 for e in evals if e.compliance_state == "FAIL"),
            "unknown_count": sum(1 for e in evals if e.compliance_state == "UNKNOWN"),
            "not_applicable_count": sum(1 for e in evals if e.compliance_state == "NOT_APPLICABLE"),
            "evaluations": [
                {
                    "rule_id": e.rule_id,
                    "rule_title": getattr(e, "rule_title", e.rule_id),
                    "category": getattr(e, "category", getattr(e, "subject_type", "SECURITY")),
                    "severity": getattr(e, "severity", "MEDIUM"),
                    "standard": getattr(e, "standard", getattr(e, "bundle_id", "NIST")),
                    "compliance_state": e.compliance_state,
                    "evidence_state": e.evidence_state,
                    "observed_value": getattr(e, "observed_value", "N/A"),
                    "expected_value": getattr(e, "expected_value", "N/A"),
                    "rationale": e.rationale,
                }
                for e in evals
            ],
        }

        # 6. Fetch Findings
        stmt_find = (
            select(SecurityFindingModel)
            .where(SecurityFindingModel.analysis_id == analysis_id)
            .order_by(SecurityFindingModel.created_at)
        )
        res_find = await self.db.execute(stmt_find)
        findings = res_find.scalars().all()

        findings_summary = {
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f.severity == "CRITICAL"),
            "high_count": sum(1 for f in findings if f.severity == "HIGH"),
            "medium_count": sum(1 for f in findings if f.severity == "MEDIUM"),
            "low_count": sum(1 for f in findings if f.severity == "LOW"),
            "findings": [
                {
                    "finding_id": getattr(f, "finding_id", str(f.id)),
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "score_deduction": getattr(f, "score_deduction", 0.0) or 0.0,
                    "affected_entity": getattr(f, "affected_entity", getattr(f, "affected_entity_id", "UNKNOWN")),
                    "technical_description": f.technical_description,
                    "remediation_guidance": getattr(f, "remediation_guidance", "N/A") or "N/A",
                    "evidence_references": getattr(f, "evidence_references", []) or [],
                    "evidence_state": f.evidence_state,
                    "root_cause_key": f.root_cause_key,
                }
                for f in findings
            ],
        }

        # 7. Fetch Score, Risk, Threats, Fingerprintability
        stmt_score = (
            select(ScoreAssessmentModel)
            .where(ScoreAssessmentModel.analysis_id == analysis_id)
        )
        res_score = await self.db.execute(stmt_score)
        score_row = res_score.scalar_one_or_none()

        score_data = {
            "score": score_row.overall_score if score_row else 100.0,
            "evidence_coverage": (score_row.coverage_percentage / 100.0) if score_row else 0.0,
            "methodology_version": score_row.score_policy_version if score_row else "1.0.0",
            "score_policy_hash": score_row.score_policy_hash if score_row else "default",
            "itemized_deductions": score_row.deduction_audit if score_row else {},
        }

        stmt_risk = (
            select(RiskAssessmentModel)
            .where(RiskAssessmentModel.analysis_id == analysis_id)
        )
        res_risk = await self.db.execute(stmt_risk)
        risk_row = res_risk.scalar_one_or_none()

        risk_data = {
            "aggregate_risk_tier": getattr(risk_row, "overall_risk_tier", getattr(risk_row, "aggregate_risk_tier", "LOW")) if risk_row else "LOW",
            "overall_risk_tier": getattr(risk_row, "overall_risk_tier", "LOW") if risk_row else "LOW",
            "risk_score": getattr(risk_row, "risk_score", 0.0) if risk_row else 0.0,
            "rationale": getattr(risk_row, "rationale", "No severe security violations observed.") if risk_row else "No severe security violations observed.",
            "risk_policy_id": getattr(risk_row, "risk_policy_id", "risk_policy_canonical_v1") if risk_row else "risk_policy_canonical_v1",
            "risk_policy_version": getattr(risk_row, "risk_policy_version", "1.0.0") if risk_row else "1.0.0",
            "risk_policy_hash": getattr(risk_row, "risk_policy_hash", "") if risk_row else "",
            "evidence_coverage": getattr(risk_row, "evidence_coverage", None) if risk_row else None,
            "evidence_gaps_count": getattr(risk_row, "evidence_gaps_count", 0) if risk_row else 0,
            "methodology_type": getattr(risk_row, "methodology_type", "DETERMINISTIC_PRIORITIZATION_HEURISTIC") if risk_row else "DETERMINISTIC_PRIORITIZATION_HEURISTIC",
        }

        stmt_threats = (
            select(ThreatInstanceModel)
            .where(ThreatInstanceModel.analysis_id == analysis_id)
        )
        res_threats = await self.db.execute(stmt_threats)
        threat_rows = res_threats.scalars().all()

        threats_data = [
            {
                "threat_id": t.threat_id,
                "title": getattr(t, "threat_name", getattr(t, "title", "Threat")),
                "threat_name": getattr(t, "threat_name", "Threat"),
                "category": getattr(t, "attack_vector", getattr(t, "category", "UNKNOWN")),
                "attack_vector": getattr(t, "attack_vector", "UNKNOWN"),
                "likelihood": getattr(t, "likelihood", "LOW"),
                "impact": getattr(t, "impact", "LOW"),
                "risk_tier": getattr(t, "risk_tier", "LOW"),
                "mitre_technique_id": getattr(t, "mitre_attack_id", getattr(t, "mitre_technique_id", "N/A")),
                "mitre_attack_id": getattr(t, "mitre_attack_id", None),
                "mitre_attack_name": getattr(t, "mitre_attack_name", None),
                "mitre_attack_url": getattr(t, "mitre_attack_url", None),
                "catalog_hash": getattr(t, "catalog_hash", None),
                "nist_control": getattr(t, "nist_control", "N/A"),
                "evidence_state": getattr(t, "evidence_state", "VERIFIED"),
            }
            for t in threat_rows
        ]

        stmt_mfi = (
            select(FingerprintabilityAssessmentModel)
            .where(FingerprintabilityAssessmentModel.analysis_id == analysis_id)
        )
        res_mfi = await self.db.execute(stmt_mfi)
        mfi_row = res_mfi.scalar_one_or_none()

        raw_components = getattr(mfi_row, "components", {}) if mfi_row else {}
        comp_scores = {}
        if isinstance(raw_components, dict):
            for k, v in raw_components.items():
                if isinstance(v, dict) and "score" in v and isinstance(v["score"], (int, float)):
                    comp_scores[k] = float(v["score"])
                elif isinstance(v, (int, float)):
                    comp_scores[k] = float(v)
                else:
                    comp_scores[k] = 0.0

        mfi_data = {
            "overall_index": mfi_row.overall_index if (mfi_row and mfi_row.overall_index is not None) else 0.0,
            "is_experimental": getattr(mfi_row, "is_experimental", True) if mfi_row else True,
            "component_metrics": comp_scores,
            "components": raw_components,
            "disclaimer": (
                getattr(mfi_row, "disclaimer", "Behavioral side-channel distinguishability of encrypted traffic metadata. Does not indicate plaintext payload recovery.")
                if mfi_row
                else "Behavioral side-channel distinguishability of encrypted traffic metadata. Does not indicate plaintext payload recovery."
            ),
        }

        # Build master snapshot dictionary
        snapshot = {
            "analysis_id": str(analysis_id),
            "capture": {
                "id": str(capture.id) if capture else None,
                "filename": (capture.original_filename or "unknown.pcap") if capture else "unknown.pcap",
                "sha256": (capture.sha256_hash or "unknown") if capture else "unknown",
                "file_size_bytes": capture.file_size_bytes if capture else 0,
                "packet_count": capture.packet_count if capture else 0,
            },
            "analysis": {
                "status": run.status,
                "current_stage": run.current_stage,
                "parser_engine": run.parser_engine,
                "parser_version": run.parser_version,
                "schema_version": run.schema_version,
                "created_at": run.created_at.isoformat() if run.created_at else None,
                "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            },
            "protocol": protocol_facts,
            "security_associations": sa_summary,
            "traffic": traffic_summary,
            "compliance": compliance_summary,
            "findings": findings_summary,
            "score": score_data,
            "risk": risk_data,
            "threats": threats_data,
            "metadata_fingerprintability": mfi_data,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Compute deterministic snapshot hash (sorted keys)
        serialized = json.dumps(snapshot, sort_keys=True, default=str)
        snapshot_sha256 = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        snapshot["snapshot_sha256"] = snapshot_sha256

        return snapshot
