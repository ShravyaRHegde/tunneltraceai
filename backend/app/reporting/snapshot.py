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

        truly_classified = [
            m for m in ml_records
            if m.input_status in ("VALID", "COMPLETE")
            and getattr(m, "ood_status", "") == "KNOWN_ACCEPTED"
            and m.final_class not in ("UNKNOWN", "UNAVAILABLE", "OUT_OF_DISTRIBUTION", "UNKNOWN_UNSEEN")
        ]
        ood_records = [
            m for m in ml_records
            if getattr(m, "ood_status", "") in ("OOD_REJECTED", "UNKNOWN_UNSEEN")
            or m.final_class in ("OUT_OF_DISTRIBUTION", "UNKNOWN_UNSEEN")
        ]
        valid_records = [m for m in ml_records if m.input_status in ("VALID", "COMPLETE")]

        traffic_summary = {
            "ml_run_status": current_run.status if current_run else ("COMPLETED" if ml_records else "NOT_CONFIGURED"),
            "model_version": current_run.bundle_version if current_run else (getattr(ml_records[0].artifact, "version", None) if (ml_records and ml_records[0].artifact) else None),
            "model_bundle_id": current_run.bundle_id if current_run else (getattr(ml_records[0].artifact, "bundle_id", None) if (ml_records and ml_records[0].artifact) else None),
            "total_flows": len(flows),
            "classified_flows": len(truly_classified),
            "skipped_flows": current_run.skipped_count if current_run else sum(1 for m in ml_records if m.input_status not in ("VALID", "COMPLETE")),
            "classes_detected": sorted({m.final_class for m in truly_classified}),
            "avg_calibrated_confidence": (
                round(sum(m.calibrated_confidence for m in truly_classified) / len(truly_classified), 4)
                if truly_classified
                else None
            ),
            "ood_count": len(ood_records),
            "anomaly_count": sum(1 for m in valid_records if getattr(m, "behavioral_anomaly_status", "") in ["ANOMALOUS_BEHAVIOR", "STATISTICAL_BEHAVIORAL_ANOMALY"]),
            "class_distribution": {},
        }
        for m in truly_classified:
            traffic_summary["class_distribution"][m.final_class] = (
                traffic_summary["class_distribution"].get(m.final_class, 0) + 1
            )

        # 5. Fetch Stage 8 Security Data
        stmt_evals = (
            select(ComplianceEvaluationModel)
            .where(ComplianceEvaluationModel.analysis_id == analysis_id)
            .order_by(ComplianceEvaluationModel.created_at.desc())
        )
        res_evals = await self.db.execute(stmt_evals)
        raw_evals = res_evals.scalars().all()
        evals = []
        seen_eval_rules = set()
        for e in raw_evals:
            if e.rule_id not in seen_eval_rules:
                seen_eval_rules.add(e.rule_id)
                evals.append(e)

        from app.security.policy.registry import PolicyRegistry
        from app.api.v1.security.router import resolve_compliance_severity
        policy_registry = PolicyRegistry()

        eval_items = []
        for e in evals:
            rule_def = policy_registry.get_rule(e.rule_id)
            title = rule_def.title if rule_def else e.rule_id
            cat = rule_def.category.value if rule_def else getattr(e, "subject_type", "SECURITY")
            if rule_def and rule_def.authoritative_reference:
                ref = rule_def.authoritative_reference
                std = f"{ref.source} {ref.section}"
            else:
                std = "NIST SP 800-77 Rev. 1"
            default_sev = rule_def.severity.value if rule_def else "MEDIUM"
            sev = resolve_compliance_severity(e.rule_id, cat, e.compliance_state, default_sev)

            exp_val = rule_def.assertion.expected_value if (rule_def and rule_def.assertion) else "N/A"
            if e.compliance_state == "PASS":
                obs_val = "Compliant parameters verified from capture"
            elif e.compliance_state == "UNKNOWN":
                obs_val = "Unobserved (capture evidence gap)"
            else:
                obs_val = "Not applicable to observed protocol mode"

            eval_items.append({
                "rule_id": e.rule_id,
                "rule_title": title,
                "category": cat,
                "severity": sev,
                "standard": std,
                "compliance_state": e.compliance_state,
                "evidence_state": e.evidence_state,
                "observed_value": obs_val,
                "expected_value": exp_val,
                "rationale": e.rationale,
            })

        compliance_summary = {
            "total_evaluations": len(evals),
            "pass_count": sum(1 for e in evals if e.compliance_state == "PASS"),
            "fail_count": sum(1 for e in evals if e.compliance_state == "FAIL"),
            "unknown_count": sum(1 for e in evals if e.compliance_state == "UNKNOWN"),
            "not_applicable_count": sum(1 for e in evals if e.compliance_state == "NOT_APPLICABLE"),
            "evaluations": eval_items,
        }

        # 6. Fetch Findings
        stmt_find = (
            select(SecurityFindingModel)
            .where(SecurityFindingModel.analysis_id == analysis_id)
            .order_by(SecurityFindingModel.created_at.desc())
        )
        res_find = await self.db.execute(stmt_find)
        raw_findings = res_find.scalars().all()
        findings = []
        seen_finding_keys = set()
        for f in raw_findings:
            f_key = f.finding_id or f.rule_id
            if f_key not in seen_finding_keys:
                seen_finding_keys.add(f_key)
                findings.append(f)

        # 7. Fetch Score, Risk, Threats, Fingerprintability
        stmt_score = (
            select(ScoreAssessmentModel)
            .where(ScoreAssessmentModel.analysis_id == analysis_id)
            .order_by(ScoreAssessmentModel.created_at.desc())
        )
        res_score = await self.db.execute(stmt_score)
        score_row = res_score.scalars().first()

        itemized_deductions = score_row.deduction_audit if (score_row and score_row.deduction_audit) else {}
        audit_items = []
        if isinstance(itemized_deductions, dict) and "audit" in itemized_deductions:
            audit_items = itemized_deductions["audit"]
        elif isinstance(itemized_deductions, list):
            audit_items = itemized_deductions

        deductions_by_id = {d.get("finding_id"): float(d.get("applied_deduction", 0.0)) for d in audit_items if isinstance(d, dict)}
        deductions_by_rule = {d.get("rule_id"): float(d.get("applied_deduction", 0.0)) for d in audit_items if isinstance(d, dict)}

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
                    "score_deduction": (
                        deductions_by_id.get(getattr(f, "finding_id", str(f.id)))
                        or deductions_by_rule.get(f.rule_id)
                        or (float(getattr(f, "score_deduction", 0.0)) if getattr(f, "score_deduction", None) is not None else 0.0)
                        or (25.0 if f.severity == "CRITICAL" else 15.0 if f.severity == "HIGH" else 5.0 if f.severity == "MEDIUM" else 2.0 if f.severity == "LOW" else 0.0)
                    ),
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

        # Deductions reconciliation: if deduction_audit is empty or None but findings exist
        if not itemized_deductions and findings:
            itemized_deductions = {
                (f.rule_id or getattr(f, "finding_id", str(f.id))): float(
                    getattr(f, "score_deduction", 0.0)
                    or (20.0 if f.severity == "CRITICAL" else 6.0 if f.severity == "HIGH" else 0.0)
                )
                for f in findings
                if getattr(f, "score_deduction", 0.0) or f.severity in ("CRITICAL", "HIGH")
            }

        # Evidence coverage calculation
        eval_pass = compliance_summary.get("pass_count", 0)
        eval_fail = compliance_summary.get("fail_count", 0)
        eval_unknown = compliance_summary.get("unknown_count", 0)
        coverage_pct = score_row.coverage_percentage if score_row else (
            (eval_pass + eval_fail) / (eval_pass + eval_fail + eval_unknown) * 100.0
            if (eval_pass + eval_fail + eval_unknown) > 0
            else 100.0
        )

        is_score_unassessable = (
            score_row is None and len(evals) == 0
        ) or (
            len(evals) > 0 and all(e.compliance_state == "UNKNOWN" for e in evals) and len(findings) == 0
        )

        effective_score = score_row.overall_score if score_row else (100.0 if not is_score_unassessable else None)
        score_status = "NOT_ASSESSABLE" if is_score_unassessable else (score_row.status if score_row else "VALIDATED")

        score_data = {
            "score": effective_score,
            "evidence_coverage": (coverage_pct / 100.0) if coverage_pct is not None else 1.0,
            "methodology_version": score_row.score_policy_version if score_row else "1.0.0",
            "score_policy_hash": score_row.score_policy_hash if score_row else "default",
            "itemized_deductions": itemized_deductions,
            "status": score_status,
            "is_assessable": not is_score_unassessable,
        }

        stmt_risk = (
            select(RiskAssessmentModel)
            .where(RiskAssessmentModel.analysis_id == analysis_id)
            .order_by(RiskAssessmentModel.created_at.desc())
        )
        res_risk = await self.db.execute(stmt_risk)
        risk_row = res_risk.scalars().first()

        # Deterministic risk tier calculation from findings to prevent CRITICAL/HIGH findings coexisting with LOW risk
        if is_score_unassessable and len(findings) == 0:
            computed_risk_tier = "INSUFFICIENT_EVIDENCE"
            computed_risk_score = 0.0
            computed_rationale = (
                f"Insufficient protocol evidence (only {coverage_pct:.1f}% coverage, "
                f"{eval_unknown} unknown check(s)). Posture score unassessable to prevent false sense of security."
            )
        elif findings_summary["critical_count"] > 0:
            computed_risk_tier = "CRITICAL"
            computed_risk_score = 95.0
            computed_rationale = f"Critical risk: {findings_summary['critical_count']} critical severity finding(s) observed requiring immediate remediation."
        elif findings_summary["high_count"] > 0:
            computed_risk_tier = "HIGH"
            computed_risk_score = 75.0
            computed_rationale = f"High risk: {findings_summary['high_count']} high severity finding(s) observed."
        elif findings_summary["medium_count"] > 0:
            computed_risk_tier = "MEDIUM"
            computed_risk_score = 45.0
            computed_rationale = f"Moderate risk: {findings_summary['medium_count']} medium severity finding(s) observed."
        else:
            computed_risk_tier = "LOW"
            computed_risk_score = 0.0
            computed_rationale = "No severe security violations observed."

        persisted_risk_tier = getattr(risk_row, "overall_risk_tier", getattr(risk_row, "aggregate_risk_tier", None)) if risk_row else None

        # Enforce consistency: a critical finding can never report as LOW risk; insufficient evidence is INSUFFICIENT_EVIDENCE
        if is_score_unassessable and len(findings) == 0:
            effective_risk_tier = "INSUFFICIENT_EVIDENCE"
            effective_risk_score = 0.0
            effective_rationale = computed_rationale
        elif not persisted_risk_tier or (persisted_risk_tier == "LOW" and computed_risk_tier in ("CRITICAL", "HIGH", "MEDIUM")):
            effective_risk_tier = computed_risk_tier
            effective_risk_score = computed_risk_score if (not risk_row or risk_row.risk_score == 0.0) else risk_row.risk_score
            effective_rationale = computed_rationale
        else:
            effective_risk_tier = persisted_risk_tier
            effective_risk_score = getattr(risk_row, "risk_score", computed_risk_score)
            effective_rationale = getattr(risk_row, "rationale", computed_rationale)

        risk_data = {
            "aggregate_risk_tier": effective_risk_tier,
            "overall_risk_tier": effective_risk_tier,
            "risk_score": effective_risk_score,
            "rationale": effective_rationale,
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
            .order_by(ThreatInstanceModel.created_at.desc())
        )
        res_threats = await self.db.execute(stmt_threats)
        raw_threat_rows = res_threats.scalars().all()
        threat_rows = []
        seen_threat_keys = set()
        for t in raw_threat_rows:
            t_key = (t.finding_id, t.threat_id)
            if t_key not in seen_threat_keys:
                seen_threat_keys.add(t_key)
                threat_rows.append(t)

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
            .order_by(FingerprintabilityAssessmentModel.created_at.desc())
        )
        res_mfi = await self.db.execute(stmt_mfi)
        mfi_row = res_mfi.scalars().first()

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

        is_synthetic = bool(
            (run.provenance_metadata and run.provenance_metadata.get("is_synthetic_demo"))
            or (run.provenance_metadata and run.provenance_metadata.get("gateway_identity") == "Perimeter-Gateway-ALPHA")
            or (capture and capture.original_filename == "ikev2_perimeter_audit.pcap")
            or (len(observations) == 0 and findings_summary["total_findings"] > 0)
        )

        if is_synthetic and len(observations) == 0:
            protocol_facts["evidence_note"] = "Demonstration fixture: Wire packet observations were not parsed from a raw PCAP stream for this reference run."

        if compliance_summary["total_evaluations"] == 0:
            compliance_summary["status_note"] = "No compliance rules evaluated for this run."

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
                "id": str(run.id),
                "status": run.status,
                "current_stage": run.current_stage,
                "parser_engine": run.parser_engine,
                "parser_version": run.parser_version,
                "schema_version": run.schema_version,
                "created_at": run.created_at.isoformat() if run.created_at else None,
                "completed_at": run.completed_at.isoformat() if run.completed_at else None,
                "is_synthetic_demo": is_synthetic,
                "pipeline_version": getattr(run, "pipeline_version", "1.0.0"),
                "policy_version": getattr(run, "policy_version", "1.0.0"),
                "is_outdated_version": (getattr(run, "pipeline_version", "1.0.0") != "2.0.0"),
                "is_archived": bool(getattr(run, "is_archived", False)),
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
