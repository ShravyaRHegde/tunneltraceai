"""Fact Lock implementation for Grounded AI Analyst.

Extracts immutable, structured, deterministic facts from AnalysisRun and all related
analytical entities (protocol observations, SAs, compliance, scores, findings,
threats, ML predictions, Twin projections, and closed-loop verification claims).
Produces an auditable FactLockContext with a deterministic SHA-256 hash.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.capture import AnalysisRun, Capture
from app.db.models.ml import FlowClassification
from app.db.models.reconstruction import (
    ChildSecurityAssociation,
    ESPFlow,
    IKESecurityAssociation,
    IKESession,
)
from app.db.models.remediation import (
    ConfigurationTwinModel,
    RemediationVerificationClaimModel,
    RemediationVerificationModel,
)
from app.db.models.security import (
    ComplianceEvaluationModel,
    FingerprintabilityAssessmentModel,
    ScoreAssessmentModel,
    SecurityFindingModel,
    ThreatInstanceModel,
)


@dataclass(frozen=True)
class FactLockItem:
    """An individual verified or inferred factual claim anchored to a source entity."""

    source_id: str
    fact_type: str  # PROTOCOL_FACT, POLICY_EVALUATION, SECURITY_FINDING, SECURITY_SCORE, ML_PREDICTION, THREAT_MAPPING, TWIN_PROJECTION, REMEDIATION_VERIFICATION
    name: str
    value: Any
    epistemic_state: str  # VERIFIED, INFERRED, UNKNOWN, PROJECTED, VERIFIED_POST_REMEDIATION
    entity: str
    provenance: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "fact_type": self.fact_type,
            "name": self.name,
            "value": self.value,
            "epistemic_state": self.epistemic_state,
            "entity": self.entity,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class FactLockContext:
    """Immutable collection of facts authorized for the current analysis scope."""

    analysis_id: str
    capture_name: str
    capture_sha256: str
    items: tuple[FactLockItem, ...]
    fact_lock_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "capture_name": self.capture_name,
            "capture_sha256": self.capture_sha256,
            "fact_lock_hash": self.fact_lock_hash,
            "items_count": len(self.items),
            "items": [item.to_dict() for item in self.items],
        }

    def to_xml(self) -> str:
        """Format facts into strict, delimited XML for system prompt inclusion."""
        lines = [
            f'<fact_lock analysis_id="{self.analysis_id}" hash="{self.fact_lock_hash}">',
            f'  <capture name="{self.capture_name}" sha256="{self.capture_sha256}" />',
            "  <verified_facts>",
        ]
        for item in self.items:
            val_str = json.dumps(item.value) if isinstance(item.value, (dict, list)) else str(item.value)
            lines.append(
                f'    <fact id="{item.source_id}" type="{item.fact_type}" state="{item.epistemic_state}" '
                f'entity="{item.entity}" prov="{item.provenance}">'
                f"{item.name} = {val_str}</fact>"
            )
        lines.append("  </verified_facts>")
        lines.append("</fact_lock>")
        return "\n".join(lines)

    def get_item(self, source_id: str) -> FactLockItem | None:
        for item in self.items:
            if item.source_id == source_id:
                return item
        return None

    def get_items_by_type(self, fact_type: str) -> list[FactLockItem]:
        return [item for item in self.items if item.fact_type == fact_type]


class FactLockBuilder:
    """Builds FactLockContext by querying authoritative relational models."""

    @classmethod
    async def build_from_analysis(
        cls, session: AsyncSession, analysis_id: uuid.UUID | str
    ) -> FactLockContext:
        aid = uuid.UUID(str(analysis_id))

        # 1. Fetch AnalysisRun & Capture
        run_res = await session.execute(
            select(AnalysisRun).where(AnalysisRun.id == aid)
        )
        run = run_res.scalar_one_or_none()
        if not run:
            raise ValueError(f"AnalysisRun not found: {analysis_id}")

        cap_res = await session.execute(
            select(Capture).where(Capture.id == run.capture_id)
        )
        capture = cap_res.scalar_one_or_none()
        cap_name = capture.original_filename if capture and capture.original_filename else "unknown.pcap"
        cap_hash = capture.sha256_hash if capture and capture.sha256_hash else "0" * 64

        items: list[FactLockItem] = []

        # Scope fact
        items.append(
            FactLockItem(
                source_id=f"analysis:{aid}",
                fact_type="ANALYSIS_METADATA",
                name="analysis_status",
                value={
                    "status": run.status,
                    "current_stage": run.current_stage,
                    "packets": capture.packet_count if capture else 0,
                    "duration_sec": capture.duration_sec if capture else 0.0,
                },
                epistemic_state="VERIFIED",
                entity="AnalysisRun",
                provenance="Stage 3 Ingestion Engine",
            )
        )

        # 2. IKE Sessions & Security Associations (Stage 4)
        ike_res = await session.execute(
            select(IKESession).where(IKESession.analysis_id == aid)
        )
        ike_sessions = ike_res.scalars().all()
        for s in ike_sessions:
            items.append(
                FactLockItem(
                    source_id=f"ike_session:{s.id}",
                    fact_type="PROTOCOL_FACT",
                    name="ike_version",
                    value=s.ike_version,
                    epistemic_state="VERIFIED",
                    entity="IKESession",
                    provenance="Stage 4 IKE Correlator",
                )
            )

        session_ids = [s.id for s in ike_sessions]
        if session_ids:
            sa_res = await session.execute(
                select(IKESecurityAssociation).where(
                    IKESecurityAssociation.session_id.in_(session_ids)
                )
            )
            for sa in sa_res.scalars().all():
                items.append(
                    FactLockItem(
                        source_id=f"sa:ike:{sa.id}",
                        fact_type="PROTOCOL_FACT",
                        name="IKE_SA_algorithms",
                        value={
                            "cipher": sa.encryption_algorithm,
                            "integrity": sa.integrity_algorithm,
                            "dh_group": sa.dh_group,
                            "prf": sa.prf_algorithm,
                        },
                        epistemic_state="VERIFIED",
                        entity="IKESecurityAssociation",
                        provenance="Stage 4 SA Builder",
                    )
                )

        child_res = await session.execute(
            select(ChildSecurityAssociation).where(
                ChildSecurityAssociation.analysis_id == aid
            )
        )
        for csa in child_res.scalars().all():
            pfs_state = "VERIFIED" if csa.pfs_dh_group else "UNKNOWN"
            items.append(
                FactLockItem(
                    source_id=f"sa:child:{csa.id}",
                    fact_type="PROTOCOL_FACT",
                    name="Child_SA_parameters",
                    value={
                        "cipher": csa.encryption_algorithm,
                        "integrity": csa.integrity_algorithm,
                        "mode": csa.mode,
                        "pfs_dh_group": csa.pfs_dh_group,
                        "inbound_spi": csa.inbound_spi,
                        "outbound_spi": csa.outbound_spi,
                        "protocol": csa.protocol,
                    },
                    epistemic_state="VERIFIED" if csa.mode != "UNKNOWN" else "INFERRED",
                    entity="ChildSecurityAssociation",
                    provenance="Stage 4 SA Builder",
                )
            )

        # 3. ESP Flows & ML (Stage 6/7)
        flow_res = await session.execute(
            select(ESPFlow).where(ESPFlow.analysis_id == aid)
        )
        flows = flow_res.scalars().all()
        fc_res = await session.execute(
            select(FlowClassification)
            .join(ESPFlow, FlowClassification.flow_id == ESPFlow.id)
            .where(ESPFlow.analysis_id == aid)
        )
        classifications_by_flow = {fc.flow_id: fc for fc in fc_res.scalars().all()}

        for flow in flows:
            fc = classifications_by_flow.get(flow.id)
            pred = getattr(flow, "traffic_prediction", None) or {}
            top_class = fc.final_class if fc else pred.get("predicted_class", "UNKNOWN")
            conf = fc.calibrated_confidence if fc else pred.get("calibrated_confidence", pred.get("confidence", 0.0))
            is_ood = (fc.ood_status in ("OOD_REJECTED", "UNKNOWN_UNSEEN")) if fc else pred.get("is_ood", False)
            entropy = getattr(fc, "entropy", 0.0) if fc else pred.get("entropy", 0.0)
            items.append(
                FactLockItem(
                    source_id=f"flow:{flow.id}",
                    fact_type="ML_PREDICTION",
                    name=f"flow_{flow.spi}_classification",
                    value={
                        "predicted_class": top_class,
                        "confidence": conf,
                        "entropy": entropy,
                        "is_ood": is_ood,
                        "packet_count": flow.packet_count,
                        "byte_count": flow.byte_count,
                    },
                    epistemic_state="INFERRED",
                    entity="ESPFlow",
                    provenance="Stage 7 ML Classifier (TorchScript CNN + XGBoost)",
                )
            )

        # 4. Security Posture Score (Stage 8)
        score_res = await session.execute(
            select(ScoreAssessmentModel)
            .where(ScoreAssessmentModel.analysis_id == aid)
            .order_by(ScoreAssessmentModel.created_at.desc())
        )
        score_obj = score_res.scalars().first()
        if score_obj:
            items.append(
                FactLockItem(
                    source_id=f"score:assessment:{score_obj.id}",
                    fact_type="SECURITY_SCORE",
                    name="security_posture_score",
                    value={
                        "overall_score": score_obj.overall_score,
                        "raw_score": score_obj.raw_score,
                        "coverage_percentage": score_obj.coverage_percentage,
                        "status": score_obj.status,
                        "deductions": score_obj.deduction_audit or {},
                    },
                    epistemic_state="VERIFIED",
                    entity="ScoreAssessment",
                    provenance="Stage 8 Scoring Engine",
                )
            )

        # 5. Compliance Evaluations & Security Findings (Stage 8)
        comp_res = await session.execute(
            select(ComplianceEvaluationModel).where(
                ComplianceEvaluationModel.analysis_id == aid
            )
        )
        for comp in comp_res.scalars().all():
            items.append(
                FactLockItem(
                    source_id=f"rule:{comp.rule_id}@{comp.rule_version}",
                    fact_type="POLICY_EVALUATION",
                    name=comp.rule_id,
                    value={
                        "compliance_state": comp.compliance_state,
                        "evidence_state": comp.evidence_state,
                        "rationale": comp.rationale,
                    },
                    epistemic_state=comp.evidence_state,
                    entity="ComplianceEvaluation",
                    provenance="Stage 8 Policy Engine (Kleene 3-valued Logic)",
                )
            )

        finding_res = await session.execute(
            select(SecurityFindingModel).where(SecurityFindingModel.analysis_id == aid)
        )
        for f in finding_res.scalars().all():
            items.append(
                FactLockItem(
                    source_id=f"finding:{f.finding_id}",
                    fact_type="SECURITY_FINDING",
                    name=f.title,
                    value={
                        "finding_id": f.finding_id,
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "category": f.category,
                        "technical_description": f.technical_description,
                        "observed": f.observed_value,
                        "expected": f.expected_requirement,
                        "remediation_guidance": f.remediation_guidance,
                    },
                    epistemic_state=f.evidence_state,
                    entity="SecurityFinding",
                    provenance="Stage 8 Security Finding Catalog",
                )
            )

        # 6. Threat Instances (Stage 8)
        threat_res = await session.execute(
            select(ThreatInstanceModel).where(ThreatInstanceModel.analysis_id == aid)
        )
        for th in threat_res.scalars().all():
            items.append(
                FactLockItem(
                    source_id=f"threat:{th.threat_id}",
                    fact_type="THREAT_MAPPING",
                    name=th.threat_name,
                    value={
                        "threat_id": th.threat_id,
                        "finding_id": th.finding_id,
                        "likelihood": th.likelihood,
                        "impact": th.impact,
                        "risk_tier": th.risk_tier,
                    },
                    epistemic_state="VERIFIED",
                    entity="ThreatInstance",
                    provenance="Stage 8 Threat Matrix",
                )
            )

        # 7. Metadata Fingerprintability (Stage 8)
        fp_res = await session.execute(
            select(FingerprintabilityAssessmentModel)
            .where(FingerprintabilityAssessmentModel.analysis_id == aid)
            .order_by(FingerprintabilityAssessmentModel.created_at.desc())
        )
        fp_obj = fp_res.scalars().first()
        if fp_obj:
            items.append(
                FactLockItem(
                    source_id=f"fingerprintability:{fp_obj.id}",
                    fact_type="FINGERPRINTABILITY",
                    name="metadata_fingerprintability",
                    value={
                        "overall_distinguishability": getattr(fp_obj, "overall_index", None),
                        "overall_index": getattr(fp_obj, "overall_index", None),
                        "class_fingerprintability": getattr(fp_obj, "components", {}),
                        "components": getattr(fp_obj, "components", {}),
                        "status": getattr(fp_obj, "status", "EVALUATED"),
                    },
                    epistemic_state="INFERRED",
                    entity="FingerprintabilityAssessment",
                    provenance="Stage 8 Fingerprintability Engine",
                )
            )

        # 8. Stage 10 Configuration Security Twin (Projected)
        twin_res = await session.execute(
            select(ConfigurationTwinModel)
            .where(ConfigurationTwinModel.analysis_id == aid)
            .order_by(ConfigurationTwinModel.created_at.desc())
        )
        twin_obj = twin_res.scalars().first()
        if twin_obj:
            items.append(
                FactLockItem(
                    source_id=f"twin:{twin_obj.id}",
                    fact_type="TWIN_PROJECTION",
                    name="configuration_security_twin_projection",
                    value={
                        "proposal_hash": twin_obj.proposal_hash,
                        "projected_score": float(twin_obj.projected_score) if twin_obj.projected_score is not None else None,
                        "projected_score_delta": float(twin_obj.projected_score_delta) if twin_obj.projected_score_delta is not None else None,
                        "status": "PROJECTED",
                    },
                    epistemic_state="PROJECTED",
                    entity="ConfigurationTwin",
                    provenance="Stage 10 Configuration Security Twin (Counterfactual Projection)",
                )
            )

        # 9. Stage 10 Closed-Loop Remediation Verification
        verif_res = await session.execute(
            select(RemediationVerificationModel)
            .where(RemediationVerificationModel.baseline_analysis_id == aid)
            .order_by(RemediationVerificationModel.verified_at.desc())
        )
        verif_obj = verif_res.scalars().first()
        if verif_obj:
            items.append(
                FactLockItem(
                    source_id=f"verification:{verif_obj.id}",
                    fact_type="REMEDIATION_VERIFICATION",
                    name="closed_loop_verification_outcome",
                    value={
                        "verification_result": verif_obj.verification_result,
                        "security_result": verif_obj.security_result,
                        "operational_result": verif_obj.operational_result,
                        "baseline_score": float(verif_obj.baseline_score) if verif_obj.baseline_score is not None else None,
                        "verified_score": float(verif_obj.verified_score) if verif_obj.verified_score is not None else None,
                        "post_analysis_id": str(verif_obj.post_analysis_id) if verif_obj.post_analysis_id else None,
                    },
                    epistemic_state=verif_obj.verification_result,
                    entity="RemediationVerification",
                    provenance="Stage 10 Closed-Loop Dual-Axis Comparator",
                )
            )

            # Verification Claims
            claim_res = await session.execute(
                select(RemediationVerificationClaimModel).where(
                    RemediationVerificationClaimModel.verification_id == verif_obj.id
                )
            )
            for cl in claim_res.scalars().all():
                items.append(
                    FactLockItem(
                        source_id=f"claim:{cl.id}",
                        fact_type="VERIFICATION_CLAIM",
                        name=f"Claim_{cl.rule_id}",
                        value={
                            "rule_id": cl.rule_id,
                            "claim_result": cl.claim_result,
                            "reason_code": cl.reason_code,
                        },
                        epistemic_state="VERIFIED_POST_REMEDIATION" if cl.claim_result == "VERIFIED_RESOLVED" else cl.claim_result,
                        entity="RemediationVerificationClaim",
                        provenance="Stage 10 Verification Claim Ledger",
                    )
                )

        # Compute hash over sorted items
        canonical_str = json.dumps(
            [item.to_dict() for item in sorted(items, key=lambda x: x.source_id)],
            sort_keys=True,
        )
        fact_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        return FactLockContext(
            analysis_id=str(aid),
            capture_name=cap_name,
            capture_sha256=cap_hash,
            items=tuple(items),
            fact_lock_hash=fact_hash,
        )
