"""Security Assessment Orchestration Service.

Coordinates Stage 8 analysis pipeline:
Reconstructed Facts -> Policy Evaluation -> Findings & Gaps -> Scoring ->
Risk Assessment -> Threat Matrix -> Metadata Fingerprintability ->
Forensic Evidence Graph -> Cryptographic Manifest.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.security.evidence.builder import EvidenceGraphBuilder
from app.security.evidence.models import EvidenceGraph
from app.security.facts.models import SecurityFact
from app.security.facts.normalizer import SecurityFactNormalizer
from app.security.findings.generator import FindingGenerator
from app.security.findings.models import EvidenceGap, SecurityFinding
from app.security.fingerprintability.engine import MetadataFingerprintabilityEngine
from app.security.fingerprintability.models import MetadataFingerprintabilityAssessment
from app.security.manifest import AssessmentManifest
from app.security.policy.evaluator import EvaluationRecord, PolicyEvaluator
from app.security.policy.registry import PolicyRegistry
from app.security.policy.schema import PolicyProfile
from app.security.risk.engine import DeterministicRiskEngine
from app.security.risk.models import RiskAssessment
from app.security.scoring.engine import SecurityScoringEngine
from app.security.scoring.models import ScoreAssessment
from app.security.threats.mapper import ThreatMatrixEngine
from app.security.threats.models import ThreatInstance

logger = logging.getLogger(__name__)


@dataclass
class SecurityAssessmentResult:
    """Consolidated immutable result of a Stage 8 security assessment."""

    analysis_id: str
    capture_sha256: str
    manifest: AssessmentManifest
    eval_records: list[EvaluationRecord]
    findings: list[SecurityFinding]
    evidence_gaps: list[EvidenceGap]
    score_assessment: ScoreAssessment
    risk_assessment: RiskAssessment
    threat_instances: list[ThreatInstance]
    fingerprintability: MetadataFingerprintabilityAssessment
    evidence_graph: EvidenceGraph
    security_facts: list[SecurityFact]


class SecurityAssessmentService:
    """Orchestration service for the complete deterministic security engine."""

    def __init__(self, rules_dir: Path | str | None = None) -> None:
        if rules_dir:
            self.rules_dir = Path(rules_dir)
        else:
            # Locate canonical policies/rules in repo root or fallback
            base_path = Path(__file__).resolve().parent.parent.parent.parent
            self.rules_dir = base_path / "policies" / "rules"

        self.policy_registry = PolicyRegistry(rules_dir=self.rules_dir)
        self.normalizer = SecurityFactNormalizer()
        self.scoring_engine = SecurityScoringEngine()
        self.risk_engine = DeterministicRiskEngine()
        self.threat_engine = ThreatMatrixEngine()
        self.mfi_engine = MetadataFingerprintabilityEngine()
        self.graph_builder = EvidenceGraphBuilder()

        # Build and register standard profile bundles if rules directory exists
        if self.rules_dir.exists():
            for prof in PolicyProfile:
                try:
                    b = self.policy_registry.build_bundle(prof)
                    self.policy_registry.register_bundle(b)
                except Exception as e:
                    logger.debug("Profile bundle %s build skipped: %s", prof, e)
            logger.info("Initialized PolicyRegistry bundles from %s.", self.rules_dir)

    def run_assessment(
        self,
        analysis_id: str,
        capture_sha256: str,
        sessions: list[Any],
        child_sas: list[Any],
        flows: list[Any],
        flows_features: list[dict[str, Any]] | None = None,
        ml_classifications: list[dict[str, Any]] | None = None,
        profile_id: str = "profile_nist_sp800_77",
        model_bundle_id: str | None = None,
        parent_analysis_id: str | None = None,
        replay_mode: str | None = None,
        scenario_metadata: dict[str, Any] | None = None,
        raw_observations: list[Any] | None = None,
        capture_filename: str | None = None,
    ) -> SecurityAssessmentResult:
        """Execute end-to-end deterministic security assessment."""
        logger.info("Starting security assessment for analysis %s on profile %s", analysis_id, profile_id)

        # 1. Normalize Reconstructed Facts
        security_facts = self.normalizer.normalize_reconstruction(
            analysis_id=analysis_id,
            capture_sha256=capture_sha256,
            sessions=sessions,
            child_sas=child_sas,
            flows=flows,
            raw_observations=raw_observations,
            capture_filename=capture_filename,
        )

        # 2. Retrieve Active Policy Bundle
        bundle = self.policy_registry.get_active_bundle(profile_id)
        if not bundle:
            # Fallback to any registered bundle if available
            registered = self.policy_registry.list_bundles()
            if registered:
                bundle = self.policy_registry.get_bundle(registered[0])
            if not bundle:
                raise RuntimeError(
                    f"POLICY_BUNDLE_UNAVAILABLE: No active policy bundle found for profile '{profile_id}'."
                )

        # 3. Deterministic Policy Evaluation
        evaluator = PolicyEvaluator(bundle)
        eval_records = evaluator.evaluate_all(analysis_id=analysis_id, facts=security_facts)

        # 4. Generate Findings and Evidence Gaps
        finding_generator = FindingGenerator(bundle)
        findings = finding_generator.generate_findings(
            analysis_id=analysis_id,
            records=eval_records,
            facts=security_facts,
        )
        evidence_gaps = finding_generator.generate_evidence_gaps(
            analysis_id=analysis_id,
            records=eval_records,
        )

        # 5. Security Posture Scoring (with root-cause deduplication)
        score_assessment = self.scoring_engine.calculate_score(
            analysis_id=analysis_id,
            findings=findings,
            eval_records=eval_records,
        )

        # 6. Deterministic Risk Assessment
        risk_assessment = self.risk_engine.assess_risks(
            analysis_id=analysis_id,
            findings=findings,
            evidence_coverage=score_assessment.evidence_coverage.coverage_percentage,
            evidence_gaps_count=len(evidence_gaps),
        )

        # 7. Threat Matrix Mapping
        threat_instances = self.threat_engine.map_findings(
            analysis_id=analysis_id,
            findings=findings,
        )

        # 8. Metadata Fingerprintability (Side-Channel Distinguishability)
        feat_list = flows_features or []
        if not feat_list and flows:
            # Generate minimal flow feature records from reconstructed flows
            for fl in flows:
                f_dict = {
                    "flow_id": str(getattr(fl, "id", "")),
                    "total_packets": getattr(fl, "packet_count", 1),
                    "duration_ms": getattr(fl, "duration_seconds", 0.0) * 1000.0,
                    "fwd_pkt_ratio": (
                        getattr(fl, "forward_packets", 0) / max(1, getattr(fl, "packet_count", 1))
                    ),
                    "pkt_len_mean": (
                        getattr(fl, "byte_count", 0) / max(1, getattr(fl, "packet_count", 1))
                    ),
                    "pkt_len_std": 0.0,
                    "iat_mean": (
                        (getattr(fl, "duration_seconds", 0.0) / max(1, getattr(fl, "packet_count", 1) - 1))
                        if getattr(fl, "packet_count", 1) > 1
                        else 0.0
                    ),
                    "iat_std": 0.0,
                }
                feat_list.append(f_dict)

        fingerprintability = self.mfi_engine.assess_analysis(
            analysis_id=analysis_id,
            flows_features=feat_list,
            ml_predictions=ml_classifications,
            model_bundle_id=model_bundle_id,
        )

        # 9. Forensic Evidence & Provenance Graph
        evidence_graph = self.graph_builder.build_graph(
            analysis_id=analysis_id,
            capture_sha256=capture_sha256,
            security_facts=security_facts,
            eval_records=eval_records,
            findings=findings,
            evidence_gaps=evidence_gaps,
            threat_instances=threat_instances,
            risk_assessment=risk_assessment,
            score_assessment=score_assessment,
            fingerprintability=fingerprintability,
            parent_analysis_id=parent_analysis_id,
            scenario_metadata=scenario_metadata,
        )

        # 10. Cryptographic Manifest
        finding_hashes = [f.record_hash for f in findings]
        manifest = AssessmentManifest.create(
            analysis_id=analysis_id,
            capture_sha256=capture_sha256,
            policy_bundle_id=bundle.bundle_id,
            policy_bundle_version=bundle.bundle_version,
            policy_bundle_hash=bundle.bundle_hash,
            score_policy_hash=score_assessment.score_policy_hash,
            risk_policy_hash=risk_assessment.risk_policy_hash,
            threat_catalog_hash=self.threat_engine.catalog_hash,
            ml_bundle_hash=model_bundle_id,
            finding_hashes=finding_hashes,
            score_value=score_assessment.overall_score,
            coverage_percentage=score_assessment.evidence_coverage.coverage_percentage,
            fingerprintability_hash=fingerprintability.methodology_hash,
            parent_analysis_id=parent_analysis_id,
            replay_mode=replay_mode,
        )

        logger.info(
            "Assessment complete for %s. Score: %.1f, Coverage: %.1f%%, Findings: %d, Manifest SHA: %s",
            analysis_id,
            score_assessment.overall_score,
            score_assessment.evidence_coverage.coverage_percentage,
            len(findings),
            manifest.manifest_sha256[:8],
        )

        return SecurityAssessmentResult(
            analysis_id=analysis_id,
            capture_sha256=capture_sha256,
            manifest=manifest,
            eval_records=eval_records,
            findings=findings,
            evidence_gaps=evidence_gaps,
            score_assessment=score_assessment,
            risk_assessment=risk_assessment,
            threat_instances=threat_instances,
            fingerprintability=fingerprintability,
            evidence_graph=evidence_graph,
            security_facts=security_facts,
        )
