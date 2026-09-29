"""Deterministic Threat Matrix Mapper.

Maps active SecurityFindings to concrete ThreatInstances using the static,
pre-authored ThreatCatalog. Prohibits any generative hallucination of threats.
Binds canonical Threat Catalog content hash and verified MITRE ATT&CK metadata.
"""

from __future__ import annotations

from app.security.findings.models import SecurityFinding
from app.security.risk.models import Impact, RiskTier
from app.security.threats.catalog import (
    compute_catalog_hash,
    find_threat_for_root_cause,
    get_threat_by_id,
)
from app.security.threats.models import ThreatInstance


class ThreatMatrixEngine:
    """Deterministic mapper converting findings into operational ThreatInstances."""

    def __init__(self) -> None:
        self.catalog_hash = compute_catalog_hash()

    def map_findings(
        self,
        analysis_id: str,
        findings: list[SecurityFinding],
    ) -> list[ThreatInstance]:
        """Convenience signature for orchestration services."""
        return self.map_threats(findings)

    def map_threats(self, findings: list[SecurityFinding]) -> list[ThreatInstance]:
        """Convert findings into concrete threat instances."""
        threat_instances: list[ThreatInstance] = []

        for finding in findings:
            entry = None
            if finding.threat_mapping_id:
                entry = get_threat_by_id(finding.threat_mapping_id)
            if entry is None and finding.root_cause_key:
                entry = find_threat_for_root_cause(finding.root_cause_key)

            if entry is None:
                # Finding is legitimate but has no catalog mapping -> remains unmapped
                continue

            # Sweet32 (CVE-2016-2183) strictly applies only to 64-bit block ciphers (e.g. 3DES, Blowfish).
            # Disallow mapping to 128-bit block ciphers (such as AES-CBC or AES-GCM).
            if entry.threat_id == "THR-002":
                obs_str = str(getattr(finding, "observed_value", "")).lower()
                desc_str = (finding.technical_description or "").lower()
                title_str = (finding.title or "").lower()
                is_64bit = any(w in obs_str or w in desc_str or w in title_str for w in ["3des", "des", "blowfish", "64-bit"])
                if not is_64bit:
                    continue

            # Determine realized risk tier for this threat instance based on finding severity
            if finding.severity.value in ("CRITICAL",):
                realized_tier = RiskTier.CRITICAL
                realized_impact = Impact.HIGH
            elif finding.severity.value in ("HIGH",):
                realized_tier = RiskTier.HIGH
                realized_impact = Impact.HIGH
            elif finding.severity.value in ("MEDIUM",):
                realized_tier = RiskTier.MEDIUM
                realized_impact = Impact.MEDIUM
            else:
                realized_tier = RiskTier.LOW
                realized_impact = Impact.LOW

            instance = ThreatInstance(
                threat_id=entry.threat_id,
                threat_version=entry.version,
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                threat_name=entry.name,
                affected_entity_id=finding.affected_entity_id,
                preconditions=entry.preconditions,
                exploit_vector=entry.attack_vector,
                cia_impact=entry.cia_impact,
                likelihood=entry.default_likelihood,
                impact=realized_impact,
                risk_tier=realized_tier,
                evidence_state=finding.evidence_state,
                authoritative_reference=entry.authoritative_reference,
                mitre_attack_id=entry.mitre_attack_id,
                mitre_attack_name=entry.mitre_attack.technique_name if entry.mitre_attack else None,
                mitre_attack_url=entry.mitre_attack.source_url if entry.mitre_attack else None,
                mitre_attack_rationale=entry.mitre_attack.rationale if entry.mitre_attack else None,
                catalog_hash=self.catalog_hash,
            )
            threat_instances.append(instance)

        return threat_instances
