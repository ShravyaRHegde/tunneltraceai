"""Policy Bundle Registry and Precedence Conflict Resolver.

Manages versioned, cryptographic policy bundles for standard compliance profiles:
- profile_ietf_baseline
- profile_nist_sp800_77
- profile_enterprise_strict
- profile_custom_org
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.security.policy.loader import SafePolicyLoader
from app.security.policy.schema import PolicyBundle, PolicyProfile, PolicyRule, RuleStatus

POLICIES_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent / "policies" / "rules"


class PolicyRegistry:
    """In-memory singleton registry of validated policy rules and bundles."""

    def __init__(self, rules_dir: Path | str | None = None) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else POLICIES_DIR
        self._all_rules: dict[str, PolicyRule] = {}
        self._bundles: dict[PolicyProfile, PolicyBundle] = {}
        self._load_all_rules()

    def _load_all_rules(self) -> None:
        """Scan rules directory and load all valid PolicyRule definitions."""
        if not self.rules_dir.is_dir():
            return
        for f in sorted(self.rules_dir.glob("*.yaml")) + sorted(self.rules_dir.glob("*.yml")):
            try:
                rule = SafePolicyLoader.load_rule_from_file(f)
                self._all_rules[rule.rule_id] = rule
            except Exception:
                # Log or raise depending on governance
                pass

    def get_rule(self, rule_id: str) -> PolicyRule | None:
        """Retrieve rule by identifier."""
        return self._all_rules.get(rule_id)

    def get_active_rules(self) -> list[PolicyRule]:
        """Return all rules currently in ACTIVE status."""
        return [r for r in self._all_rules.values() if r.status == RuleStatus.ACTIVE]

    def get_all_rules(self) -> list[PolicyRule]:
        """Return all loaded policy rules regardless of status."""
        return list(self._all_rules.values())

    def compile_bundle(
        self,
        bundle_id: str,
        profile_id: str | PolicyProfile,
        rules: list[PolicyRule],
        bundle_version: str = "1.0.0",
    ) -> PolicyBundle:
        """Compile a list of rules into an immutable hashed PolicyBundle."""
        prof = PolicyProfile(profile_id) if isinstance(profile_id, str) else profile_id
        return PolicyBundle.create(
            bundle_id=bundle_id,
            bundle_version=bundle_version,
            profile=prof,
            rules=rules,
        )

    def register_bundle(self, bundle: PolicyBundle) -> None:
        """Register a compiled bundle into the active profile cache."""
        self._bundles[bundle.profile] = bundle

    def get_active_bundle(self, profile_id: str | PolicyProfile) -> PolicyBundle | None:
        """Retrieve the active policy bundle for a profile."""
        prof = PolicyProfile(profile_id) if isinstance(profile_id, str) else profile_id
        return self.get_bundle(prof)

    def list_rules(self, profile_id: str | PolicyProfile) -> list[PolicyRule]:
        """List compiled rules for a profile."""
        bundle = self.get_active_bundle(profile_id)
        return bundle.rules if bundle else []

    def list_bundles(self) -> list[str]:
        """List registered bundle profile IDs."""
        return [p.value for p in self._bundles.keys()]

    def build_bundle(
        self,
        profile: PolicyProfile,
        custom_rules: list[PolicyRule] | None = None,
    ) -> PolicyBundle:
        """Assemble an immutable PolicyBundle for the requested profile, resolving overrides."""
        active_rules = self.get_active_rules()
        selected: dict[str, PolicyRule] = {}

        if profile == PolicyProfile.PROFILE_IETF_BASELINE:
            # IETF Baseline includes core RFC interoperability and anti-replay
            for r in active_rules:
                if r.rule_id in ["POL-RFC-7296-01", "POL-RFC-8221-01", "POL-REPLAY-001", "POL-NIST-001"]:
                    selected[r.rule_id] = r

        elif profile == PolicyProfile.PROFILE_NIST_SP800_77:
            # NIST SP 800-77 includes federal crypto strength, DH Group 14+, modern IKEv2, and PFS
            for r in active_rules:
                if r.rule_id.startswith("POL-NIST-") or r.rule_id in [
                    "POL-RFC-7296-01",
                    "POL-RFC-8221-01",
                    "POL-REPLAY-001",
                    "POL-PFS-001",
                ]:
                    selected[r.rule_id] = r

        elif profile == PolicyProfile.PROFILE_ENTERPRISE_STRICT:
            # Enterprise strict includes all NIST rules + mandatory Child SA PFS
            for r in active_rules:
                selected[r.rule_id] = r

        elif profile == PolicyProfile.PROFILE_CUSTOM_ORG:
            # Base enterprise strict + custom rules with override precedence
            for r in active_rules:
                selected[r.rule_id] = r

        # Apply custom rules with explicit precedence
        if custom_rules:
            for cr in custom_rules:
                cr.validate_field_references()
                selected[cr.rule_id] = cr

        bundle_rules = list(selected.values())
        return PolicyBundle.create(
            bundle_id=f"bundle_{profile.value}",
            bundle_version="1.0.0",
            profile=profile,
            rules=bundle_rules,
        )

    def get_bundle(self, profile: PolicyProfile) -> PolicyBundle:
        """Get or build cached bundle for a profile."""
        if profile not in self._bundles:
            self._bundles[profile] = self.build_bundle(profile)
        return self._bundles[profile]

    def list_profiles(self) -> list[dict[str, Any]]:
        """List metadata for all standard policy profiles."""
        return [
            {
                "profile_id": PolicyProfile.PROFILE_IETF_BASELINE.value,
                "title": "IETF Baseline Interoperability Profile",
                "standards": ["RFC 7296", "RFC 8221", "RFC 8247", "RFC 4303"],
                "target_environment": "Commercial standard IPsec VPN deployments",
            },
            {
                "profile_id": PolicyProfile.PROFILE_NIST_SP800_77.value,
                "title": "NIST SP 800-77 Rev. 1 Federal Security Profile",
                "standards": ["NIST SP 800-77 Rev. 1", "NIST SP 800-57 Part 1 Rev. 5"],
                "target_environment": "Government, defense, and high-assurance critical infrastructure",
            },
            {
                "profile_id": PolicyProfile.PROFILE_ENTERPRISE_STRICT.value,
                "title": "Enterprise Zero-Trust Strict Profile",
                "standards": ["NIST SP 800-77 Rev. 1", "RFC 8221", "PFS Mandatory"],
                "target_environment": "Strict corporate perimeter with mandatory PFS and AEAD",
            },
            {
                "profile_id": PolicyProfile.PROFILE_CUSTOM_ORG.value,
                "title": "Custom Organizational Security Profile",
                "standards": ["User-defined Policy-as-Code"],
                "target_environment": "Specialized lab testbed or organizational SOC rules",
            },
        ]

    @staticmethod
    def diff_bundles(bundle_a: PolicyBundle, bundle_b: PolicyBundle) -> dict[str, Any]:
        """Compute structured difference between two policy bundles for auditability."""
        rules_a = {r.rule_id: r for r in bundle_a.rules}
        rules_b = {r.rule_id: r for r in bundle_b.rules}

        added = [r.rule_id for r in rules_b.values() if r.rule_id not in rules_a]
        removed = [r.rule_id for r in rules_a.values() if r.rule_id not in rules_b]
        modified = []

        for r_id in set(rules_a.keys()).intersection(rules_b.keys()):
            ra = rules_a[r_id]
            rb = rules_b[r_id]
            if ra.rule_version != rb.rule_version or ra.severity != rb.severity or ra.assertion != rb.assertion:
                modified.append({
                    "rule_id": r_id,
                    "old_version": ra.rule_version,
                    "new_version": rb.rule_version,
                    "old_severity": ra.severity.value,
                    "new_severity": rb.severity.value,
                })

        return {
            "bundle_a_hash": bundle_a.manifest_hash,
            "bundle_b_hash": bundle_b.manifest_hash,
            "added_rules": added,
            "removed_rules": removed,
            "modified_rules": modified,
        }
