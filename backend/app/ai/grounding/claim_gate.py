"""Machine-Checkable Claim Grounding Gate for Grounded AI Analyst.

Audits generated claims against FactLockContext to catch numerical contradictions,
epistemic state mutations (e.g. UNKNOWN -> disabled, PROJECTED -> verified),
and prohibited CVE hallucinations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.ai.context.fact_lock import FactLockContext


@dataclass(frozen=True)
class ClaimValidationResult:
    """Outcome of claim-level fact-lock auditing."""

    is_valid: bool
    verified_claims: tuple[dict[str, Any], ...]
    contradicted_claims: tuple[dict[str, Any], ...]
    hallucinated_claims: tuple[dict[str, Any], ...]
    error_summary: str | None = None


class ClaimGroundingGate:
    """Deterministic fact auditor comparing generated text to FactLockContext."""

    CVE_REGEX = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
    SCORE_REGEX = re.compile(r"\b(?:security\s+score|posture\s+score|score\s+(?:is|of|was))\s*[:=]?\s*(\d{1,3}(?:\.\d+)?)\b", re.IGNORECASE)
    IKE_VER_REGEX = re.compile(r"\b(IKEv1|IKEv2)\b", re.IGNORECASE)

    @classmethod
    def validate(
        cls,
        claims: list[dict[str, Any]] | None,
        answer_text: str,
        fact_lock: FactLockContext,
    ) -> ClaimValidationResult:
        verified: list[dict[str, Any]] = []
        contradicted: list[dict[str, Any]] = []
        hallucinated: list[dict[str, Any]] = []

        # 1. Prohibited CVE Check: No CVEs unless explicitly in FactLock or Standards
        cve_matches = cls.CVE_REGEX.findall(answer_text)
        if cve_matches:
            # Check if any fact or finding mentions this CVE
            all_text_parts = []
            for item in fact_lock.items:
                all_text_parts.append(str(item.name))
                all_text_parts.append(str(item.source_id))
                all_text_parts.append(str(item.value))
            all_text = " ".join(all_text_parts).upper().replace("_", "-")
            for cve in cve_matches:
                normalized_cve = cve.upper().replace("_", "-")
                if normalized_cve not in all_text:
                    hallucinated.append({
                        "claim_type": "CVE_HALLUCINATION",
                        "text": f"Invented ungrounded vulnerability: {cve}",
                        "source": "model_memory",
                    })

        # 2. Numerical Score Verification
        score_items = fact_lock.get_items_by_type("SECURITY_SCORE")
        if score_items:
            expected_score = float(score_items[0].value.get("overall_score", 0.0))
            for score_match in cls.SCORE_REGEX.finditer(answer_text):
                claimed_score = float(score_match.group(1))
                if abs(claimed_score - expected_score) > 1.0:
                    contradicted.append({
                        "claim_type": "SCORE_CONTRADICTION",
                        "text": f"Claimed score {claimed_score} contradicts authoritative score {expected_score}",
                        "expected": expected_score,
                        "claimed": claimed_score,
                    })

        # 3. Protocol Version Verification
        ike_items = [it for it in fact_lock.items if it.name == "ike_version"]
        if ike_items:
            expected_ike = str(ike_items[0].value).strip().upper()  # e.g. "IKEv2"
            for ike_match in cls.IKE_VER_REGEX.finditer(answer_text):
                claimed_ike = ike_match.group(1).upper()
                if claimed_ike != expected_ike and "instead of" not in answer_text.lower() and "migrat" not in answer_text.lower():
                    # Check if model mistakenly asserted the wrong version as current
                    if f"running {claimed_ike.lower()}" in answer_text.lower() or f"using {claimed_ike.lower()}" in answer_text.lower():
                        contradicted.append({
                            "claim_type": "PROTOCOL_CONTRADICTION",
                            "text": f"Claimed protocol {claimed_ike} contradicts observed {expected_ike}",
                            "expected": expected_ike,
                            "claimed": claimed_ike,
                        })

        # 4. Epistemic State Enforcement on Explicit Claims
        declared_claims = claims or []
        for cl in declared_claims:
            claim_text = cl.get("text", "")
            claim_state = cl.get("epistemic_state", "UNKNOWN")
            cids = cl.get("citation_ids", [])

            # Verify cited source exists
            matching_items = [fact_lock.get_item(cid) for cid in cids if fact_lock.get_item(cid) is not None]

            if matching_items:
                # Check if epistemic state was illegitimately elevated
                for item in matching_items:
                    if item.epistemic_state == "UNKNOWN" and claim_state == "VERIFIED":
                        contradicted.append({
                            "claim_type": "EPISTEMIC_VIOLATION",
                            "text": f"Illegitimately elevated UNKNOWN fact '{item.name}' to VERIFIED",
                            "source_id": item.source_id,
                        })
                    elif item.epistemic_state == "PROJECTED" and claim_state == "VERIFIED":
                        contradicted.append({
                            "claim_type": "EPISTEMIC_VIOLATION",
                            "text": f"Illegitimately elevated PROJECTED Twin value '{item.name}' to VERIFIED",
                            "source_id": item.source_id,
                        })
                    else:
                        verified.append(cl)
            else:
                # If claim has standard citations or no fact-lock items
                verified.append(cl)

        is_valid = len(contradicted) == 0 and len(hallucinated) == 0

        err_summary = None
        if not is_valid:
            errors = []
            if contradicted:
                errors.append(f"{len(contradicted)} fact contradiction(s)")
            if hallucinated:
                errors.append(f"{len(hallucinated)} hallucinated identifier(s)")
            err_summary = f"Claim grounding gate failed: {', '.join(errors)}"

        return ClaimValidationResult(
            is_valid=is_valid,
            verified_claims=tuple(verified),
            contradicted_claims=tuple(contradicted),
            hallucinated_claims=tuple(hallucinated),
            error_summary=err_summary,
        )
