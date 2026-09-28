"""Strict strongSwan swanctl.conf and forensic facts parser for Configuration IR."""

from __future__ import annotations

import re
from typing import Any

from app.remediation.ir import (
    ChildSAConfigurationIR,
    ConfigurationIR,
    ConnectionConfigurationIR,
    CurrentConfigurationSnapshot,
    EpistemicState,
    EpistemicValue,
    SecretConfigurationIR,
    TransformIR,
)
from app.security.facts.models import EvidenceState, SecurityFact


def parse_dh_group_string(token: str) -> int | None:
    """Parse DH group token like modp2048, ecp256, curve25519, 14, 19 into integer group ID."""
    token = token.strip().lower().replace("_", "-")
    dh_map = {
        "modp768": 1,
        "modp1024": 2,
        "modp1536": 5,
        "modp2048": 14,
        "modp3072": 15,
        "modp4096": 16,
        "modp6144": 17,
        "modp8192": 18,
        "ecp256": 19,
        "ecp384": 20,
        "ecp521": 21,
        "curve25519": 31,
        "x25519": 31,
    }
    if token in dh_map:
        return dh_map[token]
    digits = re.findall(r"\d+", token)
    if digits:
        val = int(digits[0])
        if val in (1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21, 31):
            return val
        if val == 2048:
            return 14
        if val == 1024:
            return 2
        if val == 1536:
            return 5
        if val == 3072:
            return 15
        if val == 4096:
            return 16
        if val == 256 and "ecp" in token:
            return 19
        if val == 384 and "ecp" in token:
            return 20
        if val == 521 and "ecp" in token:
            return 21
    return None


def parse_single_proposal_string(prop_str: str, is_ike: bool = False) -> TransformIR:
    """Parse a single transform proposal string like 'aes256gcm16-prfsha256-ecp256' or 'aes128-sha1-modp1024'."""
    tokens = [t.strip().rstrip("!") for t in prop_str.strip().split("-") if t.strip()]
    if not tokens:
        return TransformIR(encryption="unknown")

    encryption = tokens[0]
    key_length: int | None = None
    integrity: str | None = None
    prf: str | None = None
    dh_group: int | None = None

    # Check for embedded key length in cipher (e.g. aes256 or aes256gcm16 or aes128)
    enc_digits = re.findall(r"\d+", encryption)
    if enc_digits:
        for d in (256, 192, 128):
            if str(d) in encryption:
                key_length = d
                break

    for tok in tokens[1:]:
        tok_lower = tok.lower()
        # DH group?
        dh = parse_dh_group_string(tok_lower)
        if dh is not None:
            dh_group = dh
            continue

        # PRF?
        if tok_lower.startswith("prf"):
            prf = tok_lower
            continue

        # Integrity hash?
        if any(h in tok_lower for h in ("sha", "md5", "aesxcbc")):
            integrity = tok_lower
            continue

    return TransformIR(
        encryption=encryption,
        key_length=key_length,
        integrity=integrity,
        prf=prf,
        dh_group=dh_group,
    )


def parse_proposals_list(props_line: str, is_ike: bool = False) -> tuple[TransformIR, ...]:
    """Parse comma-separated or space-separated proposals like 'aes256gcm16-ecp256,aes256-sha256-ecp256'."""
    raw_props = [p.strip() for p in re.split(r"[,;]", props_line) if p.strip()]
    parsed = []
    for rp in raw_props:
        if rp:
            parsed.append(parse_single_proposal_string(rp, is_ike=is_ike))
    return tuple(parsed)


class SwanctlParser:
    """Strict parser for strongSwan swanctl.conf files."""

    @classmethod
    def parse_text(cls, text: str) -> ConfigurationIR:
        """Parse swanctl.conf text into typed ConfigurationIR."""
        # Simple robust brace-matching parser for swanctl.conf
        lines = [line.strip() for line in text.splitlines()]
        connections: list[ConnectionConfigurationIR] = []
        secrets: list[SecretConfigurationIR] = []

        in_connections = False
        in_secrets = False

        current_conn_name: str | None = None
        conn_dict: dict[str, Any] = {}
        children_list: list[ChildSAConfigurationIR] = []

        current_child_name: str | None = None
        child_dict: dict[str, Any] = {}

        current_secret_name: str | None = None
        secret_dict: dict[str, Any] = {}

        brace_depth = 0
        block_stack: list[str] = []

        for line in lines:
            if not line or line.startswith("#"):
                continue

            # Strip comments at end of line
            if "#" in line:
                line = line.split("#")[0].strip()

            if line.endswith("{"):
                block_name = line[:-1].strip()
                block_stack.append(block_name)
                brace_depth += 1

                if block_name == "connections":
                    in_connections = True
                elif block_name == "secrets":
                    in_secrets = True
                elif in_connections and len(block_stack) == 2:
                    current_conn_name = block_name
                    conn_dict = {"name": current_conn_name}
                    children_list = []
                elif in_connections and len(block_stack) == 4 and block_stack[2] == "children":
                    current_child_name = block_name
                    child_dict = {"name": current_child_name}
                elif in_secrets and len(block_stack) == 2:
                    current_secret_name = block_name
                    secret_dict = {"secret_id": current_secret_name}
                continue

            if line == "}":
                if block_stack:
                    closing_block = block_stack.pop()
                    brace_depth -= 1

                    if closing_block == "connections":
                        in_connections = False
                    elif closing_block == "secrets":
                        in_secrets = False
                    elif in_connections and len(block_stack) == 1:
                        # Finished connection
                        ike_props = parse_proposals_list(conn_dict.get("proposals", "aes256gcm16"), is_ike=True)
                        conn_ir = ConnectionConfigurationIR(
                            name=conn_dict.get("name", "tt-conn"),
                            ike_version=int(conn_dict.get("version", 2)),
                            local_addrs=conn_dict.get("local_addrs", "%any"),
                            remote_addrs=conn_dict.get("remote_addrs", "%any"),
                            local_id=conn_dict.get("local_id", "peer-a.tunneltrace.local"),
                            remote_id=conn_dict.get("remote_id", "peer-b.tunneltrace.local"),
                            ike_proposals=ike_props,
                            encap=str(conn_dict.get("encap", "no")).lower() in ("yes", "true", "1"),
                            rekey_time=conn_dict.get("rekey_time", "14400s"),
                            children=tuple(children_list),
                        )
                        connections.append(conn_ir)
                        current_conn_name = None
                    elif in_connections and len(block_stack) == 3 and block_stack[2] == "children":
                        # Finished child
                        esp_props = parse_proposals_list(child_dict.get("esp_proposals", "aes256gcm16"), is_ike=False)
                        pfs_dh = None
                        for p in esp_props:
                            if p.dh_group is not None:
                                pfs_dh = p.dh_group
                                break
                        child_ir = ChildSAConfigurationIR(
                            name=child_dict.get("name", "child-sa"),
                            mode=child_dict.get("mode", "tunnel"),
                            esp_proposals=esp_props,
                            local_ts=child_dict.get("local_ts", "0.0.0.0/0"),
                            remote_ts=child_dict.get("remote_ts", "0.0.0.0/0"),
                            pfs_dh_group=pfs_dh,
                            start_action=child_dict.get("start_action", "start"),
                            rekey_time=child_dict.get("rekey_time", "3600s"),
                            replay_window=int(child_dict.get("replay_window", 64)),
                        )
                        children_list.append(child_ir)
                        current_child_name = None
                    elif in_secrets and len(block_stack) == 1:
                        # Finished secret - sanitize!
                        secret_ir = SecretConfigurationIR(
                            secret_id=secret_dict.get("secret_id", "ike-psk"),
                            remote_id=secret_dict.get("id", "peer-b.tunneltrace.local"),
                            is_redacted=True,
                            secret_placeholder="[REDACTED_LAB_SECRET]",
                        )
                        secrets.append(secret_ir)
                        current_secret_name = None
                continue

            # Key-value assignment line
            if "=" in line:
                k, v = [part.strip() for part in line.split("=", 1)]
                v = v.strip('"').strip("'")
                if in_connections:
                    if len(block_stack) >= 4 and block_stack[2] == "children":
                        child_dict[k] = v
                    elif len(block_stack) >= 3 and block_stack[2] == "local":
                        if k == "id":
                            conn_dict["local_id"] = v
                    elif len(block_stack) >= 3 and block_stack[2] == "remote":
                        if k == "id":
                            conn_dict["remote_id"] = v
                    else:
                        conn_dict[k] = v
                elif in_secrets:
                    secret_dict[k] = v

        return ConfigurationIR(
            connections=tuple(connections),
            secrets=tuple(secrets),
            raw_syntax_format="SWANCTL",
            metadata={"parsed_from": "swanctl_text"},
        )


class ForensicFactsSnapshotBuilder:
    """Builds an immutable CurrentConfigurationSnapshot from Stage 8 SecurityFacts."""

    @classmethod
    def build_snapshot(
        cls,
        analysis_id: str,
        capture_sha256: str,
        facts: list[SecurityFact],
        policy_profile: str = "profile_nist_sp800_77",
    ) -> CurrentConfigurationSnapshot:
        """Constructs an epistemic snapshot from Stage 8 verified and inferred facts."""
        facts_map: dict[str, SecurityFact] = {f.key: f for f in facts}

        def _get_val(*keys: str) -> EpistemicValue[Any]:
            for k in keys:
                fact = facts_map.get(k)
                if not fact:
                    continue

                state_map = {
                    EvidenceState.VERIFIED: EpistemicState.KNOWN,
                    EvidenceState.INFERRED: EpistemicState.KNOWN,
                    EvidenceState.MISCONFIGURATION_OBSERVED: EpistemicState.KNOWN,
                    EvidenceState.UNKNOWN: EpistemicState.UNKNOWN,
                }
                ep_state = state_map.get(fact.evidence_state, EpistemicState.UNKNOWN)
                if ep_state == EpistemicState.KNOWN and fact.value is not None:
                    # Also normalize string "UNKNOWN" values
                    if str(fact.value).upper() == "UNKNOWN":
                        return EpistemicValue.unknown(source=f"fact:{fact.key}:UNKNOWN_VALUE")
                    return EpistemicValue.known(fact.value, source=f"fact:{fact.key}:{fact.evidence_state.value}")
                return EpistemicValue.unknown(source=f"fact:{fact.key}:UNKNOWN")
            return EpistemicValue.unknown(source=f"NO_FACT_OBSERVED:{','.join(keys)}")

        return CurrentConfigurationSnapshot(
            analysis_id=analysis_id,
            capture_sha256=capture_sha256,
            ike_version=_get_val("ike_session.ike_version", "ike_version"),
            ike_encryption=_get_val("ike_sa.encryption_algorithm", "ike_encryption"),
            ike_key_length=_get_val("ike_sa.key_length_bits", "ike_key_length"),
            ike_integrity=_get_val("ike_sa.integrity_algorithm", "ike_integrity"),
            ike_prf=_get_val("ike_sa.prf_algorithm", "ike_prf"),
            ike_dh_group=_get_val("ike_sa.diffie_hellman_group", "ike_dh_group"),
            child_mode=_get_val("child_sa.mode", "child_mode"),
            child_encryption=_get_val("child_sa.encryption_algorithm", "child_encryption"),
            child_integrity=_get_val("child_sa.integrity_algorithm", "child_integrity"),
            child_pfs_status=_get_val("child_sa.pfs_status", "child_pfs_status"),
            child_pfs_dh_group=_get_val("child_sa.pfs_dh_group", "child_pfs_dh_group"),
            child_replay_window=_get_val("child_sa.replay_window_size", "child_replay_window"),
            is_nat_detected=_get_val("ike_session.is_nat_detected", "is_nat_detected"),
            policy_profile=policy_profile,
            raw_observed_facts={f.key: {"value": f.value, "evidence_state": f.evidence_state.value} for f in facts},
        )
