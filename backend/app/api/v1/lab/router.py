"""REST API endpoints for Lab Testbed scenarios, execution provenance, and verification states."""

from __future__ import annotations

import json
import logging
import os
import platform
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from lab.scenarios.loader import ScenarioLoader

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/lab", tags=["lab"])

PROFILES_DIR = Path("lab/scenarios/profiles")
RUNS_DIR = Path("storage/lab/runs")


class ScenarioSummaryDTO(BaseModel):
    scenario_id: str
    scenario_version: str
    title: str
    description: str
    topology: str
    ip_version: str
    ike_version: str
    crypto_profile: str
    pfs: str
    encapsulation: str
    expected_outcome: str
    is_negative_test: bool
    category: str
    is_verified: bool
    status: str = Field(..., description="'VERIFIED' or 'EXPERIMENTAL_UNVERIFIED'")
    total_runs: int = 0
    validated_runs: int = 0
    latest_run_id: Optional[str] = None
    latest_run_status: Optional[str] = None
    latest_run_summary: Optional[str] = None
    latest_run_timestamp: Optional[str] = None
    sha256_hash: Optional[str] = None


class LabStatsDTO(BaseModel):
    total_scenarios: int
    verified_scenarios_count: int
    experimental_scenarios_count: int
    total_stored_manifests: int
    validated_manifests_count: int
    host_os: str
    namespaces_supported: bool
    execution_environment_note: str


SCENARIO_METADATA: dict[str, dict[str, str]] = {
    "scn-01-tunnel-v4-gcm-pfs": {
        "title": "Baseline Tunnel Mode IPv4 (AES-256-GCM / ECP-256 / PFS Enabled)",
        "category": "BASELINE",
    },
    "scn-02-tunnel-v4-cbc-nopfs": {
        "title": "Legacy CBC Mode IPv4 (AES-256-CBC / HMAC-SHA256 / No PFS)",
        "category": "COMPARISON",
    },
    "scn-03-transport-v4-gcm": {
        "title": "Transport Mode Host-to-Host IPv4 (AES-256-GCM / ECP-256)",
        "category": "TRANSPORT",
    },
    "scn-04-tunnel-v6-gcm-pfs": {
        "title": "Tunnel Mode IPv6 Site-to-Site (AES-256-GCM / ECP-256 / PFS)",
        "category": "IPV6",
    },
    "scn-05-tunnel-v4-netem": {
        "title": "Impaired WAN Simulation (tc/netem: 40ms delay, 10ms jitter, 2% loss)",
        "category": "IMPAIRMENT",
    },
    "scn-06-tunnel-v4-natt": {
        "title": "NAT-Traversal Simulation (UDP port 4500 ESP encapsulation)",
        "category": "NAT_T",
    },
    "scn-07-tunnel-v4-ikev1-3des-sha1-weak": {
        "title": "Intentional Negative: Weak Legacy IKEv1 (3DES-CBC / SHA-1 / MODP-1024)",
        "category": "NEGATIVE_TEST",
    },
    "scn-08-tunnel-v4-no-common-proposal": {
        "title": "Intentional Negative: Negotiation Rejection (Proposal Mismatch)",
        "category": "NEGATIVE_TEST",
    },
    "scn-09-tunnel-v4-aes128gcm-pfs": {
        "title": "SIH Baseline Compliance: Tunnel Mode IPv4 (AES-128-GCM / MODP-2048 / PFS)",
        "category": "COMPLIANCE",
    },
}


def _get_run_manifests_by_scenario() -> dict[str, list[dict[str, Any]]]:
    """Scans local storage for run manifests and groups by scenario_id."""
    runs_by_scn: dict[str, list[dict[str, Any]]] = {}
    if not RUNS_DIR.exists():
        return runs_by_scn

    for entry in sorted(RUNS_DIR.iterdir()):
        if entry.is_dir():
            manifest_file = entry / "manifest.json"
            if manifest_file.exists():
                try:
                    with open(manifest_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        scn_id = data.get("scenario_id")
                        if scn_id:
                            runs_by_scn.setdefault(scn_id, []).append(
                                {
                                    "run_id": entry.name,
                                    "validation_status": data.get("validation_status"),
                                    "status_summary": data.get("status_summary"),
                                    "started_at": data.get("started_at_utc"),
                                }
                            )
                except Exception as exc:
                    logger.warning("Could not parse manifest at %s: %s", manifest_file, exc)

    return runs_by_scn


@router.get(
    "/scenarios",
    response_model=list[ScenarioSummaryDTO],
    summary="List all lab testbed scenarios with tracked verification provenance",
)
async def list_scenarios() -> list[ScenarioSummaryDTO]:
    """Returns all 9 scenario specifications cross-referenced with actual test runs.

    Scenarios with at least one VALIDATED run on record are marked VERIFIED.
    Scenarios without historical verification runs are marked EXPERIMENTAL_UNVERIFIED.
    """
    runs_by_scn = _get_run_manifests_by_scenario()
    results: list[ScenarioSummaryDTO] = []

    if PROFILES_DIR.exists():
        for yaml_path in sorted(PROFILES_DIR.glob("*.yaml")):
            try:
                sc = ScenarioLoader.load_from_yaml(yaml_path)
                meta = SCENARIO_METADATA.get(sc.scenario_id, {})
                title = meta.get("title", sc.scenario_id)
                category = meta.get("category", "GENERAL")

                runs = runs_by_scn.get(sc.scenario_id, [])
                total_runs = len(runs)
                validated_runs = sum(1 for r in runs if r.get("validation_status") == "VALIDATED")

                latest_run: Optional[dict[str, Any]] = None
                for r in reversed(runs):
                    if r.get("validation_status") == "VALIDATED":
                        latest_run = r
                        break
                if not latest_run and runs:
                    latest_run = runs[-1]

                is_verified = validated_runs > 0
                status_label = "VERIFIED" if is_verified else "EXPERIMENTAL_UNVERIFIED"

                dto = ScenarioSummaryDTO(
                    scenario_id=sc.scenario_id,
                    scenario_version=sc.scenario_version,
                    title=title,
                    description=sc.description,
                    topology=sc.topology.value,
                    ip_version=sc.ip_version.value,
                    ike_version=sc.ike_version.value,
                    crypto_profile=sc.crypto_profile.value,
                    pfs=sc.pfs.value,
                    encapsulation=sc.encapsulation.value,
                    expected_outcome=sc.expected_outcome.value,
                    is_negative_test=sc.is_negative_test,
                    category=category,
                    is_verified=is_verified,
                    status=status_label,
                    total_runs=total_runs,
                    validated_runs=validated_runs,
                    latest_run_id=latest_run.get("run_id") if latest_run else None,
                    latest_run_status=latest_run.get("validation_status") if latest_run else None,
                    latest_run_summary=latest_run.get("status_summary") if latest_run else None,
                    latest_run_timestamp=latest_run.get("started_at") if latest_run else None,
                    sha256_hash=sc.sha256_hash,
                )
                results.append(dto)
            except Exception as exc:
                logger.error("Error loading scenario %s: %s", yaml_path, exc)

    return results


@router.get(
    "/stats",
    response_model=LabStatsDTO,
    summary="Get lab environment statistics and host execution capabilities",
)
async def get_lab_stats() -> LabStatsDTO:
    """Returns runtime host capability indicators and aggregate scenario counts."""
    runs_by_scn = _get_run_manifests_by_scenario()
    total_manifests = sum(len(runs) for runs in runs_by_scn.values())
    validated_manifests = sum(
        sum(1 for r in runs if r.get("validation_status") == "VALIDATED")
        for runs in runs_by_scn.values()
    )

    scenarios = await list_scenarios()
    verified_count = sum(1 for s in scenarios if s.is_verified)
    experimental_count = len(scenarios) - verified_count

    current_os = platform.system()
    namespaces_supported = current_os.lower() == "linux"

    if namespaces_supported:
        env_note = "Linux host detected. Network namespaces and CAP_NET_ADMIN available."
    else:
        env_note = f"{current_os} host detected. Linux namespaces unavailable. Use docker-compose.lab.yml or WSL2 runner."

    return LabStatsDTO(
        total_scenarios=len(scenarios),
        verified_scenarios_count=verified_count,
        experimental_scenarios_count=experimental_count,
        total_stored_manifests=total_manifests,
        validated_manifests_count=validated_manifests,
        host_os=current_os,
        namespaces_supported=namespaces_supported,
        execution_environment_note=env_note,
    )
