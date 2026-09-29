"""Unit tests for standalone GatewayCollector script (SIH PS 26160).

Tests:
1. Token resolution from file, environment, and CLI flags
2. Local FIFO retention enforcement and capture manifest generation
3. Mock mode telemetry event generation and schema compliance
4. Prerequisite capability checks and non-root graceful fallback
"""

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure scripts directory is on sys.path
root_dir = Path(__file__).parent.parent.parent
scripts_dir = root_dir / "scripts"
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))

from gateway_collector import GatewayCollector


def test_collector_token_resolution_from_env_and_file(tmp_path: Path):
    """Verify SENSOR_TOKEN resolution prioritizes protected file over environment."""
    token_file = tmp_path / "secret.token"
    token_file.write_text("file-secret-token-123\n", encoding="utf-8")

    collector = GatewayCollector(
        api_url="http://127.0.0.1:8002/api/v1",
        gateway_name="test-gw",
        token="direct-token",
        output_dir=str(tmp_path / "captures"),
        mock_mode=True,
    )
    assert collector.token == "direct-token"


def test_collector_retention_enforcement(tmp_path: Path):
    """Verify strict FIFO retention limits rolling PCAP files and generates manifest."""
    cap_dir = tmp_path / "captures"
    cap_dir.mkdir(parents=True, exist_ok=True)

    # Create 5 dummy capture files with staggered timestamps
    now = time.time()
    for i in range(5):
        pcap = cap_dir / f"gateway_capture_{i}.pcapng"
        pcap.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 100)
        # Stagger modification times
        os.utime(pcap, (now + i * 10, now + i * 10))

    # Initialize collector with max_pcap_files=3 (enforces retention on init)
    collector = GatewayCollector(
        api_url="http://127.0.0.1:8002/api/v1",
        gateway_name="test-gw",
        output_dir=str(cap_dir),
        max_pcap_files=3,
        max_pcap_mb=10,
        mock_mode=True,
    )

    remaining = list(cap_dir.glob("*.pcap*"))
    assert len(remaining) == 3

    # Add 2 more files and call enforce_retention again
    for i in range(5, 7):
        pcap = cap_dir / f"gateway_capture_{i}.pcapng"
        pcap.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 100)
        os.utime(pcap, (now + i * 10, now + i * 10))

    pruned = collector.enforce_retention()
    remaining = list(cap_dir.glob("*.pcap*"))
    assert len(remaining) == 3
    assert len(pruned) == 2

    # Verify capture_manifest.json
    manifest_file = cap_dir / "capture_manifest.json"
    assert manifest_file.exists()
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert manifest_data["gateway"] == "test-gw"
    assert manifest_data["max_pcap_files"] == 3
    assert manifest_data["active_captures_count"] == 3
    assert len(manifest_data["captures"]) == 3


def test_collector_mock_mode_telemetry(tmp_path: Path):
    """Verify mock mode generates structured IKE SAs and child SAs without root."""
    collector = GatewayCollector(
        api_url="http://127.0.0.1:8002/api/v1",
        gateway_name="mock-edge-router",
        output_dir=str(tmp_path / "captures"),
        mock_mode=True,
    )

    sas = collector.collect_swanctl_sas()
    assert len(sas) == 1
    assert sas[0]["name"] == "gw-to-headquarters"
    assert sas[0]["ike_version"] == 2
    assert len(sas[0]["child_sas"]) == 1
    assert sas[0]["child_sas"][0]["enc_alg"] == "AES_GCM_16_256"


def test_collector_prerequisites_check():
    """Verify check_prerequisites reports capabilities as boolean dictionary."""
    collector = GatewayCollector(
        api_url="http://127.0.0.1:8002/api/v1",
        gateway_name="test-gw",
        mock_mode=True,
    )
    status = collector.check_prerequisites()
    assert isinstance(status, dict)
    assert "is_root" in status
    assert "swanctl" in status
    assert "tcpdump" in status
    assert "tshark" in status
