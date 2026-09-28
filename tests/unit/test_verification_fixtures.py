"""Automated validation tests for curated verification captures fixture suite."""

import hashlib
import json
from pathlib import Path
import pytest

from app.capture.validation import validate_capture_file, CaptureValidationError
from app.capture.metadata import extract_capture_metadata

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "verification_captures"
MANIFEST_PATH = FIXTURES_DIR / "manifest.json"


def test_manifest_exists_and_parses():
    assert MANIFEST_PATH.exists(), "verification_captures/manifest.json must exist"
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "fixtures" in data
    assert len(data["fixtures"]) >= 10


def test_fixtures_integrity_and_sha256():
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    for entry in manifest["fixtures"]:
        file_path = FIXTURES_DIR / entry["filename"]
        assert file_path.exists(), f"Fixture file {entry['filename']} missing from disk"
        
        # Verify size
        actual_size = file_path.stat().st_size
        assert actual_size == entry["size_bytes"], (
            f"Size mismatch for {entry['filename']}: expected {entry['size_bytes']}, got {actual_size}"
        )

        # Verify sha256
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        actual_hash = h.hexdigest()
        assert actual_hash == entry["sha256"], (
            f"SHA-256 mismatch for {entry['filename']}: expected {entry['sha256']}, got {actual_hash}"
        )


def test_corrupted_magic_rejection():
    """Verify that 08_edge_corrupted_magic_bytes.pcap is rejected deterministically."""
    corrupted_file = FIXTURES_DIR / "08_edge_corrupted_magic_bytes.pcap"
    assert corrupted_file.exists()

    with pytest.raises(CaptureValidationError) as exc_info:
        validate_capture_file(corrupted_file)

    assert exc_info.value.code == "CAPTURE_INVALID_FORMAT"


def test_valid_captures_header_validation():
    """Verify that all authentic capture headers pass format validation."""
    valid_files = [
        "01_strongswan_ikev2_esp_aes_gcm.pcapng",
        "02_strongswan_esp_only_partial.pcapng",
        "03_strongswan_natt_udp4500.pcap",
        "04_plaintext_icmp_non_ipsec.pcap",
        "05_wireguard_tunnel_non_ipsec.pcapng",
        "06_openvpn_chat_sample_non_ipsec.pcap",
        "07_edge_truncated_pcap_frame.pcap",
        "09_edge_corrupted_spi_zero.pcap",
        "10_edge_esp_seq_jump_replay.pcap",
    ]
    for fn in valid_files:
        p = FIXTURES_DIR / fn
        fmt, magic = validate_capture_file(p)
        assert fmt.value in ("PCAP", "PCAPNG")
