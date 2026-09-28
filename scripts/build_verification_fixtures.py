#!/usr/bin/env python3
"""Build and verify curated test fixture library for TunnelTrace AI.

Generates:
  tests/fixtures/verification_captures/
    ├── 01_strongswan_ikev2_esp_aes_gcm.pcapng
    ├── 02_strongswan_esp_only_partial.pcap
    ├── 03_strongswan_natt_udp4500.pcap
    ├── 04_plaintext_icmp_non_ipsec.pcap
    ├── 05_wireguard_tunnel_non_ipsec.pcapng
    ├── 06_openvpn_chat_sample_non_ipsec.pcap
    ├── 07_edge_truncated_pcap_frame.pcap
    ├── 08_edge_corrupted_magic_bytes.pcap
    ├── 09_edge_corrupted_spi_zero.pcap
    ├── 10_edge_esp_seq_jump_replay.pcap
    ├── manifest.json
    └── INDEX.md
"""

import hashlib
import json
import os
import shutil
import struct
import sys
from pathlib import Path

# Add backend directory for imports
BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.capture.validation import validate_capture_file, CaptureValidationError
from app.capture.metadata import extract_capture_metadata

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_DIR = REPO_ROOT / "tests" / "fixtures" / "verification_captures"


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def create_truncated_pcap(dest: Path):
    """Create a valid PCAP global header with a packet header declaring 128 bytes but only 16 bytes present."""
    # PCAP LE global header: magic (4), v_maj (2), v_min (2), zone (4), sigfigs (4), snaplen (4), net (4)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    # Packet header: ts_sec (4), ts_usec (4), incl_len (4), orig_len (4)
    # Declaring incl_len = 128, orig_len = 128
    pkt_hdr = struct.pack("<IIII", 1727113665, 12345, 128, 128)
    # Only 16 bytes of payload instead of 128
    truncated_payload = b"\x00" * 16
    with open(dest, "wb") as f:
        f.write(global_hdr + pkt_hdr + truncated_payload)


def create_corrupted_magic_file(dest: Path):
    """Create a file with completely invalid magic header to test upload rejection."""
    with open(dest, "wb") as f:
        f.write(b"CORRUPTED_NON_PCAP_MAGIC_HEADER_BYTES_12345678")


def create_corrupted_spi_zero_pcap(source_pcap: Path, dest: Path):
    """Mutate packet 5 in NAT-T PCAP so ESP SPI is 0x00000000 (illegal per RFC 4303)."""
    with open(source_pcap, "rb") as f:
        content = bytearray(f.read())

    # Find the offset of packet 5
    # Header is 24 bytes
    offset = 24
    for pkt_idx in range(1, 13):
        if offset + 16 > len(content):
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", content[offset:offset+16])
        if pkt_idx == 5:
            # UDP encapsulated ESP: Eth (14) + IP (20) + UDP (8) = 42 bytes into packet data
            # SPI is 4 bytes at offset + 16 + 42
            spi_offset = offset + 16 + 42
            # Replace SPI with 0x00000000
            content[spi_offset:spi_offset+4] = b"\x00\x00\x00\x00"
            break
        offset += 16 + incl_len

    with open(dest, "wb") as f:
        f.write(content)


def create_esp_seq_jump_replay_pcap(source_pcap: Path, dest: Path):
    """Mutate packet 7 (direction 0xce7e5151) so ESP Seq repeats Seq 1 (replay anomaly)."""
    with open(source_pcap, "rb") as f:
        content = bytearray(f.read())

    offset = 24
    for pkt_idx in range(1, 13):
        if offset + 16 > len(content):
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", content[offset:offset+16])
        if pkt_idx == 7:
            # UDP encapsulated ESP: Eth (14) + IP (20) + UDP (8) = 42 bytes into packet data
            # Seq is 4 bytes right after SPI: offset + 16 + 42 + 4
            seq_offset = offset + 16 + 42 + 4
            # Set seq to 1 (replaying seq 1 on SPI 0xce7e5151 instead of expected seq 2)
            content[seq_offset:seq_offset+4] = struct.pack(">I", 1)
            break
        offset += 16 + incl_len

    with open(dest, "wb") as f:
        f.write(content)


def create_sampled_pcap(source_pcap: Path, dest: Path, max_packets: int = 50):
    """Extract a lightweight sample of packets from a large PCAP file."""
    with open(source_pcap, "rb") as f:
        hdr = f.read(24)
        packets_data = []
        count = 0
        while count < max_packets:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", pkt_hdr)
            pkt_bytes = f.read(incl_len)
            packets_data.append(pkt_hdr + pkt_bytes)
            count += 1

    with open(dest, "wb") as f:
        f.write(hdr)
        for p in packets_data:
            f.write(p)


def main():
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Building verification fixtures in: {TARGET_DIR}")

    # 1. 01_strongswan_ikev2_esp_aes_gcm.pcapng
    f1_src = REPO_ROOT / "tests" / "fixtures" / "captures" / "real_tunnel_gcm.pcapng"
    f1_dst = TARGET_DIR / "01_strongswan_ikev2_esp_aes_gcm.pcapng"
    shutil.copy2(f1_src, f1_dst)
    print("Copied fixture 01")

    # 2. 02_strongswan_esp_only_partial.pcap
    f2_src = REPO_ROOT / "tests" / "fixtures" / "captures" / "real_esp_only.pcap"
    f2_dst = TARGET_DIR / "02_strongswan_esp_only_partial.pcap"
    shutil.copy2(f2_src, f2_dst)
    print("Copied fixture 02")

    # 3. 03_strongswan_natt_udp4500.pcap
    f3_src = REPO_ROOT / "storage" / "lab" / "runs" / "tt-1790185927-b1d8f6" / "captures" / "wan_encrypted.pcap"
    f3_dst = TARGET_DIR / "03_strongswan_natt_udp4500.pcap"
    shutil.copy2(f3_src, f3_dst)
    print("Copied fixture 03")

    # 4. 04_plaintext_icmp_non_ipsec.pcap
    f4_src = REPO_ROOT / "storage" / "lab" / "runs" / "tt-1790185654-25c4bc" / "captures" / "client_plaintext.pcap"
    f4_dst = TARGET_DIR / "04_plaintext_icmp_non_ipsec.pcap"
    shutil.copy2(f4_src, f4_dst)
    print("Copied fixture 04")

    # 5. 05_wireguard_tunnel_non_ipsec.pcapng
    f5_src = REPO_ROOT / "storage" / "captures" / "767fc240-29e4-483d-b601-a455260e61ce" / "raw.pcapng"
    f5_dst = TARGET_DIR / "05_wireguard_tunnel_non_ipsec.pcapng"
    shutil.copy2(f5_src, f5_dst)
    print("Copied fixture 05")

    # 6. 06_openvpn_chat_sample_non_ipsec.pcap
    f6_src = REPO_ROOT / "storage" / "captures" / "8fb17d2c-889a-4bed-8571-d0900205b8b3" / "raw.pcap"
    f6_dst = TARGET_DIR / "06_openvpn_chat_sample_non_ipsec.pcap"
    create_sampled_pcap(f6_src, f6_dst, max_packets=50)
    print("Generated fixture 06 (sampled OpenVPN)")

    # 7. 07_edge_truncated_pcap_frame.pcap
    f7_dst = TARGET_DIR / "07_edge_truncated_pcap_frame.pcap"
    create_truncated_pcap(f7_dst)
    print("Generated fixture 07 (truncated frame)")

    # 8. 08_edge_corrupted_magic_bytes.pcap
    f8_dst = TARGET_DIR / "08_edge_corrupted_magic_bytes.pcap"
    create_corrupted_magic_file(f8_dst)
    print("Generated fixture 08 (corrupted magic)")

    # 9. 09_edge_corrupted_spi_zero.pcap
    f9_dst = TARGET_DIR / "09_edge_corrupted_spi_zero.pcap"
    create_corrupted_spi_zero_pcap(f3_dst, f9_dst)
    print("Generated fixture 09 (RFC 4303 SPI 0)")

    # 10. 10_edge_esp_seq_jump_replay.pcap
    f10_dst = TARGET_DIR / "10_edge_esp_seq_jump_replay.pcap"
    create_esp_seq_jump_replay_pcap(f3_dst, f10_dst)
    print("Generated fixture 10 (ESP sequence replay)")

    # Inspect all fixtures and compile manifest
    fixtures_metadata = [
        {
            "fixture_id": "FIX-VERIF-01-IKEV2-GCM",
            "filename": "01_strongswan_ikev2_esp_aes_gcm.pcapng",
            "category": "GENUINE_IPSEC_TUNNEL",
            "source": "strongSwan Lab (scn-01-tunnel-v4-gcm-pfs)",
            "description": "Full strongSwan IKEv2 negotiation and ESP AES-GCM data transfer.",
            "expected_behavior": {
                "validation": "PASS",
                "ipsec_detected": True,
                "ike_version": "IKEv2",
                "esp_detected": True,
                "encryption": "AES-GCM-16-256",
                "dh_group": "ECP-256 (DH19)",
                "expected_score": 100,
                "evidence_coverage": "85.7% (6/7 assessed, 1 unknown)",
                "traffic_ml_disposition": "OUT_OF_DISTRIBUTION (OOD Abstention) or low confidence"
            }
        },
        {
            "fixture_id": "FIX-VERIF-02-ESP-ONLY",
            "filename": "02_strongswan_esp_only_partial.pcap",
            "category": "PARTIAL_EVIDENCE",
            "source": "strongSwan Lab (frames 5-12 isolated)",
            "description": "ESP ciphertext frames only without preceding IKE negotiation handshake.",
            "expected_behavior": {
                "validation": "PASS",
                "ipsec_detected": True,
                "ike_version": None,
                "esp_detected": True,
                "expected_score": 100,
                "evidence_coverage": "14.3% (1/7 assessed, 6 unknown)",
                "traffic_ml_disposition": "PARTIAL_METADATA_EXTRACTED"
            }
        },
        {
            "fixture_id": "FIX-VERIF-03-NATT-UDP4500",
            "filename": "03_strongswan_natt_udp4500.pcap",
            "category": "GENUINE_IPSEC_TUNNEL",
            "source": "strongSwan Lab (scn-06-tunnel-v4-natt)",
            "description": "IKEv2 negotiation migrating from UDP 500 to UDP 4500 with UDP-encapsulated ESP.",
            "expected_behavior": {
                "validation": "PASS",
                "ipsec_detected": True,
                "natt_detected": True,
                "esp_encapsulation": "UDP_ENCAPSULATED_ESP",
                "udp_port": 4500,
                "expected_score": 100,
                "evidence_coverage": "85.7%"
            }
        },
        {
            "fixture_id": "FIX-VERIF-04-PLAINTEXT-ICMP",
            "filename": "04_plaintext_icmp_non_ipsec.pcap",
            "category": "NON_IPSEC_BASELINE",
            "source": "strongSwan Lab (client plaintext probe)",
            "description": "Plaintext ICMP echo requests and replies before IPsec tunnel establishment.",
            "expected_behavior": {
                "validation": "PASS",
                "ipsec_detected": False,
                "disposition": "NO_IPSEC_FOUND",
                "expected_score": None,
                "evidence_coverage": "0.0%"
            }
        },
        {
            "fixture_id": "FIX-VERIF-05-WIREGUARD",
            "filename": "05_wireguard_tunnel_non_ipsec.pcapng",
            "category": "NON_IPSEC_BASELINE",
            "source": "Controlled Capture (WireGuard ping tcp)",
            "description": "Non-IPsec VPN traffic consisting of WireGuard handshake and encrypted transport.",
            "expected_behavior": {
                "validation": "PASS",
                "ipsec_detected": False,
                "disposition": "NOT_IPSEC",
                "protocol": "WIREGUARD"
            }
        },
        {
            "fixture_id": "FIX-VERIF-06-OPENVPN-CHAT",
            "filename": "06_openvpn_chat_sample_non_ipsec.pcap",
            "category": "NON_IPSEC_BASELINE",
            "source": "Controlled Capture (OpenVPN application session sample)",
            "description": "Non-IPsec VPN capture containing OpenVPN transport frames.",
            "expected_behavior": {
                "validation": "PASS",
                "ipsec_detected": False,
                "disposition": "NOT_IPSEC / INSUFFICIENT_EVIDENCE",
                "protocol": "OPENVPN"
            }
        },
        {
            "fixture_id": "FIX-VERIF-07-TRUNCATED-FRAME",
            "filename": "07_edge_truncated_pcap_frame.pcap",
            "category": "EDGE_CASE_PARSER_INTEGRITY",
            "source": "Synthetic deterministic generation",
            "description": "PCAP with truncated frame length to verify parser doesn't crash on incomplete frames.",
            "expected_behavior": {
                "validation": "PASS (Header valid) / Parser handled safely",
                "error_handling": "GRACEFUL_TRUNCATION_HANDLING"
            }
        },
        {
            "fixture_id": "FIX-VERIF-08-CORRUPTED-MAGIC",
            "filename": "08_edge_corrupted_magic_bytes.pcap",
            "category": "EDGE_CASE_VALIDATION_REJECTION",
            "source": "Synthetic deterministic generation",
            "description": "Non-PCAP binary header to verify upload endpoint rejects invalid magic bytes.",
            "expected_behavior": {
                "validation": "FAIL",
                "error_code": "CAPTURE_INVALID_FORMAT",
                "http_status": 400
            }
        },
        {
            "fixture_id": "FIX-VERIF-09-CORRUPTED-SPI-ZERO",
            "filename": "09_edge_corrupted_spi_zero.pcap",
            "category": "EDGE_CASE_SECURITY_ANOMALY",
            "source": "Synthetic mutation from strongSwan NAT-T",
            "description": "ESP packet with SPI = 0x00000000 violating RFC 4303 Section 2.1.",
            "expected_behavior": {
                "validation": "PASS",
                "ipsec_detected": True,
                "anomaly_flag": "RFC_4303_RESERVED_SPI_ZERO"
            }
        },
        {
            "fixture_id": "FIX-VERIF-10-ESP-SEQ-REPLAY",
            "filename": "10_edge_esp_seq_jump_replay.pcap",
            "category": "EDGE_CASE_SECURITY_ANOMALY",
            "source": "Synthetic mutation from strongSwan NAT-T",
            "description": "ESP frame sequence jump / replay (sequence number duplicate).",
            "expected_behavior": {
                "validation": "PASS",
                "ipsec_detected": True,
                "anomaly_flag": "ESP_SEQUENCE_REPLAY_DETECTED"
            }
        },
    ]

    manifest = {"manifest_version": "1.0.0", "target_suite": "TunnelTrace AI Verification Captures", "fixtures": []}

    md_lines = [
        "# Curated Test Fixtures & Manifest",
        "",
        "This directory contains authentic lab traces, protocol baselines, and deterministic edge-case captures used to rigorously verify the TunnelTrace AI platform without modifying production or demo databases.",
        "",
        "| ID | Filename | Format | Size (B) | Packets | Category | SHA-256 | Expected Disposition |",
        "|---|---|---|---|---|---|---|---|",
    ]

    for item in fixtures_metadata:
        file_path = TARGET_DIR / item["filename"]
        file_size = file_path.stat().st_size
        sha256 = compute_sha256(file_path)

        # Validate header
        val_status = "UNKNOWN"
        try:
            fmt, magic = validate_capture_file(file_path)
            val_status = f"{fmt.value} ({magic.value})"
        except CaptureValidationError as cve:
            val_status = f"REJECTED ({cve.code})"

        # Extract metadata
        pkt_count = None
        duration = None
        try:
            meta = extract_capture_metadata(file_path)
            pkt_count = meta.packet_count
            duration = meta.duration_sec
        except Exception:
            pass

        entry = {
            "fixture_id": item["fixture_id"],
            "filename": item["filename"],
            "category": item["category"],
            "format": val_status,
            "sha256": sha256,
            "size_bytes": file_size,
            "packet_count": pkt_count,
            "duration_sec": duration,
            "source": item["source"],
            "description": item["description"],
            "expected_behavior": item["expected_behavior"],
        }
        manifest["fixtures"].append(entry)

        disp = item["expected_behavior"].get("disposition") or (
            f"Score: {item['expected_behavior'].get('expected_score')}, Cov: {item['expected_behavior'].get('evidence_coverage')}"
            if "expected_score" in item["expected_behavior"]
            else item["expected_behavior"].get("error_code", "PASS")
        )
        md_lines.append(
            f"| `{item['fixture_id']}` | `{item['filename']}` | {val_status} | {file_size} | {pkt_count or 'N/A'} | {item['category']} | `{sha256[:12]}...` | {disp} |"
        )

    # Write manifest.json
    manifest_path = TARGET_DIR / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Wrote manifest to {manifest_path}")

    # Write INDEX.md
    md_lines.extend([
        "",
        "## Detailed Fixture Specifications",
        "",
    ])
    for item in manifest["fixtures"]:
        md_lines.extend([
            f"### `{item['fixture_id']}`: {item['filename']}",
            f"- **Category**: `{item['category']}`",
            f"- **Provenance / Source**: {item['source']}",
            f"- **SHA-256**: `{item['sha256']}`",
            f"- **Size**: {item['size_bytes']} bytes",
            f"- **Packet Count**: {item['packet_count'] or 'N/A'}",
            f"- **Format Validation**: `{item['format']}`",
            f"- **Description**: {item['description']}",
            f"- **Expected Analytical Behavior**:",
        ])
        for k, v in item["expected_behavior"].items():
            md_lines.append(f"  - **{k}**: `{v}`")
        md_lines.append("")

    index_path = TARGET_DIR / "INDEX.md"
    with open(index_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines) + "\n")
    print(f"Wrote index to {index_path}")


if __name__ == "__main__":
    main()
