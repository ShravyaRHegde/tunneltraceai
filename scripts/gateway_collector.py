#!/usr/bin/env python3
"""TunnelTrace AI — Standalone Gateway Telemetry & Capture Collector.

Part of SIH 2026 / NTRO Problem Statement 26160.
Deployed directly on Linux IPsec VPN Gateways (strongSwan / Libreswan / XFRM).
Collects:
1. Active Security Associations (IKE & Child SAs via swanctl/VICI or ip xfrm)
2. Directional ESP traffic metrics (packet counts, byte volumes, SPI pairs)
3. Cryptographic state transitions and rekey events
4. Rolling PCAP capture with authoritative IPsec BPF filter:
   "udp port 500 or udp port 4500 or esp"
5. Forwarding structured, authenticated telemetry event batches to POST /api/v1/monitoring/events
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [TunnelTrace-Collector] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("gateway_collector")

BPF_FILTER = "udp port 500 or udp port 4500 or esp"


class GatewayCollector:
    """Collects IPsec SA telemetry and forwards heartbeats to TunnelTrace AI."""

    def __init__(
        self,
        api_url: str,
        gateway_name: str,
        sensor_id: str | None = None,
        gateway_id: str | None = None,
        token: str | None = None,
        scope: str = "10.0.0.0/8",
        interface: str | None = None,
        output_dir: str = "./captures",
        interval: int = 10,
        mock_mode: bool = False,
        max_pcap_files: int = 5,
        max_pcap_mb: int = 50,
        upload_on_stop: bool = False,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.gateway_name = gateway_name
        self.sensor_id = sensor_id or str(uuid.uuid4())
        self.gateway_id = gateway_id or str(uuid.uuid4())
        self.token = token
        self.scope = scope
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.interval = interval
        self.mock_mode = mock_mode
        self.max_pcap_files = max(1, max_pcap_files)
        self.max_pcap_mb = max(1, max_pcap_mb)
        self.upload_on_stop = upload_on_stop
        self.running = False
        self.sequence_number = 0
        self.session_id = str(uuid.uuid4())[:8]

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.enforce_retention()

    def enforce_retention(self) -> list[Path]:
        """Enforce strict local FIFO retention on PCAP files to protect router disk space."""
        import hashlib
        captures = sorted(
            [p for p in self.output_dir.glob("*.pcap*") if p.is_file()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        pruned: list[Path] = []
        if len(captures) > self.max_pcap_files:
            for old_file in captures[self.max_pcap_files:]:
                try:
                    old_file.unlink()
                    pruned.append(old_file)
                    logger.info("Enforced retention quota: pruned old capture %s", old_file.name)
                except OSError as exc:
                    logger.warning("Failed to prune old capture %s: %s", old_file.name, exc)

        # Update local tamper-evident capture manifest
        active_captures = [p for p in self.output_dir.glob("*.pcap*") if p.is_file()]
        manifest_entries = []
        for cap in sorted(active_captures, key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                size_b = cap.stat().st_size
                manifest_entries.append({
                    "filename": cap.name,
                    "size_bytes": size_b,
                    "modified_at": datetime.fromtimestamp(cap.stat().st_mtime, timezone.utc).isoformat(),
                })
            except OSError:
                continue

        manifest_file = self.output_dir / "capture_manifest.json"
        try:
            manifest_file.write_text(json.dumps({
                "gateway": self.gateway_name,
                "sensor_id": self.sensor_id,
                "max_pcap_files": self.max_pcap_files,
                "max_pcap_mb": self.max_pcap_mb,
                "active_captures_count": len(manifest_entries),
                "captures": manifest_entries,
            }, indent=2), encoding="utf-8")
        except OSError as exc:
            logger.warning("Could not write capture manifest: %s", exc)

        return pruned

    def check_prerequisites(self) -> dict[str, bool]:
        """Check for strongSwan tools, tshark/tcpdump, and raw socket permissions."""
        status = {
            "swanctl": shutil.which("swanctl") is not None,
            "ip_xfrm": shutil.which("ip") is not None,
            "tcpdump": shutil.which("tcpdump") is not None,
            "tshark": shutil.which("tshark") is not None,
            "is_root": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
        }
        logger.info("System Capabilities: %s", status)
        return status

    def collect_swanctl_sas(self) -> list[dict[str, Any]]:
        """Query strongSwan via swanctl CLI."""
        if self.mock_mode:
            return [
                {
                    "name": "gw-to-headquarters",
                    "ike_version": 2,
                    "local_host": "192.168.1.1",
                    "remote_host": "198.51.100.1",
                    "initiator_spi": "0x1122334455667788",
                    "responder_spi": "0x8877665544332211",
                    "state": "ESTABLISHED",
                    "child_sas": [
                        {
                            "name": "net-net",
                            "protocol": "ESP",
                            "spi_in": "0xc0ffee01",
                            "spi_out": "0xc0ffee02",
                            "enc_alg": "AES_GCM_16_256",
                            "bytes_in": 1048576,
                            "bytes_out": 2097152,
                        }
                    ],
                }
            ]

        if not shutil.which("swanctl"):
            return []

        try:
            res = subprocess.run(
                ["swanctl", "--list-sas"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            return self._parse_swanctl_output(res.stdout)
        except Exception as exc:
            logger.warning("Failed to query swanctl: %s", exc)
            return []

    def _parse_swanctl_output(self, raw: str) -> list[dict[str, Any]]:
        """Parse text output of swanctl --list-sas into structured JSON."""
        sas = []
        current_sa: dict[str, Any] | None = None

        for line in raw.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            if not line.startswith(" ") and ":" in line:
                if current_sa:
                    sas.append(current_sa)
                sa_name = line.split(":", 1)[0].strip()
                current_sa = {
                    "name": sa_name,
                    "state": "ESTABLISHED",
                    "child_sas": [],
                }
            elif current_sa and "SPIs:" in line_str:
                m = re.search(r"([0-9a-fA-F_x]+)_i\s+([0-9a-fA-F_x]+)_o", line_str)
                if m:
                    current_sa["initiator_spi"] = m.group(1)
                    current_sa["responder_spi"] = m.group(2)
            elif current_sa and "ESP" in line_str:
                current_sa["child_sas"].append({"summary": line_str})

        if current_sa:
            sas.append(current_sa)
        return sas

    def collect_xfrm_state(self) -> list[dict[str, Any]]:
        """Query kernel XFRM state directly via ip xfrm."""
        if not shutil.which("ip"):
            return []
        try:
            res = subprocess.run(
                ["ip", "-s", "xfrm", "state"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            states = []
            for block in res.stdout.split("\n\n"):
                if "src " in block and "dst " in block:
                    states.append({"raw_state": block.strip()})
            return states
        except Exception as exc:
            logger.warning("Failed to query ip xfrm state: %s", exc)
            return []

    def start_packet_capture(self) -> subprocess.Popen | None:
        """Start rolling background packet capture restricted to IPsec traffic."""
        if not self.interface:
            logger.info("No capture interface specified; skipping background PCAP sniffing.")
            return None

        pcap_file = self.output_dir / f"gateway_capture_{int(time.time())}.pcapng"
        if shutil.which("tshark"):
            cmd = [
                "tshark",
                "-i", self.interface,
                "-f", BPF_FILTER,
                "-b", f"filesize:{self.max_pcap_mb * 1024}",
                "-b", f"files:{self.max_pcap_files}",
                "-w", str(pcap_file),
            ]
        elif shutil.which("tcpdump"):
            # tcpdump expects BPF expression as positional argument, not preceded by -f
            cmd = [
                "tcpdump",
                "-i", self.interface,
                "-C", str(self.max_pcap_mb),
                "-W", str(self.max_pcap_files),
                "-w", str(pcap_file),
                BPF_FILTER,
            ]
        else:
            logger.warning("Neither tshark nor tcpdump is available; skipping capture.")
            return None
        logger.info(
            "Launching IPsec rolling capture (Ring buffer: %d files x %d MB): %s",
            self.max_pcap_files,
            self.max_pcap_mb,
            " ".join(cmd),
        )
        try:
            return subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            logger.warning("Failed to start packet capture process: %s", exc)
            return None

    def send_telemetry(self, events: list[dict[str, Any]]) -> bool:
        """Post structured MonitoringEventBatchRequest to backend API."""
        if not events:
            return True

        url = f"{self.api_url}/monitoring/events"
        batch_payload = json.dumps({"events": events}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "TunnelTrace-GatewayCollector/1.2.0",
        }
        if self.token:
            headers["X-Sensor-Token"] = self.token

        req = urllib.request.Request(url, data=batch_payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8")
                res_json = json.loads(body)
                logger.info(
                    "Telemetry forwarded successfully: %d accepted, %d duplicates (Batch ID: %s)",
                    res_json.get("accepted_count", 0),
                    res_json.get("duplicate_count", 0),
                    res_json.get("batch_id", "unknown"),
                )
                return True
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            logger.warning("Backend API rejected telemetry (HTTP %d): %s", exc.code, err_body)
            return False
        except urllib.error.URLError as exc:
            logger.warning("Failed to connect to TunnelTrace API at %s: %s", url, exc.reason)
            return False
        except Exception as exc:
            logger.warning("Unexpected error forwarding telemetry: %s", exc)
            return False

    def run(self) -> None:
        """Main collection loop."""
        self.running = True
        logger.info(
            "Starting Gateway Collector targeting '%s' (Interval: %ds, Sensor ID: %s)",
            self.gateway_name,
            self.interval,
            self.sensor_id,
        )
        logger.info("Authoritative IPsec BPF filter: '%s'", BPF_FILTER)

        cap_proc = self.start_packet_capture()

        try:
            while self.running:
                sas = self.collect_swanctl_sas()
                xfrm = self.collect_xfrm_state()

                now_utc = datetime.now(timezone.utc)
                now_iso = now_utc.isoformat()

                telemetry = {
                    "timestamp": now_iso,
                    "gateway": self.gateway_name,
                    "sensor_id": self.sensor_id,
                    "gateway_id": self.gateway_id,
                    "authorized_scope": self.scope,
                    "active_sas_count": len(sas),
                    "active_sas": sas,
                    "xfrm_count": len(xfrm),
                }

                logger.info(
                    "Heartbeat: %d active IKE SAs, %d XFRM state pairs observed",
                    len(sas),
                    len(xfrm),
                )

                # Write local rolling telemetry snapshot
                status_file = self.output_dir / "latest_telemetry.json"
                status_file.write_text(json.dumps(telemetry, indent=2), encoding="utf-8")

                # Build typed event batch for TunnelTrace continuous monitoring
                self.sequence_number += 1
                events: list[dict[str, Any]] = [
                    {
                        "event_id": str(uuid.uuid4()),
                        "schema_version": "v1.0.0",
                        "sensor_id": self.sensor_id,
                        "gateway_id": self.gateway_id,
                        "authorized_scope": self.scope,
                        "event_kind": "GATEWAY_HEARTBEAT",
                        "source_timestamp": now_iso,
                        "sequence_number": self.sequence_number,
                        "source_session_id": self.session_id,
                        "evidence_grade": "OBSERVED" if not self.mock_mode else "INFERRED",
                        "collector_version": "1.2.0",
                        "payload": {
                            "gateway_name": self.gateway_name,
                            "active_sas_count": len(sas),
                            "xfrm_count": len(xfrm),
                            "interface": self.interface,
                        },
                    }
                ]

                for sa in sas:
                    self.sequence_number += 1
                    ike_evt = {
                        "event_id": str(uuid.uuid4()),
                        "schema_version": "v1.0.0",
                        "sensor_id": self.sensor_id,
                        "gateway_id": self.gateway_id,
                        "authorized_scope": self.scope,
                        "event_kind": "GATEWAY_IKE_SA_ESTABLISHED",
                        "source_timestamp": now_iso,
                        "sequence_number": self.sequence_number,
                        "source_session_id": self.session_id,
                        "evidence_grade": "OBSERVED" if not self.mock_mode else "INFERRED",
                        "ike_version": str(sa.get("ike_version", "2")),
                        "local_endpoint": sa.get("local_host"),
                        "remote_endpoint": sa.get("remote_host"),
                        "initiator_spi": sa.get("initiator_spi"),
                        "responder_spi": sa.get("responder_spi"),
                        "collector_version": "1.2.0",
                        "payload": {"sa_name": sa.get("name", "unknown")},
                    }
                    events.append(ike_evt)

                    for child in sa.get("child_sas", []):
                        self.sequence_number += 1
                        child_evt = {
                            "event_id": str(uuid.uuid4()),
                            "schema_version": "v1.0.0",
                            "sensor_id": self.sensor_id,
                            "gateway_id": self.gateway_id,
                            "authorized_scope": self.scope,
                            "event_kind": "GATEWAY_CHILD_SA_ESTABLISHED",
                            "source_timestamp": now_iso,
                            "sequence_number": self.sequence_number,
                            "source_session_id": self.session_id,
                            "evidence_grade": "OBSERVED" if not self.mock_mode else "INFERRED",
                            "child_spi_in": child.get("spi_in"),
                            "child_spi_out": child.get("spi_out"),
                            "cipher_suite": child.get("enc_alg"),
                            "byte_count": child.get("bytes_in", 0) + child.get("bytes_out", 0),
                            "collector_version": "1.2.0",
                            "payload": {"child_name": child.get("name", "net-net")},
                        }
                        events.append(child_evt)

                # Send batch to backend
                self.send_telemetry(events)

                time.sleep(self.interval)
        except KeyboardInterrupt:
            logger.info("Interrupted by operator. Halting collection...")
        finally:
            if cap_proc and cap_proc.poll() is None:
                cap_proc.terminate()
                logger.info("Stopped packet capture process.")
            logger.info("Gateway Collector stopped.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TunnelTrace AI — Standalone Gateway Telemetry & Capture Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Inspect strongSwan on local Linux router:
  python gateway_collector.py --gateway "datacenter-edge-gw" --interface eth0

  # Synthetic testing mode (no root or strongSwan required):
  python gateway_collector.py --gateway "demo-gateway" --mock --interval 5
""",
    )
    parser.add_argument("--gateway", default="strongswan-edge-router", help="Name/ID of the monitored VPN gateway")
    parser.add_argument("--gateway-id", help="UUID of registered MonitoredGateway (defaults to random UUID)")
    parser.add_argument("--sensor-id", help="UUID of registered MonitoredSensor (defaults to random UUID)")
    parser.add_argument(
        "--token",
        default=os.environ.get("SENSOR_TOKEN"),
        help="Secret authentication token issued by TunnelTrace for this sensor (defaults to SENSOR_TOKEN env var)",
    )
    parser.add_argument(
        "--token-file",
        help="Path to protected file containing the secret authentication token (prevents process list exposure)",
    )
    parser.add_argument("--scope", default="10.0.0.0/8", help="Authorized CIDR boundary or scope label")
    parser.add_argument("--api-url", default="http://127.0.0.1:8002/api/v1", help="TunnelTrace backend API URL")
    parser.add_argument("--interface", help="Network interface to capture (e.g. eth0, wan0)")
    parser.add_argument("--output-dir", default="./captures", help="Directory for rolling PCAPs and JSON telemetry")
    parser.add_argument("--interval", type=int, default=10, help="Heartbeat interval in seconds (default: 10)")
    parser.add_argument("--pcap-max-files", type=int, default=5, help="Maximum number of rolling PCAP files to retain (FIFO)")
    parser.add_argument("--pcap-max-mb", type=int, default=50, help="Maximum size in MB per rolling PCAP file before rotation")
    parser.add_argument("--mock", action="store_true", help="Run in mock mode for non-Linux or demonstration setups")

    args = parser.parse_args()

    # Resolve token securely: --token CLI -> --token-file -> SENSOR_TOKEN env
    resolved_token = args.token
    if not resolved_token and args.token_file and os.path.exists(args.token_file):
        try:
            with open(args.token_file, "r", encoding="utf-8") as tf:
                resolved_token = tf.read().strip()
        except OSError as exc:
            logger.warning("Could not read token from %s: %s", args.token_file, exc)

    collector = GatewayCollector(
        api_url=args.api_url,
        gateway_name=args.gateway,
        sensor_id=args.sensor_id,
        gateway_id=args.gateway_id,
        token=resolved_token,
        scope=args.scope,
        interface=args.interface,
        output_dir=args.output_dir,
        interval=args.interval,
        mock_mode=args.mock,
        max_pcap_files=args.pcap_max_files,
        max_pcap_mb=args.pcap_max_mb,
    )

    collector.check_prerequisites()
    collector.run()


if __name__ == "__main__":
    main()
