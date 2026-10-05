"""Hardened unprivileged TShark subprocess execution and output streaming."""

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.errors import ParserError
from app.protocol.tshark.binary import get_toolchain

logger = logging.getLogger(__name__)

# Standard display filter restricting dissection strictly to IPsec traffic families
IPSEC_DISPLAY_FILTER = "udp.port == 500 or udp.port == 4500 or esp or ah"


class TSharkProcessRunner:
    """Executes TShark in an unprivileged, isolated sandbox with strict bounds."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.toolchain = get_toolchain()

    def run_dissection(
        self,
        pcap_path: Path | str,
        display_filter: str = IPSEC_DISPLAY_FILTER,
        timeout_sec: float | None = None,
        allow_fallback: bool = True,
        max_packets: int | None = None,
    ) -> list[dict[str, Any]]:
        """Execute TShark on the target PCAP and return parsed frame layer records.

        Security & Safety Invariants:
        - shell=False argument vectors exclusively.
        - -n disables all DNS/hostname network resolution.
        - Sanitized environment stripping SSLKEYLOGFILE and Wireshark user configs.
        - Hard execution timeout preventing pathological parser hangs.
        - Bounded stderr capture.

        Args:
            pcap_path: Path to capture file.
            display_filter: Wireshark display filter expression.
            timeout_sec: Maximum wall-clock execution time before termination.

        Returns:
            List of parsed packet dictionaries containing frame layers.

        Raises:
            ParserError: If TShark segfaults, times out, or outputs malformed data.
        """
        pcap = Path(pcap_path)
        if not pcap.exists():
            raise ParserError(f"Capture file not found: {pcap}", code="CAPTURE_NOT_FOUND")

        timeout = timeout_sec or self.settings.TSHARK_TIMEOUT_SEC

        # Arguments:
        # -r <file>: read capture
        # -n: disable network name resolution
        # -Y <filter>: apply display filter
        # -T json: output structured JSON
        # --no-duplicate-keys: merge duplicate keys into lists
        args = [
            "-r",
            str(pcap),
            "-n",
            "-Y",
            display_filter,
            "-T",
            "json",
            "--no-duplicate-keys",
        ]
        if max_packets is not None:
            args.extend(["-c", str(max_packets)])

        cmd = self.toolchain.resolve_command("tshark", args)

        # Sanitize execution environment
        clean_env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("WIRESHARK_")
            and k not in ("SSLKEYLOGFILE", "SSLKEYLOG", "KEYLOGFILE")
        }
        clean_env["LC_ALL"] = "C.UTF-8"

        start_time = time.perf_counter()
        logger.debug(f"Starting unprivileged TShark dissection on '{pcap.name}' (timeout: {timeout}s)")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                env=clean_env,
            )
        except subprocess.TimeoutExpired as exc:
            logger.error(f"TShark timed out after {timeout} seconds on '{pcap.name}'")
            raise ParserError(
                f"TShark parser timed out after {timeout} seconds.",
                code="PARSER_TIMEOUT",
                details={"timeout_sec": timeout},
            ) from exc
        except Exception as exc:
            logger.error(f"TShark process execution error: {exc}")
            raise ParserError(
                f"Failed to execute TShark subprocess: {exc}",
                code="PARSER_FAILED",
            ) from exc

        duration = time.perf_counter() - start_time
        logger.debug(
            f"TShark completed in {duration:.3f}s with exit code {proc.returncode} "
            f"(stdout: {len(proc.stdout)} bytes)"
        )

        # TShark exit code 0 is normal. If 1 or 2, check if output was generated or fatal error.
        if proc.returncode != 0 and not proc.stdout.strip():
            stderr_preview = proc.stderr[:500] if proc.stderr else "unknown"
            logger.error(f"TShark failed (exit {proc.returncode}): {stderr_preview}")
            raise ParserError(
                f"TShark dissection failed with code {proc.returncode}: {stderr_preview}",
                code="PARSER_FAILED",
                details={"exit_code": proc.returncode, "stderr": stderr_preview},
            )

        output_str = proc.stdout.strip()
        data: list[dict[str, Any]] = []
        if output_str:
            try:
                parsed = json.loads(output_str)
                if isinstance(parsed, list):
                    data = parsed
                elif isinstance(parsed, dict):
                    data = [parsed]
            except json.JSONDecodeError as exc:
                logger.error(f"TShark JSON decode error: {exc}. Output prefix: {output_str[:200]}")
                raise ParserError(
                    "TShark produced malformed JSON output.",
                    code="PARSER_OUTPUT_INVALID",
                    details={"error": str(exc)},
                ) from exc

        if not data:
            # Valid capture, but primary IPsec filter matched 0 packets.
            # Run adaptive fallback for protocol discrimination (WireGuard, OpenVPN, ICMP, cleartext, etc.)
            if allow_fallback and display_filter == IPSEC_DISPLAY_FILTER:
                logger.info(
                    f"IPsec filter matched 0 packets in '{pcap.name}'. Running adaptive fallback for protocol discrimination."
                )
                return self.run_dissection(
                    pcap_path,
                    display_filter="ip or ipv6",
                    timeout_sec=timeout_sec or 120.0,
                    allow_fallback=False,
                    max_packets=5000,
                )
            return []

        return data
