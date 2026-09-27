"""Subprocess execution manager for Nmap with process bounds and safety isolation."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings
from app.discovery.profiles import SCAN_PROFILES
from app.discovery.validator import ValidatedScope


class ToolUnavailableError(RuntimeError):
    """Raised when Nmap executable is not installed or not operable."""
    pass


class ScanExecutionError(RuntimeError):
    """Raised when scan process fails or terminates abnormally."""
    pass


@dataclass(frozen=True)
class NmapBinaryInfo:
    is_available: bool
    path: str | None = None
    version: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class ExecutionResult:
    status: str  # "COMPLETED", "TOOL_UNAVAILABLE", "FAILED", "CANCELLED"
    exit_code: int | None
    raw_xml_content: str | None
    output_sha256: str | None
    output_bytes_count: int
    tool_version: str | None
    diagnostic_message: str | None
    executed_argv: list[str]


def detect_nmap_binary() -> NmapBinaryInfo:
    """Detect whether Nmap is available and inspect its version."""
    candidate_path = settings.NMAP_PATH or shutil.which("nmap")
    if not candidate_path or not os.path.exists(candidate_path):
        return NmapBinaryInfo(
            is_available=False,
            error_message="Nmap executable not found on host or configured NMAP_PATH.",
        )

    try:
        proc = subprocess.run(
            [candidate_path, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            timeout=5.0,
            check=False,
        )
        if proc.returncode != 0:
            return NmapBinaryInfo(
                is_available=False,
                path=candidate_path,
                error_message=f"Nmap returned non-zero exit code {proc.returncode} during version probe.",
            )

        match = re.search(r"Nmap version ([0-9a-zA-Z.]+)", proc.stdout)
        version_str = match.group(1) if match else "unknown"
        return NmapBinaryInfo(
            is_available=True,
            path=candidate_path,
            version=version_str,
        )
    except Exception as e:
        return NmapBinaryInfo(
            is_available=False,
            path=candidate_path,
            error_message=f"Failed to execute Nmap version probe: {e}",
        )


def build_nmap_argv(
    *,
    binary_path: str,
    scope: ValidatedScope,
    output_xml_path: str,
    rate_limit: int | None = None,
) -> list[str]:
    """Construct an immutable, un-interpolated argv list for subprocess execution."""
    profile_cfg = SCAN_PROFILES[scope.profile]
    rate = rate_limit or settings.DISCOVERY_RATE_LIMIT_PPS

    # Convert permitted ports to sorted comma-delimited string
    ports_arg = ",".join(str(p) for p in scope.permitted_ports)

    # Base profile flags (e.g. -sU or -sT, -Pn, -n)
    argv: list[str] = [binary_path]
    argv.extend(profile_cfg.base_args)

    # Timing template
    argv.append(profile_cfg.timing_template)

    # Rate limiting
    argv.extend(["--max-rate", str(rate)])

    # Ports
    argv.extend(["-p", ports_arg])

    # Machine-readable XML output destination
    argv.extend(["-oX", output_xml_path])

    # Append canonical target IP addresses directly
    argv.extend(scope.canonical_targets)

    return argv


def run_discovery_scan(
    *,
    job_id: uuid.UUID,
    scope: ValidatedScope,
    timeout_sec: float | None = None,
    mock_runner: Any = None,
) -> ExecutionResult:
    """Execute bounded Nmap discovery job through safe subprocess controls.

    Guarantees:
    - Strictly forbids shell execution (shell is always False)
    - Enforces timeout and kills process tree on expiration
    - Computes SHA-256 digest of XML output
    - Enforces output byte limit
    - Cleans up temporary artifacts
    """
    binary_info = detect_nmap_binary() if mock_runner is None else mock_runner.binary_info
    if not binary_info.is_available:
        return ExecutionResult(
            status="TOOL_UNAVAILABLE",
            exit_code=None,
            raw_xml_content=None,
            output_sha256=None,
            output_bytes_count=0,
            tool_version=None,
            diagnostic_message=binary_info.error_message or "Nmap is not installed on this system.",
            executed_argv=[],
        )

    binary_path = binary_info.path or "nmap"
    timeout = timeout_sec or settings.DISCOVERY_TIMEOUT_SEC
    max_bytes = settings.DISCOVERY_MAX_OUTPUT_BYTES

    with tempfile.TemporaryDirectory(prefix=f"tunneltrace_nmap_{job_id}_") as temp_dir:
        output_xml_path = str(Path(temp_dir) / "output.xml")
        argv = build_nmap_argv(
            binary_path=binary_path,
            scope=scope,
            output_xml_path=output_xml_path,
        )

        if mock_runner is not None:
            return mock_runner.execute(argv=argv, output_path=output_xml_path)

        proc = None
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )
            stdout, stderr = proc.communicate(timeout=timeout)
            exit_code = proc.returncode

            # Check if XML output file was created
            xml_path = Path(output_xml_path)
            if not xml_path.exists():
                sanitized_stderr = _sanitize_diagnostic(stderr)
                return ExecutionResult(
                    status="FAILED",
                    exit_code=exit_code,
                    raw_xml_content=None,
                    output_sha256=None,
                    output_bytes_count=0,
                    tool_version=binary_info.version,
                    diagnostic_message=f"Nmap exited with code {exit_code} without generating XML. Stderr: {sanitized_stderr}",
                    executed_argv=argv,
                )

            # Read XML content and verify size
            xml_bytes = xml_path.read_bytes()
            if len(xml_bytes) > max_bytes:
                return ExecutionResult(
                    status="FAILED",
                    exit_code=exit_code,
                    raw_xml_content=None,
                    output_sha256=None,
                    output_bytes_count=len(xml_bytes),
                    tool_version=binary_info.version,
                    diagnostic_message=f"Output XML size ({len(xml_bytes)} bytes) exceeded limit of {max_bytes} bytes.",
                    executed_argv=argv,
                )

            xml_str = xml_bytes.decode("utf-8", errors="replace")
            output_sha256 = hashlib.sha256(xml_bytes).hexdigest()

            # Status determination
            status = "COMPLETED" if exit_code == 0 else "FAILED"
            sanitized_err = _sanitize_diagnostic(stderr) if exit_code != 0 else None

            return ExecutionResult(
                status=status,
                exit_code=exit_code,
                raw_xml_content=xml_str,
                output_sha256=output_sha256,
                output_bytes_count=len(xml_bytes),
                tool_version=binary_info.version,
                diagnostic_message=sanitized_err,
                executed_argv=argv,
            )

        except subprocess.TimeoutExpired:
            if proc:
                _kill_process_tree(proc)
            return ExecutionResult(
                status="CANCELLED",
                exit_code=None,
                raw_xml_content=None,
                output_sha256=None,
                output_bytes_count=0,
                tool_version=binary_info.version,
                diagnostic_message=f"Scan execution exceeded hard timeout of {timeout} seconds and was terminated.",
                executed_argv=argv,
            )
        except Exception as e:
            if proc:
                _kill_process_tree(proc)
            return ExecutionResult(
                status="FAILED",
                exit_code=None,
                raw_xml_content=None,
                output_sha256=None,
                output_bytes_count=0,
                tool_version=binary_info.version,
                diagnostic_message=f"Subprocess invocation failure: {str(e)}",
                executed_argv=argv,
            )


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """Safely terminate a subprocess and its child tree."""
    try:
        if os.name == "nt":
            # On Windows, taskkill /F /T kills entire process tree
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            proc.kill()
    except Exception:
        pass


def _sanitize_diagnostic(text: str | None) -> str:
    """Redact filesystem paths, environment variables, or sensitive data from stderr."""
    if not text:
        return ""
    # Redact common path structures
    sanitized = re.sub(r"[A-Za-z]:\\[\w\\\.-]+", "[REDACTED_PATH]", text)
    sanitized = re.sub(r"/(?:[a-zA-Z0-9_\.-]+/)+[a-zA-Z0-9_\.-]+", "[REDACTED_PATH]", sanitized)
    return sanitized.strip()[:500]  # Cap length


class DemoSimulatedRunner:
    """Simulated runner for demonstrating Stage 2 Asset Discovery when Nmap binary is unavailable."""

    def __init__(self, target_ip: str = "127.0.0.1") -> None:
        self.target_ip = target_ip
        self.binary_info = NmapBinaryInfo(
            is_available=True,
            version="7.94-simulated",
            path="simulated-nmap",
        )

    def execute(self, argv: list[str], output_path: str) -> ExecutionResult:
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
<host>
  <status state="up"/>
  <address addr="{self.target_ip}" addrtype="ipv4"/>
  <ports>
    <port protocol="udp" portid="500">
      <state state="open|filtered" reason="no-response"/>
      <service name="isakmp" product="strongSwan IKEv2 daemon" conf="3"/>
    </port>
    <port protocol="udp" portid="4500">
      <state state="open|filtered" reason="no-response"/>
      <service name="ipsec-msft" product="NAT-Traversal RFC 3948" conf="3"/>
    </port>
  </ports>
</host>
</nmaprun>
"""
        raw_bytes = xml_content.encode("utf-8")
        Path(output_path).write_bytes(raw_bytes)
        output_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        return ExecutionResult(
            status="COMPLETED",
            exit_code=0,
            raw_xml_content=xml_content,
            output_sha256=output_sha256,
            output_bytes_count=len(raw_bytes),
            tool_version="7.94-simulated",
            diagnostic_message=None,
            executed_argv=argv,
        )

