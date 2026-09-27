"""
TunnelTrace AI - Testbed Experiment Runner
==========================================
End-to-end automated orchestrator executing real, isolated IPsec testbed scenarios.
Combines topology creation, strongSwan orchestration, netem impairment, packet capture,
traffic probing, XFRM state verification, provenance manifest creation, and safe teardown.
"""

import hashlib
import os
import re
from typing import Optional, Dict, Any, List
import json
import time
import secrets
from datetime import datetime, timezone

from lab.scenarios.schema import ExpectedOutcome, ScenarioDefinition, TopologyType, IPVersion
from lab.scenarios.loader import ScenarioLoader
from lab.agent.operations.runner import SystemRunner
from lab.agent.doctor import EnvironmentDoctor
from lab.agent.cleanup.tracker import LabResourceTracker
from lab.agent.topology.orchestrator import TopologyOrchestrator
from lab.agent.strongswan.config_generator import SwanctlConfigGenerator
from lab.agent.strongswan.manager import StrongSwanManager
from lab.agent.netem.manager import NetemManager
from lab.agent.capture.manager import CaptureManager
from lab.agent.models.manifest import RunManifest, CaptureArtifact


def sanitize_error_text(err: Any) -> str:
    """Sanitize error messages to prevent leaking PSKs, private keys, or passwords."""
    text = str(err)
    text = re.sub(r'(secret\s*=\s*["\'])([^"\']+)(["\'])', r'\1[REDACTED_SECRET]\3', text, flags=re.IGNORECASE)
    text = re.sub(r'([a-fA-F0-9]{32,})', lambda m: f"{m.group(1)[:4]}...[REDACTED]...{m.group(1)[-4:]}", text)
    text = re.sub(r'-----BEGIN [A-Z ]+KEY-----.*?-----END [A-Z ]+KEY-----', '[REDACTED_PRIVATE_KEY]', text, flags=re.DOTALL)
    text = re.sub(r'((?:password|psk|secret|token)\s*[:=]\s*)([^\s,;&"\']+)', r'\1[REDACTED]', text, flags=re.IGNORECASE)
    return text


class ExperimentRunner:
    """Executes end-to-end IPsec testbed experiments with zero fabrication."""

    def __init__(
        self,
        runner: Optional[SystemRunner] = None,
        storage_base_dir: str = "storage/lab/runs"
    ) -> None:
        self.runner = runner or SystemRunner()
        self.doctor = EnvironmentDoctor(self.runner)
        self.storage_base_dir = storage_base_dir
        os.makedirs(self.storage_base_dir, exist_ok=True)

    def execute_scenario(
        self,
        scenario: ScenarioDefinition,
        run_id_prefix: str = "tt",
        cleanup_after: bool = True,
        parent_run_id: Optional[str] = None,
        replay_mode: Optional[str] = None,
    ) -> RunManifest:
        """
        Executes a validated scenario end-to-end inside Linux namespaces.
        Generates real traffic, captures encrypted and plaintext packets,
        verifies kernel XFRM state, writes immutable manifest, and cleans up.
        """
        start_time = datetime.now(timezone.utc)
        run_id = f"{run_id_prefix}-{int(start_time.timestamp())}-{secrets.token_hex(3)}"
        
        # Target local storage directory
        run_storage_dir = os.path.abspath(os.path.join(self.storage_base_dir, run_id))
        os.makedirs(run_storage_dir, exist_ok=True)
        captures_storage_dir = os.path.join(run_storage_dir, "captures")
        os.makedirs(captures_storage_dir, exist_ok=True)
        logs_storage_dir = os.path.join(run_storage_dir, "logs")
        os.makedirs(logs_storage_dir, exist_ok=True)

        tracker = LabResourceTracker(self.runner)
        manifest = RunManifest(
            run_id=run_id,
            scenario_id=scenario.scenario_id,
            scenario_version=scenario.version,
            topology_type=scenario.topology.value,
            started_at_utc=start_time.isoformat(),
            scenario_sha256=scenario.sha256_hash or "",
            evidence_directory=run_storage_dir,
            parent_run_id=parent_run_id,
            replay_mode=replay_mode,
        )

        # 1. Acquire Run Mutex Lock
        tracker.acquire_lock(run_id)

        try:
            # 2. Pre-flight Environment Doctor
            doc_report = self.doctor.check_environment()
            manifest.environment = doc_report
            if not doc_report.get("ready"):
                manifest.validation_status = "BLOCKED"
                manifest.status_summary = f"Preflight checks failed: {doc_report.get('checks')}"
                return manifest

            # 3. Setup Network Namespaces & Topology
            orchestrator = TopologyOrchestrator(self.runner, tracker)
            if scenario.topology == TopologyType.TUNNEL_SITE_TO_SITE:
                topo = orchestrator.setup_tunnel_topology(run_id, scenario.ip_version)
            else:
                topo = orchestrator.setup_transport_topology(run_id, scenario.ip_version)

            manifest.namespaces = tracker.tracked_namespaces
            manifest.interfaces = tracker.tracked_interfaces
            manifest.address_plan = topo.address_plan

            # 4. Generate strongSwan & swanctl Configurations and Start Daemons
            # Daemons run strictly inside isolated network namespaces with private /var/run tmpfs mounts
            sw_mgr = StrongSwanManager(run_id=run_id, tracker=tracker, runner=self.runner)
            # Generate a secure, runtime-only ephemeral pre-shared key (never written to manifest or git)
            lab_psk = secrets.token_hex(32)

            peer_runtimes: Dict[str, Dict[str, str]] = {}
            if scenario.topology == TopologyType.TUNNEL_SITE_TO_SITE:
                peers_to_run = [("gw_a", topo.ns_gw_a), ("gw_b", topo.ns_gw_b)]
            else:
                peers_to_run = [("peer_a", topo.ns_peer_a), ("peer_b", topo.ns_peer_b)]

            for peer_role, peer_ns in peers_to_run:
                peer_dir, vici_sock, cfg_hash = sw_mgr.prepare_peer_runtime(
                    peer_role=peer_role,
                    namespace=peer_ns,
                    scenario=scenario,
                    address_plan=topo.address_plan,
                    psk_secret=lab_psk
                )
                sw_mgr.start_charon(peer_ns, peer_dir)
                sw_mgr.load_configuration(peer_ns, peer_dir, vici_sock)
                peer_runtimes[peer_role] = {
                    "netns": peer_ns,
                    "peer_dir": peer_dir,
                    "vici_socket": vici_sock,
                    "config_hash": cfg_hash
                }

            # Record non-secret configuration hashes and canonical redacted digest
            manifest.config_hashes = {
                p: item["config_hash"] for p, item in peer_runtimes.items()
            }
            manifest.requested_configuration = scenario.model_dump()
            from app.replay.redaction import compute_canonical_config_digest
            _, cfg_digest = compute_canonical_config_digest(manifest.requested_configuration)
            manifest.canonical_config_digest = cfg_digest

            # 5. Apply Network Impairment (tc/netem) if configured
            netem_mgr = NetemManager(self.runner, tracker)
            if scenario.netem.has_impairment():
                netem_iface = "br-wan"
                netem_mgr.apply_impairment(netem_iface, scenario.netem, netns=topo.ns_wan)

            # 6. Start Packet Captures
            cap_mgr = CaptureManager(self.runner, tracker)
            wan_pcap_local = os.path.join(captures_storage_dir, "wan_encrypted.pcap")
            # In Linux/WSL, capture on the WAN bridge in the WAN namespace
            cap_mgr.start_capture(
                capture_id=f"{run_id}-wan",
                interface="br-wan",
                output_pcap_path=f"/tmp/{run_id}/captures/wan_encrypted.pcap",
                netns=topo.ns_wan,
                bpf_filter=CaptureManager.WAN_IPSEC_FILTER
            )

            # Optional plaintext capture on client
            if scenario.topology == TopologyType.TUNNEL_SITE_TO_SITE:
                cap_mgr.start_capture(
                    capture_id=f"{run_id}-client-plaintext",
                    interface="v-cli-gw",
                    output_pcap_path=f"/tmp/{run_id}/captures/client_plaintext.pcap",
                    netns=topo.ns_client,
                    bpf_filter=CaptureManager.PLAINTEXT_FILTER
                )

            # 7. Initiate IPsec Connection
            init_peer = "gw_a" if scenario.topology == TopologyType.TUNNEL_SITE_TO_SITE else "peer_a"
            init_info = peer_runtimes[init_peer]
            
            # Initiate child-sa
            init_res = sw_mgr.initiate_tunnel(
                namespace=init_info["netns"],
                vici_socket=init_info["vici_socket"],
                child_name="child-sa"
            )

            # Poll for SA establishment (up to 10 seconds)
            sa_established = False
            for _ in range(10):
                sa_status = sw_mgr.query_sa_status(init_info["netns"], init_info["vici_socket"])
                if "ESTABLISHED" in sa_status or "INSTALLED" in sa_status:
                    sa_established = True
                    break
                time.sleep(1.0)

            manifest.sa_established = sa_established

            # 8. Generate Control Traffic Across Protected Path
            ping_passed = False
            if scenario.topology == TopologyType.TUNNEL_SITE_TO_SITE:
                target_ip = topo.address_plan["server_ip"]
                src_netns = topo.ns_client
            else:
                target_ip = topo.address_plan["peer_b_wan_ip"]
                src_netns = topo.ns_peer_a

            # Execute ICMP echo
            ping_cmd = "ping6" if scenario.ip_version == IPVersion.IPV6 else "ping"
            ping_res = self.runner.run_raw(
                [ping_cmd, "-c", "4", "-W", "2", target_ip],
                netns=src_netns,
                check=False
            )
            ping_passed = (ping_res.returncode == 0)
            manifest.traffic_probe_passed = ping_passed

            # 9. Record Runtime State & XFRM Policies
            runtime_observations: Dict[str, Any] = {
                "initiate_output": (init_res.stdout + "\n" + init_res.stderr).strip(),
                "sa_status": {
                    peer: sw_mgr.query_sa_status(item["netns"], item["vici_socket"])
                    for peer, item in peer_runtimes.items()
                },
                "xfrm_state": {},
                "xfrm_policy": {},
                "ping_output": ping_res.stdout
            }
            for peer, item in peer_runtimes.items():
                runtime_observations["xfrm_state"][peer] = sw_mgr.query_xfrm_state(item["netns"])
                runtime_observations["xfrm_policy"][peer] = sw_mgr.query_xfrm_policy(item["netns"])

            manifest.observed_runtime_state = runtime_observations


            # 11. Stop Captures & Collect Evidence
            cap_results = cap_mgr.stop_all()
            for cap in cap_results:
                # Copy PCAP from Linux /tmp into run storage directory
                src_pcap = cap["wsl_path"]
                dest_filename = os.path.basename(src_pcap)
                dest_pcap = os.path.join(captures_storage_dir, dest_filename)
                
                # Copy via runner
                self.runner.run_raw(["cp", src_pcap, self.runner._to_wsl_path(dest_pcap)])
                
                manifest.captures.append(CaptureArtifact(
                    capture_id=cap["capture_id"],
                    role="WAN_ENCRYPTED" if "wan" in cap["capture_id"] else "PLAINTEXT",
                    interface=cap["interface"],
                    netns=cap["netns"],
                    output_path=dest_pcap,
                    file_size_bytes=cap.get("file_size_bytes", 0),
                    packet_count=cap.get("packet_count", 0),
                    sha256=cap.get("sha256", ""),
                    bpf_filter=cap.get("bpf_filter")
                ))

            # 12. Determine Final Validation Status against ExpectedOutcome Contract
            wan_cap = next((c for c in manifest.captures if "wan" in c.capture_id), None)
            has_wan_packets = wan_cap and wan_cap.packet_count > 0
            exp_outcome = getattr(scenario, "expected_outcome", ExpectedOutcome.SUCCESS)

            if exp_outcome == ExpectedOutcome.EXPECTED_REJECTION:
                # Deliberate misconfiguration / proposal mismatch
                if not sa_established:
                    manifest.validation_status = "VALIDATED"
                    manifest.status_summary = (
                        f"Expected rejection verified: SA failed to establish as predicted "
                        f"(reason: {scenario.expected_failure_reason or 'NO_PROPOSAL_CHOSEN'})."
                    )
                else:
                    manifest.validation_status = "FAILED"
                    manifest.status_summary = (
                        "Negative test failed: IPsec SA unexpectedly established despite mismatched proposals."
                    )
            elif exp_outcome == ExpectedOutcome.EXPECTED_NEGATIVE:
                # Deliberate weak cipher / legacy suite in isolated lab
                if sa_established and ping_passed and has_wan_packets:
                    manifest.validation_status = "VALIDATED"
                    manifest.status_summary = (
                        f"Isolated negative test verified: Weak suite established in lab namespace: {scenario.crypto_profile.value}."
                    )
                elif sa_established and ping_passed:
                    manifest.validation_status = "PARTIAL"
                    manifest.status_summary = "Negative test: SA established and traffic passed, but WAN capture had 0 packets."
                else:
                    manifest.validation_status = "FAILED"
                    manifest.status_summary = f"Negative test failed to complete: SA={sa_established}, Ping={ping_passed}"
            elif exp_outcome == ExpectedOutcome.UNSUPPORTED_ENVIRONMENT:
                manifest.validation_status = "BLOCKED"
                manifest.status_summary = f"Environment unsupported: {scenario.expected_failure_reason or 'Feature disabled in strongSwan build'}"
            else:
                # ExpectedOutcome.SUCCESS
                if sa_established and ping_passed and has_wan_packets:
                    manifest.validation_status = "VALIDATED"
                    manifest.status_summary = "IPsec SA established, ping crossed tunnel successfully, and WAN PCAP captured genuine IPsec packets."
                elif sa_established and ping_passed:
                    manifest.validation_status = "PARTIAL"
                    manifest.status_summary = "IPsec SA established and traffic passed, but WAN capture had 0 packets."
                else:
                    manifest.validation_status = "FAILED"
                    manifest.status_summary = f"Establishment failed: SA={sa_established}, Ping={ping_passed}"

        except Exception as exc:
            manifest.validation_status = "FAILED"
            manifest.status_summary = f"Execution exception: {sanitize_error_text(exc)}"
            raise exc

        finally:
            # 13. Idempotent Teardown & Lock Release
            end_time = datetime.now(timezone.utc)
            manifest.ended_at_utc = end_time.isoformat()
            manifest.duration_seconds = round((end_time - start_time).total_seconds(), 2)

            # Seal manifest with SHA-256 digest
            manifest_json = manifest.model_dump_json(exclude={"manifest_sha256"}, indent=2)
            manifest.manifest_sha256 = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()

            # Save manifest to disk
            manifest_path = os.path.join(run_storage_dir, "manifest.json")
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(manifest.model_dump_json(indent=2))

            if cleanup_after:
                tracker.clean_current_run()
                tracker.release_lock()

        return manifest

    def replay_scenario(
        self,
        scenario: ScenarioDefinition,
        parent_manifest: RunManifest,
        run_id_prefix: str = "tt-replay",
        cleanup_after: bool = True,
    ) -> tuple[RunManifest, Dict[str, Any]]:
        """Executes a controlled lab replay of an existing versioned scenario.

        Enforces:
        - Parent-child lineage binding (parent_run_id recorded in child manifest).
        - Environment and tool compatibility verification via EnvironmentDoctor.
        - Semantic assertion comparison against parent run (evaluating SA state,
          traffic transit, and validation status rather than requiring byte-identical PCAPs).
        """
        from app.replay.comparator import ScenarioReplayComparator

        # Preflight doctor check
        doc_report = self.doctor.check_environment()
        if not doc_report.get("ready"):
            # Record environment mismatch truthfully without fabricating execution
            start_time = datetime.now(timezone.utc)
            run_id = f"{run_id_prefix}-{int(start_time.timestamp())}-{secrets.token_hex(3)}"
            child_manifest = RunManifest(
                run_id=run_id,
                scenario_id=scenario.scenario_id,
                scenario_version=scenario.version,
                topology_type=scenario.topology.value,
                started_at_utc=start_time.isoformat(),
                ended_at_utc=start_time.isoformat(),
                duration_seconds=0.0,
                parent_run_id=parent_manifest.run_id,
                replay_mode="SCENARIO_REPLAY",
                environment=doc_report,
                environment_compatibility={
                    "is_compatible": False,
                    "mismatches": ["Missing required testbed tools or Linux netns/kernel execution."]
                },
                scenario_sha256=scenario.sha256_hash or parent_manifest.scenario_sha256 or "unknown",
                validation_status="BLOCKED",
                status_summary=f"Scenario replay blocked: Environment prerequisites not met ({doc_report.get('checks')})",
            )
            cmp_res = ScenarioReplayComparator.compare_manifests(
                parent_manifest.model_dump(),
                child_manifest.model_dump(),
            )
            child_manifest.semantic_assertions = cmp_res
            return child_manifest, cmp_res

        # Execute in lab
        child_manifest = self.execute_scenario(
            scenario=scenario,
            run_id_prefix=run_id_prefix,
            cleanup_after=cleanup_after,
            parent_run_id=parent_manifest.run_id,
            replay_mode="SCENARIO_REPLAY",
        )
        cmp_res = ScenarioReplayComparator.compare_manifests(
            parent_manifest.model_dump(),
            child_manifest.model_dump(),
        )
        child_manifest.semantic_assertions = cmp_res
        return child_manifest, cmp_res

    def execute_workload_session(
        self,
        scenario: ScenarioDefinition,
        workload_profile: Any,  # WorkloadProfile
        run_id_prefix: str = "tt-ds",
        cleanup_after: bool = True,
        retain_plaintext: bool = False,
    ) -> RunManifest:
        """Execute an independent dataset session combining strongSwan IPsec with a typed application workload.

        Enforces:
        - Point A plaintext capture (temporary verification) + Point B WAN encrypted capture (model input).
        - Privacy policy: plaintext capture is purged unless retain_plaintext=True.
        - Workload execution tracking and success confirmation.
        """
        from lab.workloads import get_generator_for_profile

        start_time = datetime.now(timezone.utc)
        run_id = f"{run_id_prefix}-{int(start_time.timestamp())}-{secrets.token_hex(3)}"

        run_storage_dir = os.path.abspath(os.path.join(self.storage_base_dir, run_id))
        os.makedirs(run_storage_dir, exist_ok=True)
        captures_storage_dir = os.path.join(run_storage_dir, "captures")
        os.makedirs(captures_storage_dir, exist_ok=True)

        tracker = LabResourceTracker(self.runner)
        manifest = RunManifest(
            run_id=run_id,
            scenario_id=scenario.scenario_id,
            scenario_version=scenario.version,
            topology_type=scenario.topology.value,
            started_at_utc=start_time.isoformat(),
            scenario_sha256=scenario.sha256_hash or "",
            evidence_directory=run_storage_dir,
            workload_profile=workload_profile.model_dump() if hasattr(workload_profile, "model_dump") else None,
        )

        tracker.acquire_lock(run_id)
        generator = None

        try:
            doc_report = self.doctor.check_environment()
            manifest.environment = doc_report
            if not doc_report.get("ready"):
                manifest.validation_status = "BLOCKED"
                manifest.status_summary = f"Preflight checks failed: {doc_report.get('checks')}"
                return manifest

            orchestrator = TopologyOrchestrator(self.runner, tracker)
            if scenario.topology == TopologyType.TUNNEL_SITE_TO_SITE:
                topo = orchestrator.setup_tunnel_topology(run_id, scenario.ip_version)
            else:
                topo = orchestrator.setup_transport_topology(run_id, scenario.ip_version)

            manifest.namespaces = tracker.tracked_namespaces
            manifest.interfaces = tracker.tracked_interfaces
            manifest.address_plan = topo.address_plan

            sw_mgr = StrongSwanManager(run_id=run_id, tracker=tracker, runner=self.runner)
            lab_psk = secrets.token_hex(32)

            peer_runtimes: Dict[str, Dict[str, str]] = {}
            if scenario.topology == TopologyType.TUNNEL_SITE_TO_SITE:
                peers_to_run = [("gw_a", topo.ns_gw_a), ("gw_b", topo.ns_gw_b)]
            else:
                peers_to_run = [("peer_a", topo.ns_peer_a), ("peer_b", topo.ns_peer_b)]

            for peer_role, peer_ns in peers_to_run:
                peer_dir, vici_sock, cfg_hash = sw_mgr.prepare_peer_runtime(
                    peer_role=peer_role,
                    namespace=peer_ns,
                    scenario=scenario,
                    address_plan=topo.address_plan,
                    psk_secret=lab_psk,
                )
                sw_mgr.start_charon(peer_ns, peer_dir)
                sw_mgr.load_configuration(peer_ns, peer_dir, vici_sock)
                peer_runtimes[peer_role] = {
                    "netns": peer_ns,
                    "peer_dir": peer_dir,
                    "vici_socket": vici_sock,
                    "config_hash": cfg_hash,
                }

            manifest.config_hashes = {p: item["config_hash"] for p, item in peer_runtimes.items()}
            manifest.requested_configuration = scenario.model_dump()

            netem_mgr = NetemManager(self.runner, tracker)
            if scenario.netem.has_impairment():
                netem_mgr.apply_impairment("br-wan", scenario.netem, netns=topo.ns_wan)

            # Start Dual Captures
            cap_mgr = CaptureManager(self.runner, tracker)

            # Point B: WAN Encrypted Capture
            cap_mgr.start_capture(
                capture_id=f"{run_id}-wan",
                interface="br-wan",
                output_pcap_path=f"/tmp/{run_id}/captures/wan_encrypted.pcap",
                netns=topo.ns_wan,
                bpf_filter=CaptureManager.WAN_IPSEC_FILTER,
            )

            # Point A: Plaintext Internal Capture
            plaintext_ns = topo.ns_client if scenario.topology == TopologyType.TUNNEL_SITE_TO_SITE else topo.ns_peer_a
            plaintext_iface = "v-cli-gw" if scenario.topology == TopologyType.TUNNEL_SITE_TO_SITE else "v-pa-wan"
            cap_mgr.start_capture(
                capture_id=f"{run_id}-plaintext",
                interface=plaintext_iface,
                output_pcap_path=f"/tmp/{run_id}/captures/plaintext.pcap",
                netns=plaintext_ns,
                bpf_filter=CaptureManager.PLAINTEXT_FILTER,
            )

            # Initiate IPsec Tunnel
            init_peer = "gw_a" if scenario.topology == TopologyType.TUNNEL_SITE_TO_SITE else "peer_a"
            init_info = peer_runtimes[init_peer]
            sw_mgr.initiate_tunnel(namespace=init_info["netns"], vici_socket=init_info["vici_socket"], child_name="child-sa")

            sa_established = False
            for _ in range(10):
                sa_status = sw_mgr.query_sa_status(init_info["netns"], init_info["vici_socket"])
                if "ESTABLISHED" in sa_status or "INSTALLED" in sa_status:
                    sa_established = True
                    break
                time.sleep(1.0)
            manifest.sa_established = sa_established

            # Execute Workload Generator
            workload_success = False
            if sa_established:
                if scenario.topology == TopologyType.TUNNEL_SITE_TO_SITE:
                    target_ip = topo.address_plan["server_ip"]
                    server_ns = topo.ns_server
                    client_ns = topo.ns_client
                else:
                    target_ip = topo.address_plan["peer_b_wan_ip"]
                    server_ns = topo.ns_peer_b
                    client_ns = topo.ns_peer_a

                generator = get_generator_for_profile(workload_profile, runner=self.runner)
                generator.start_server(server_ns, target_ip, workload_profile.target_port)

                time.sleep(0.3)
                workload_res = generator.run_client(
                    client_ns=client_ns,
                    target_ip=target_ip,
                    target_port=workload_profile.target_port,
                    duration_seconds=workload_profile.duration_seconds,
                    seed=workload_profile.random_seed,
                )
                manifest.workload_result = workload_res.model_dump()
                workload_success = workload_res.success
                manifest.traffic_probe_passed = workload_success
                generator.stop_server()

            # Record Runtime State & XFRM Policies
            runtime_obs: Dict[str, Any] = {
                "sa_status": {peer: sw_mgr.query_sa_status(item["netns"], item["vici_socket"]) for peer, item in peer_runtimes.items()},
                "xfrm_state": {peer: sw_mgr.query_xfrm_state(item["netns"]) for peer, item in peer_runtimes.items()},
                "xfrm_policy": {peer: sw_mgr.query_xfrm_policy(item["netns"]) for peer, item in peer_runtimes.items()},
            }
            manifest.observed_runtime_state = runtime_obs

            # Stop Captures & Collect Evidence
            cap_results = cap_mgr.stop_all()
            for cap in cap_results:
                src_pcap = cap["wsl_path"]
                dest_filename = os.path.basename(src_pcap)
                is_wan = "wan" in cap["capture_id"]

                if is_wan or retain_plaintext:
                    dest_pcap = os.path.join(captures_storage_dir, dest_filename)
                    self.runner.run_raw(["cp", src_pcap, self.runner._to_wsl_path(dest_pcap)])
                else:
                    # Privacy Policy: purge plaintext payload file, record non-sensitive metadata only
                    dest_pcap = "[PURGED_PER_PRIVACY_POLICY]"

                manifest.captures.append(CaptureArtifact(
                    capture_id=cap["capture_id"],
                    role="WAN_ENCRYPTED" if is_wan else "PLAINTEXT_INTERNAL",
                    interface=cap["interface"],
                    netns=cap["netns"],
                    output_path=dest_pcap,
                    file_size_bytes=cap.get("file_size_bytes", 0),
                    packet_count=cap.get("packet_count", 0),
                    sha256=cap.get("sha256", ""),
                    bpf_filter=cap.get("bpf_filter"),
                ))

            # Determine Validation Status
            wan_cap = next((c for c in manifest.captures if "wan" in c.capture_id), None)
            has_wan = wan_cap and wan_cap.packet_count > 0

            if sa_established and workload_success and has_wan:
                manifest.validation_status = "VALIDATED"
                manifest.status_summary = f"IPsec SA established, workload {workload_profile.workload_class.value} succeeded, WAN ESP captured."
            elif sa_established and workload_success:
                manifest.validation_status = "PARTIAL"
                manifest.status_summary = "SA established and workload succeeded, but WAN capture had 0 packets."
            else:
                manifest.validation_status = "FAILED"
                manifest.status_summary = f"Execution failed: SA={sa_established}, WorkloadSuccess={workload_success}"

        except Exception as exc:
            manifest.validation_status = "FAILED"
            manifest.status_summary = sanitize_error_text(f"Execution exception: {str(exc)}")
            raise exc

        finally:
            if generator is not None:
                generator.clean_up()

            end_time = datetime.now(timezone.utc)
            manifest.ended_at_utc = end_time.isoformat()
            manifest.duration_seconds = round((end_time - start_time).total_seconds(), 2)

            manifest_path = os.path.join(run_storage_dir, "manifest.json")
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(manifest.model_dump_json(indent=2))

            if cleanup_after:
                tracker.clean_current_run()
                tracker.release_lock()

        return manifest

