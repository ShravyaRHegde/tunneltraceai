"""Integration tests for Closed-Loop Remediation Runner and SAGA Rollback."""

from __future__ import annotations

import hashlib
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.capture import AnalysisRun, Capture
from app.db.models.remediation import (
    ConfigurationSnapshotModel,
    ConfigurationTwinModel,
    RemediationRunModel,
    RemediationVerificationClaimModel,
    RemediationVerificationModel,
)
from app.db.models.security import SecurityFindingModel
from app.integrations.privileged_agent.base import AgentStatus, AgentStatusResponse, PrivilegedAgentClient
from app.remediation.ir import ConfigurationIR, ConnectionConfigurationIR, TransformIR
from app.remediation.runner import ClosedLoopRemediationRunner
from lab.agent.cleanup.tracker import LabResourceTracker


class MockPrivilegedAgent(PrivilegedAgentClient):
    """Mock agent simulating controlled strongSwan testbed responses."""

    def __init__(self, should_fail_load: bool = False) -> None:
        self.should_fail_load = should_fail_load
        self.actions_called: list[str] = []

    async def get_status(self) -> AgentStatusResponse:
        return AgentStatusResponse(
            status=AgentStatus.UP,
            available=True,
            configured=True,
            endpoint="mock://lab",
            message="Mock Lab Ready",
        )

    async def ping(self) -> bool:
        return True

    async def execute_action(self, action: str, params: dict) -> dict:
        self.actions_called.append(action)

        if action == "VALIDATE_CONFIG":
            return {"valid": True, "connection_count": 1, "errors": []}

        elif action == "BACKUP_CONFIG":
            return {
                "backup_path": "/tmp/mock_backup.bak",
                "backup_sha256": "backup_sha256_mock_1234",
                "content": "connections {}",
            }

        elif action == "APPLY_CONFIG":
            return {
                "applied_path": params.get("target_path"),
                "applied_hash": params.get("expected_hash"),
                "success": True,
                "verified": True,
            }

        elif action == "RELOAD_STRONGSWAN":
            if self.should_fail_load and "RESTORE_BACKUP" not in self.actions_called:
                return {"load_success": False, "load_stdout": "Fatal syntax error in swanctl proposal"}
            return {"load_success": True, "load_stdout": "loaded 1 connection successfully"}

        elif action == "VERIFY_FRESH_SA":
            return {
                "fresh_sa_established": True,
                "observed_spis": ["c0ffee01", "c0ffee02"],
                "new_spis": ["c0ffee01", "c0ffee02"],
                "sa_status": "tunnel-gw-a: #1, ESTABLISHED, IKEv2, spi 0xc0ffee01",
            }

        elif action == "START_LIVE_CAPTURE":
            return {"status": "CAPTURING", "session_id": params.get("session_id")}

        elif action == "STOP_LIVE_CAPTURE":
            return {
                "status": "STOPPED",
                "pcap_path": "/tmp/mock.pcap",
                "sha256": "mock_pcap_sha256_1234567890abcdef",
                "file_size": 1024,
            }

        elif action == "RUN_REMEDIATION_WORKLOAD":
            return {"success": True, "packets_transmitted": 3, "packets_received": 3}

        elif action == "RESTORE_BACKUP":
            return {
                "restored": True,
                "verified": True,
                "target_path": params.get("target_path"),
                "restored_sha256": params.get("expected_hash"),
            }

        raise ValueError(f"Unhandled mock action: {action}")


@pytest.mark.asyncio
async def test_closed_loop_runner_successful_execution():
    """Verify SAGA execution: backup -> apply -> reload -> fresh SA -> workload -> capture -> verification."""
    mock_agent = MockPrivilegedAgent(should_fail_load=False)
    runner = ClosedLoopRemediationRunner(agent_client=mock_agent)

    # Mock DB Session
    db = MagicMock(spec=AsyncSession)

    analysis_id = uuid.uuid4()
    twin_id = uuid.uuid4()
    run_id = uuid.uuid4()
    proposal_hash = hashlib.sha256(b"mock_proposal").hexdigest()

    # Setup entities
    analysis_run = AnalysisRun(id=analysis_id, status="COMPLETED")
    hardened_snapshot = ConfigurationSnapshotModel(
        id=uuid.uuid4(),
        config_format="SWANCTL",
        config_content="connections { tt { version = 2 } }",
        config_hash=proposal_hash,
        normalized_ir={"connections": [{"name": "tt", "ike_version": 2}]},
    )
    twin = ConfigurationTwinModel(
        id=twin_id,
        analysis_id=analysis_id,
        hardened_snapshot_id=hardened_snapshot.id,
        observed_snapshot_id=uuid.uuid4(),
        proposal_hash=proposal_hash,
        projected_score=95.0,
        projected_score_delta=50.0,
        projected_regression_audit={
            "has_blocking_regressions": False,
            "proof_obligations": [
                {
                    "obligation_id": "obl-1",
                    "target_finding_id": "find-1",
                    "target_rule_id": "POL-NIST-001",
                    "target_rule_version": "1.0.0",
                    "root_cause_key": "CIPHER_DEPRECATED_DES",
                    "baseline_observed_fact_key": "ike_sa.encryption_algorithm",
                    "baseline_observed_value": "3DES",
                    "proposed_expected_value": "AES256-GCM",
                    "assertion_operator": "not_in_set",
                    "resolution_criteria": "3DES absent",
                    "non_resolution_criteria": "3DES persists",
                    "insufficient_evidence_criteria": "unobserved",
                }
            ],
        },
    )
    run = RemediationRunModel(
        id=run_id,
        twin_id=twin_id,
        proposal_hash=proposal_hash,
        status="CREATED",
    )

    finding = SecurityFindingModel(
        analysis_id=analysis_id,
        rule_id="POL-NIST-001",
        rule_version="1.0.0",
        profile_id="profile_nist_sp800_77",
        category="CRYPTOGRAPHY",
        severity="CRITICAL",
        title="3DES Prohibition",
        technical_description="3DES used",
        root_cause_key="CIPHER_DEPRECATED_DES",
        affected_entity_type="IKE_SA",
        affected_entity_id="sa-1",
        evidence_state="VERIFIED",
        remediation_directive="esp = aes256gcm16-ecp256!",
        record_hash="hash-1",
    )

    # Configure db execute responses
    async def _mock_execute(query):
        mock_result = MagicMock()
        query_str = str(query)
        if "remediation_runs" in query_str and "WHERE remediation_runs.id =" in query_str:
            mock_result.scalar_one_or_none.return_value = run
            mock_result.scalar_one.return_value = run
        elif "configuration_twins" in query_str:
            mock_result.scalar_one_or_none.return_value = twin
            mock_result.scalar_one.return_value = twin
        elif "configuration_snapshots" in query_str:
            mock_result.scalar_one_or_none.return_value = hardened_snapshot
            mock_result.scalar_one.return_value = hardened_snapshot
        elif "analysis_runs" in query_str:
            mock_result.scalar_one_or_none.return_value = analysis_run
            mock_result.scalar_one.return_value = analysis_run
        elif "security_findings" in query_str:
            if str(analysis_id) in query_str:
                mock_result.scalars.return_value.all.return_value = [finding]
            else:
                mock_result.scalars.return_value.all.return_value = []
        elif "protocol_observations" in query_str:
            mock_obs = MagicMock()
            mock_obs.field_name = "ike_sa.encryption_algorithm"
            mock_obs.protocol = "ike_sa"
            mock_obs.normalized_value = "AES256-GCM"
            mock_result.scalars.return_value.all.return_value = [mock_obs]
        else:
            mock_result.scalar_one_or_none.return_value = None
            mock_result.scalar_one.return_value = None
            mock_result.scalars.return_value.all.return_value = []
        return mock_result

    db.execute = AsyncMock(side_effect=_mock_execute)
    db.commit = AsyncMock()
    db.add = MagicMock()

    # Preflight Check
    preflight = await runner.run_preflight_checks(
        db=db,
        analysis_id=analysis_id,
        twin_id=twin_id,
        proposal_hash=proposal_hash,
    )
    assert preflight.is_ready is True
    assert preflight.status == "READY"

    # Patch LabResourceTracker to avoid host filesystem lock conflicts
    with (
        patch.object(LabResourceTracker, "acquire_lock") as mock_lock,
        patch.object(LabResourceTracker, "release_lock") as mock_unlock,
        patch("app.services.pipeline.execute_full_analysis_pipeline", new_callable=AsyncMock),
    ):
        result_run = await runner.execute_closed_loop_run(
            db=db,
            run_id=run_id,
            analysis_id=analysis_id,
            twin_id=twin_id,
            approved_proposal_hash=proposal_hash,
        )

        assert result_run.status == "COMPLETED"
        assert result_run.rollback_state == "NONE"
        mock_lock.assert_called_once()
        mock_unlock.assert_called_once()

        # Verify all SAGA steps were invoked in order
        assert "BACKUP_CONFIG" in mock_agent.actions_called
        assert "APPLY_CONFIG" in mock_agent.actions_called
        assert "RELOAD_STRONGSWAN" in mock_agent.actions_called
        assert "VERIFY_FRESH_SA" in mock_agent.actions_called
        assert "START_LIVE_CAPTURE" in mock_agent.actions_called
        assert "RUN_REMEDIATION_WORKLOAD" in mock_agent.actions_called
        assert "STOP_LIVE_CAPTURE" in mock_agent.actions_called


@pytest.mark.asyncio
async def test_automatic_rollback_triggered_on_load_failure():
    """Verify that configuration load failure triggers automatic safe rollback to backup."""
    mock_agent = MockPrivilegedAgent(should_fail_load=True)
    runner = ClosedLoopRemediationRunner(agent_client=mock_agent)

    db = MagicMock(spec=AsyncSession)

    analysis_id = uuid.uuid4()
    twin_id = uuid.uuid4()
    run_id = uuid.uuid4()
    proposal_hash = hashlib.sha256(b"mock_proposal_fail").hexdigest()

    hardened_snapshot = ConfigurationSnapshotModel(
        id=uuid.uuid4(),
        config_format="SWANCTL",
        config_content="connections { bad { proposals = invalid_cipher } }",
        config_hash=proposal_hash,
        normalized_ir={"connections": []},
    )
    twin = ConfigurationTwinModel(
        id=twin_id,
        analysis_id=analysis_id,
        hardened_snapshot_id=hardened_snapshot.id,
        observed_snapshot_id=uuid.uuid4(),
        proposal_hash=proposal_hash,
        projected_score=90.0,
        projected_score_delta=40.0,
        projected_regression_audit={"has_blocking_regressions": False, "proof_obligations": []},
    )
    run = RemediationRunModel(
        id=run_id,
        twin_id=twin_id,
        proposal_hash=proposal_hash,
        status="CREATED",
    )

    async def _mock_execute(query):
        mock_result = MagicMock()
        query_str = str(query)
        if "remediation_runs" in query_str and "WHERE remediation_runs.id =" in query_str:
            mock_result.scalar_one_or_none.return_value = run
        elif "configuration_twins" in query_str:
            mock_result.scalar_one_or_none.return_value = twin
        elif "configuration_snapshots" in query_str:
            mock_result.scalar_one_or_none.return_value = hardened_snapshot
        elif "analysis_runs" in query_str:
            mock_result.scalar_one_or_none.return_value = AnalysisRun(id=analysis_id, status="COMPLETED")
        else:
            mock_result.scalar_one_or_none.return_value = None
            mock_result.scalars.return_value.all.return_value = []
        return mock_result

    db.execute = AsyncMock(side_effect=_mock_execute)
    db.commit = AsyncMock()
    db.add = MagicMock()

    with (
        patch.object(LabResourceTracker, "acquire_lock"),
        patch.object(LabResourceTracker, "release_lock"),
        patch("os.path.exists", return_value=True),
    ):
        result_run = await runner.execute_closed_loop_run(
            db=db,
            run_id=run_id,
            analysis_id=analysis_id,
            twin_id=twin_id,
            approved_proposal_hash=proposal_hash,
        )

        # Must trigger rollback and finish in ROLLED_BACK state
        assert result_run.status == "ROLLED_BACK"
        assert result_run.rollback_state == "COMPLETED"
        assert "RESTORE_BACKUP" in mock_agent.actions_called
