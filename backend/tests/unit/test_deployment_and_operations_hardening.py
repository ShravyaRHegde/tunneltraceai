"""
Unit tests for Deployment and Operations Hardening.
Verifies privileged capture boundaries, input validation, audit logging,
data lifecycle/retention, backup integrity, and production security rules.
"""

import json
import os
import tempfile
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from app.api.v1.schemas import StartLiveCaptureRequestDTO
from app.core.audit import AuditOutcome, SecurityAuditLogger
from app.core.backup import DatabaseBackupManager
from app.core.config import Settings, settings
from app.core.lifecycle import DataClassification, DataLifecycleManager
from lab.agent.capture.manager import CaptureManager
from lab.agent.operations.runner import SecurityViolationError, SystemRunner


class TestPrivilegedCaptureBoundaries:
    """Tests verifying privileged capture input validation and shell isolation."""

    def test_start_capture_rejects_protected_physical_interface(self):
        runner = SystemRunner()
        mgr = CaptureManager(runner=runner)

        with pytest.raises(SecurityViolationError, match="protected physical host interface"):
            mgr.start_capture(
                capture_id="test1",
                interface="eth0",
                output_pcap_path="/tmp/test.pcap",
            )

    def test_start_capture_rejects_dangerous_capture_id(self):
        runner = SystemRunner()
        mgr = CaptureManager(runner=runner)

        with pytest.raises(ValueError, match="Invalid capture_id"):
            mgr.start_capture(
                capture_id="../../etc/cron.d/evil",
                interface="br-wan",
                output_pcap_path="/tmp/test.pcap",
            )

    def test_start_capture_rejects_bpf_shell_injection(self):
        runner = SystemRunner()
        mgr = CaptureManager(runner=runner)

        # Injection with semicolon
        with pytest.raises(SecurityViolationError, match="forbidden shell character"):
            mgr.start_capture(
                capture_id="cap1",
                interface="br-wan",
                output_pcap_path="/tmp/test.pcap",
                bpf_filter="port 500; rm -rf /tmp/data",
            )

        # Injection with backticks
        with pytest.raises(SecurityViolationError, match="forbidden shell character"):
            mgr.start_capture(
                capture_id="cap2",
                interface="br-wan",
                output_pcap_path="/tmp/test.pcap",
                bpf_filter="port `id`",
            )

        # Injection with pipes
        with pytest.raises(SecurityViolationError, match="forbidden shell character"):
            mgr.start_capture(
                capture_id="cap3",
                interface="br-wan",
                output_pcap_path="/tmp/test.pcap",
                bpf_filter="port 500 | cat /etc/passwd",
            )

    def test_start_capture_rejects_invalid_netns(self):
        runner = SystemRunner()
        mgr = CaptureManager(runner=runner)

        with pytest.raises(SecurityViolationError, match="Invalid netns name"):
            mgr.start_capture(
                capture_id="cap4",
                interface="br-wan",
                output_pcap_path="/tmp/test.pcap",
                netns="client; evil_command",
            )


class TestLiveCaptureRequestSchemaValidation:
    """Tests verifying StartLiveCaptureRequestDTO Pydantic constraints."""

    def test_valid_request_dto(self):
        req = StartLiveCaptureRequestDTO(
            interface_id="br-wan",
            duration_sec=60,
            capture_profile="IPSEC_RELEVANT",
            bpf_filter="udp port 500 or esp",
        )
        assert req.interface_id == "br-wan"
        assert req.duration_sec == 60
        assert req.bpf_filter == "udp port 500 or esp"

    def test_rejects_interface_with_shell_characters(self):
        with pytest.raises(ValidationError):
            StartLiveCaptureRequestDTO(
                interface_id="br-wan; rm -rf",
            )

    def test_rejects_duration_out_of_bounds(self):
        with pytest.raises(ValidationError):
            StartLiveCaptureRequestDTO(
                interface_id="br-wan",
                duration_sec=0,  # Below min 1
            )

        with pytest.raises(ValidationError):
            StartLiveCaptureRequestDTO(
                interface_id="br-wan",
                duration_sec=500,  # Above max 300
            )

    def test_rejects_bpf_filter_with_shell_characters(self):
        with pytest.raises(ValidationError):
            StartLiveCaptureRequestDTO(
                interface_id="br-wan",
                bpf_filter="port 500 && whoami",
            )

        with pytest.raises(ValidationError):
            StartLiveCaptureRequestDTO(
                interface_id="br-wan",
                bpf_filter="port $(id -u)",
            )


class TestProductionSecurityConfigurationValidation:
    """Tests verifying fail-closed configuration rules in production mode."""

    def test_production_mode_rejects_default_insecure_secret(self):
        with pytest.raises(ValueError, match="APP_SECRET_KEY must be overridden"):
            Settings(
                APP_ENV="production",
                APP_SECRET_KEY="insecure-local-dev-secret-change-in-production-min32chars",
            )

    def test_production_mode_rejects_short_secret(self):
        with pytest.raises(ValueError, match="at least 32 characters"):
            Settings(
                APP_ENV="production",
                APP_SECRET_KEY="short-secret-12345",
            )

    def test_production_mode_rejects_debug_enabled(self):
        with pytest.raises(ValueError, match="APP_DEBUG must be False in production"):
            Settings(
                APP_ENV="production",
                APP_SECRET_KEY="a-very-long-and-secure-secret-key-for-prod-32chars!",
                APP_DEBUG=True,
            )

    def test_production_mode_rejects_wildcard_cors(self):
        with pytest.raises(ValueError, match=r"Wildcard '\*' in CORS_ALLOWED_ORIGINS is prohibited"):
            Settings(
                APP_ENV="production",
                APP_SECRET_KEY="a-very-long-and-secure-secret-key-for-prod-32chars!",
                APP_DEBUG=False,
                CORS_ALLOWED_ORIGINS=["*"],
            )

    def test_production_mode_rejects_unauthenticated_monitoring_bypass(self):
        with pytest.raises(ValueError, match="MONITORING_ALLOW_UNAUTHENTICATED_LOCAL must be False"):
            Settings(
                APP_ENV="production",
                APP_SECRET_KEY="a-very-long-and-secure-secret-key-for-prod-32chars!",
                APP_DEBUG=False,
                MONITORING_ALLOW_UNAUTHENTICATED_LOCAL=True,
            )

    def test_production_mode_accepts_hardened_settings(self):
        s = Settings(
            APP_ENV="production",
            APP_SECRET_KEY="a-very-long-and-secure-secret-key-for-prod-32chars!",
            APP_DEBUG=False,
            CORS_ALLOWED_ORIGINS=["https://soc.tunneltrace.corp.internal"],
            MONITORING_ALLOW_UNAUTHENTICATED_LOCAL=False,
            DISCOVERY_ALLOW_UNAUTHENTICATED_LOCAL=False,
        )
        assert s.is_production is True
        assert s.app_debug is False


class TestSecurityAuditLogger:
    """Tests verifying structured audit logging and secret redaction."""

    def test_record_audit_event_scrubs_secrets_in_metadata(self, tmp_path):
        logger = SecurityAuditLogger(log_dir=tmp_path)
        evt = logger.record_event(
            action="TEST_SENSITIVE_ACTION",
            target_resource="gw:198.51.100.1",
            authorized_scope="198.51.100.0/24",
            outcome=AuditOutcome.SUCCESS,
            actor_id="operator-admin",
            metadata={
                "operator_psk": "my_super_secret_psk_key_123",
                "auth_token": "bearer-token-abc",
                "normal_detail": "ikev2_proposal",
            },
        )

        assert evt.action == "TEST_SENSITIVE_ACTION"
        assert evt.metadata["operator_psk"] == "[REDACTED_SECRET]"
        assert evt.metadata["auth_token"] == "[REDACTED_SECRET]"
        assert evt.metadata["normal_detail"] == "ikev2_proposal"

        # Verify JSONL file persistence
        events = logger.query_events(action="TEST_SENSITIVE_ACTION")
        assert len(events) == 1
        assert events[0]["outcome"] == "SUCCESS"
        assert events[0]["metadata"]["operator_psk"] == "[REDACTED_SECRET]"

    def test_record_denied_and_failed_events(self, tmp_path):
        logger = SecurityAuditLogger(log_dir=tmp_path)
        logger.record_event(
            action="PRIVILEGED_APPLY_CONFIG",
            target_resource="/etc/swanctl/swanctl.conf",
            authorized_scope="lab:tt-test",
            outcome=AuditOutcome.DENIED,
            actor_id="anonymous",
            reason_or_error="Access denied: Production mode requires explicit verified authorization provider.",
        )

        logger.record_event(
            action="PRIVILEGED_CAPTURE_START",
            target_resource="interface:eth0",
            authorized_scope="lab:tt-test",
            outcome=AuditOutcome.FAILED,
            actor_id="operator-1",
            reason_or_error="Refusing to execute operation touching protected physical host interface: 'eth0'",
        )

        denied = logger.query_events(outcome="DENIED")
        assert len(denied) == 1
        assert "Access denied" in denied[0]["reason_or_error"]

        failed = logger.query_events(outcome="FAILED")
        assert len(failed) == 1
        assert "protected physical host interface" in failed[0]["reason_or_error"]


class TestDataLifecycleManager:
    """Tests verifying data lifecycle definitions and safe artifact purge."""

    def test_lifecycle_policies_cover_all_data_types(self):
        policies = DataLifecycleManager.get_policies()
        assert DataClassification.RAW_PCAP.value in policies
        assert DataClassification.DERIVED_OBSERVATIONS.value in policies
        assert DataClassification.REPORTS.value in policies
        assert DataClassification.TEMPORARY_LAB_FILES.value in policies
        assert DataClassification.AUDIT_LOGS.value in policies
        assert DataClassification.CONFIG_CERT_SNAPSHOTS.value in policies

    def test_purge_temporary_staging_files(self, tmp_path, monkeypatch):
        tmp_storage = tmp_path / "storage"
        tmp_dir = tmp_storage / "tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)

        old_file = tmp_dir / "old_staged_probe.tmp"
        old_file.write_text("old data")

        # Fake old timestamp (25 hours ago)
        old_time = os.path.getmtime(old_file) - (25 * 3600)
        os.utime(old_file, (old_time, old_time))

        new_file = tmp_dir / "fresh_probe.tmp"
        new_file.write_text("fresh data")

        monkeypatch.setattr(settings, "STORAGE_ROOT", tmp_storage)
        mgr = DataLifecycleManager()
        result = mgr.purge_temporary_staging_files(max_age_hours=24)

        assert result["purged_files"] >= 1
        assert not old_file.exists()
        assert new_file.exists()

    def test_inspect_storage_footprint(self, tmp_path, monkeypatch):
        tmp_storage = tmp_path / "storage"
        (tmp_storage / "captures").mkdir(parents=True, exist_ok=True)
        (tmp_storage / "captures" / "sample.pcap").write_bytes(b"\x00" * 1024)

        monkeypatch.setattr(settings, "STORAGE_ROOT", tmp_storage)
        mgr = DataLifecycleManager()
        footprint = mgr.inspect_storage_footprint()

        assert footprint["categories"]["captures"]["file_count"] == 1
        assert footprint["categories"]["captures"]["total_bytes"] == 1024


class TestDatabaseBackupManager:
    """Tests verifying SQLite database backup creation and disaster recovery integrity."""

    def test_sqlite_backup_and_fk_verification(self, tmp_path):
        # Create a small valid test database
        db_file = tmp_path / "test_source.sqlite"
        import sqlite3
        conn = sqlite3.connect(str(db_file))
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;")
        cursor.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY, name TEXT);")
        cursor.execute("CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id));")
        cursor.execute("INSERT INTO parent VALUES (1, 'Gateway-1');")
        cursor.execute("INSERT INTO child VALUES (10, 1);")
        conn.commit()
        conn.close()

        backup_dir = tmp_path / "backups"
        mgr = DatabaseBackupManager(backup_dir=backup_dir)
        meta = mgr.create_sqlite_backup(db_file)

        assert meta.status == "VERIFIED_CONSISTENT"
        assert meta.foreign_keys_valid is True
        assert meta.size_bytes > 0
        assert Path(meta.backup_file).exists()

        # Test verification helper
        verify_res = mgr.verify_backup_file(meta.backup_file, expected_sha=meta.backup_sha256)
        assert verify_res["valid"] is True
        assert verify_res["foreign_key_errors"] == 0

    def test_tampered_backup_fails_verification(self, tmp_path):
        db_file = tmp_path / "test_source2.sqlite"
        import sqlite3
        conn = sqlite3.connect(str(db_file))
        conn.execute("CREATE TABLE items (id INT);")
        conn.commit()
        conn.close()

        backup_dir = tmp_path / "backups"
        mgr = DatabaseBackupManager(backup_dir=backup_dir)
        meta = mgr.create_sqlite_backup(db_file)

        # Tamper check with invalid sha
        verify_res = mgr.verify_backup_file(meta.backup_file, expected_sha="deadbeef0000111122223333444455556666777788889999aaaabbbbccccdddd")
        assert verify_res["valid"] is False
        assert "Digest mismatch" in verify_res["error"]
