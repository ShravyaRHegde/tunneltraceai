"""Unit tests for Stage 9 analysis overview, list, traffic, and realtime WebSocket endpoints."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient

from app.db.models.capture import AnalysisRun, Capture
from app.db.models.ml import FlowClassification
from app.db.models.reconstruction import ESPFlow
from app.db.models.security import ScoreAssessmentModel, SecurityFindingModel
from app.db.session import get_db_session
from app.main import app


class TestAnalysesOverviewAndWebSocket:
    """Verifies Command Center data aggregation, traffic intelligence, and WebSocket streaming."""

    @pytest.mark.asyncio
    async def test_list_analyses_endpoint(self) -> None:
        analysis_id = uuid.uuid4()
        cap_id = uuid.uuid4()

        mock_capture = Capture(
            id=cap_id,
            capture_source="OFFLINE_UPLOAD",
            capture_format="PCAP",
            original_filename="demo.pcap",
            sha256_hash="1234567890abcdef" * 4,
            file_size_bytes=4096,
            storage_path="captures/demo.pcap",
            validation_state="VALID",
            created_at=datetime.now(timezone.utc),
        )
        mock_run = AnalysisRun(
            id=analysis_id,
            capture_id=cap_id,
            status="COMPLETED",
            current_stage="COMPLETED",
            parser_engine="tshark",
            parser_version="4.2.0",
            schema_version="1.0.0",
            created_at=datetime.now(timezone.utc),
        )
        mock_run.capture = mock_capture

        mock_db = AsyncMock()
        mock_res_runs = MagicMock()
        mock_res_runs.scalars().all.return_value = [mock_run]

        mock_res_scores = MagicMock()
        mock_score = ScoreAssessmentModel(
            id=uuid.uuid4(),
            analysis_id=analysis_id,
            overall_score=95.0,
            raw_score=95.0,
            score_policy_id="default",
            score_policy_version="1.0.0",
            score_policy_hash="test",
            status="FINAL",
            coverage_percentage=100.0,
        )
        mock_res_scores.scalars().all.return_value = [mock_score]

        mock_res_risks = MagicMock()
        mock_res_risks.scalars().all.return_value = []

        mock_res_finds = MagicMock()
        mock_res_finds.scalars().all.return_value = []

        mock_res_flows = MagicMock()
        mock_res_flows.all.return_value = []

        mock_res_ike = MagicMock()
        mock_res_ike.all.return_value = []

        mock_res_comp = MagicMock()
        mock_res_comp.scalars().all.return_value = []

        mock_db.execute.side_effect = [
            mock_res_runs,
            mock_res_scores,
            mock_res_risks,
            mock_res_finds,
            mock_res_comp,
            mock_res_flows,
            mock_res_ike,
        ]

        app.dependency_overrides[get_db_session] = lambda: mock_db
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as ac:
                res = await ac.get("/api/v1/analyses")
                assert res.status_code == 200
                data = res.json()
                assert len(data) == 1
                assert data[0]["analysis_id"] == str(analysis_id)
                assert data[0]["capture_filename"] == "demo.pcap"
                assert data[0]["security_score"] == 95.0
        finally:
            app.dependency_overrides.pop(get_db_session, None)

    @pytest.mark.asyncio
    async def test_get_analysis_traffic_endpoint(self) -> None:
        analysis_id = uuid.uuid4()
        flow_id = uuid.uuid4()

        mock_flow = ESPFlow(
            id=flow_id,
            analysis_id=analysis_id,
            spi="0x12345678",
            reverse_spi="0x87654321",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            duration_seconds=5.0,
            packet_count=100,
            byte_count=80000,
            association_state="BIDIRECTIONAL_ASSOCIATED",
        )
        mock_ml = FlowClassification(
            id=uuid.uuid4(),
            flow_id=flow_id,
            known_class="VOIP_IPSEC",
            final_class="VOIP_IPSEC",
            calibrated_confidence=0.915,
            entropy=0.45,
            normalized_entropy=0.25,
            ood_status="KNOWN_ACCEPTED",
            behavioral_anomaly_status="NORMAL_BEHAVIOR",
            transparency_data={"shap_values": {"pkt_len_mean": 0.42, "iat_std": -0.15}},
        )

        mock_db = AsyncMock()
        mock_res_flows = MagicMock()
        mock_res_flows.scalars().all.return_value = [mock_flow]

        mock_res_run = MagicMock()
        mock_res_run.scalars().first.return_value = None

        mock_res_ml = MagicMock()
        mock_res_ml.scalars().all.return_value = [mock_ml]

        mock_db.execute.side_effect = [mock_res_flows, mock_res_run, mock_res_ml]

        app.dependency_overrides[get_db_session] = lambda: mock_db
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as ac:
                res = await ac.get(f"/api/v1/analyses/{analysis_id}/traffic")
                assert res.status_code == 200
                data = res.json()
                assert data["analysis_id"] == str(analysis_id)
                assert data["total_flows"] == 1
                assert data["classified_flows"] == 1
                assert "VOIP_IPSEC" in data["classes_detected"]
                assert data["flows"][0]["calibrated_confidence"] == 0.915
                assert len(data["flows"][0]["top_shap_features"]) == 2
        finally:
            app.dependency_overrides.pop(get_db_session, None)

    @pytest.mark.asyncio
    async def test_export_manifest_endpoint(self) -> None:
        analysis_id = uuid.uuid4()
        cap_id = uuid.uuid4()

        mock_capture = Capture(
            id=cap_id,
            capture_source="OFFLINE_UPLOAD",
            capture_format="PCAP",
            original_filename="real_tunnel_gcm.pcapng",
            sha256_hash="e" * 64,
            file_size_bytes=2048,
            packet_count=12,
            storage_path="captures/real_tunnel_gcm.pcapng",
            validation_state="VALID",
            created_at=datetime.now(timezone.utc),
        )
        mock_finding = SecurityFindingModel(
            id=uuid.uuid4(),
            finding_id="FND-SWEET32-01",
            analysis_id=analysis_id,
            rule_id="RULE_CRYPTO_SWEET32",
            rule_version="1.0.0",
            profile_id="RFC8221",
            category="CRYPTOGRAPHY",
            severity="HIGH",
            title="Legacy 3DES Sweet32 Vulnerability",
            technical_description="Sweet32 collision attack",
            root_cause_key="CIPHER_SWEET32",
            affected_entity_type="CHILD_SA",
            affected_entity_id="ESP_0x1234",
            evidence_state="CONFIRMED",
            remediation_guidance="Upgrade to AES-GCM-256",
            remediation_directive="SET_AEAD",
            record_hash="e" * 64,
            created_at=datetime.now(timezone.utc),
        )
        mock_score = ScoreAssessmentModel(
            id=uuid.uuid4(),
            analysis_id=analysis_id,
            overall_score=85.0,
            raw_score=85.0,
            score_policy_id="POLICY-NIST-RFC8221",
            score_policy_version="1.0.0",
            score_policy_hash="a" * 64,
            status="EVALUATED",
            coverage_percentage=92.5,
            created_at=datetime.now(timezone.utc),
        )
        mock_run = AnalysisRun(
            id=analysis_id,
            capture_id=cap_id,
            status="COMPLETED",
            current_stage="COMPLETED",
            parser_engine="tshark",
            parser_version="4.2.0",
            schema_version="1.0.0",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
        )
        mock_run.capture = mock_capture
        mock_run.findings = [mock_finding]
        mock_run.score_assessment = mock_score

        mock_db = AsyncMock()
        mock_res_run = MagicMock()
        mock_res_run.scalar_one_or_none.return_value = mock_run

        mock_res_findings = MagicMock()
        mock_res_findings.scalars().all.return_value = [mock_finding]

        mock_res_score = MagicMock()
        mock_res_score.scalars().first.return_value = mock_score

        mock_db.execute.side_effect = [mock_res_run, mock_res_findings, mock_res_score]

        app.dependency_overrides[get_db_session] = lambda: mock_db
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as ac:
                res = await ac.get(f"/api/v1/analyses/{analysis_id}/export/manifest")
                assert res.status_code == 200
                assert res.headers["content-type"] == "application/json"
                assert "Content-Disposition" in res.headers
                data = res.json()
                assert data["manifest_schema_version"] == "1.0.0"
                assert data["analysis"]["analysis_id"] == str(analysis_id)
                assert data["capture"]["filename"] == "real_tunnel_gcm.pcapng"
                assert data["security_posture"]["score"] == 85
                assert data["findings_summary"]["total"] == 1
                assert data["findings"][0]["rule_id"] == "RULE_CRYPTO_SWEET32"
        finally:
            app.dependency_overrides.pop(get_db_session, None)

    @pytest.mark.asyncio
    async def test_export_findings_csv_endpoint(self) -> None:
        analysis_id = uuid.uuid4()
        mock_finding = SecurityFindingModel(
            id=uuid.uuid4(),
            finding_id="FND-SWEET32-02",
            analysis_id=analysis_id,
            rule_id="RULE_CRYPTO_SWEET32",
            rule_version="1.0.0",
            profile_id="RFC8221",
            category="CRYPTOGRAPHY",
            severity="HIGH",
            title="Legacy 3DES Sweet32",
            technical_description="Sweet32 collision attack",
            root_cause_key="CIPHER_SWEET32",
            affected_entity_type="CHILD_SA",
            affected_entity_id="ESP_0x1234",
            evidence_state="CONFIRMED",
            remediation_guidance="Upgrade to AES-GCM",
            remediation_directive="SET_AEAD",
            record_hash="e" * 64,
            created_at=datetime.now(timezone.utc),
        )
        mock_run = AnalysisRun(
            id=analysis_id,
            capture_id=uuid.uuid4(),
            status="COMPLETED",
            current_stage="COMPLETED",
            parser_engine="tshark",
            parser_version="4.2.0",
            schema_version="1.0.0",
            created_at=datetime.now(timezone.utc),
        )
        mock_run.findings = [mock_finding]

        mock_db = AsyncMock()
        mock_res_run = MagicMock()
        mock_res_run.scalar_one_or_none.return_value = mock_run

        mock_res_findings = MagicMock()
        mock_res_findings.scalars().all.return_value = [mock_finding]

        mock_db.execute.side_effect = [mock_res_run, mock_res_findings]

        app.dependency_overrides[get_db_session] = lambda: mock_db
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as ac:
                res = await ac.get(f"/api/v1/analyses/{analysis_id}/export/findings.csv")
                assert res.status_code == 200
                assert "text/csv" in res.headers["content-type"]
                assert "tunneltrace_findings_" in res.headers["Content-Disposition"]
                csv_text = res.text
                assert "Finding ID,Rule ID,Severity,Title" in csv_text
                assert "RULE_CRYPTO_SWEET32" in csv_text
        finally:
            app.dependency_overrides.pop(get_db_session, None)

    def test_realtime_websocket_connection_and_heartbeat(self) -> None:
        client = TestClient(app)
        analysis_id = uuid.uuid4()

        with patch("app.api.v1.websocket.router.get_session_factory") as mock_factory:
            mock_session = AsyncMock()
            mock_res = MagicMock()
            mock_run = AnalysisRun(
                id=analysis_id,
                capture_id=uuid.uuid4(),
                status="RUNNING",
                current_stage="FLOW_RECONSTRUCTION",
                started_at=datetime.now(timezone.utc),
            )
            mock_res.scalar_one_or_none.return_value = mock_run
            mock_session.execute = AsyncMock(return_value=mock_res)

            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = mock_session
            mock_factory.return_value = MagicMock(return_value=mock_cm)

            with client.websocket_connect(f"/api/v1/ws/analyses/{analysis_id}") as websocket:
                # 1. Receive initial state event
                raw_init = websocket.receive_text()
                init_msg = json.loads(raw_init)
                assert init_msg["type"] == "ANALYSIS_STATE"
                assert init_msg["payload"]["status"] == "RUNNING"
                assert init_msg["payload"]["current_stage"] == "FLOW_RECONSTRUCTION"

                # 2. Send client ping and expect pong
                websocket.send_text(json.dumps({"type": "PING"}))
                raw_pong = websocket.receive_text()
                pong_msg = json.loads(raw_pong)
                assert pong_msg["type"] == "PONG"
                assert pong_msg["analysis_id"] == str(analysis_id)
