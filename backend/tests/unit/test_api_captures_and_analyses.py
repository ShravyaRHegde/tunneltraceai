"""Unit and API contract tests for offline capture ingestion, analysis, and live capture."""

import hashlib
import io
import struct
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings
from app.db.base import Base
from app.db.session import get_db_session
from app.integrations.privileged_agent import reset_privileged_agent_client
from app.main import create_app


def _make_pcap_header() -> bytes:
    """Create minimal valid 24-byte PCAP global header."""
    return struct.pack("<4sHHIIII", b"\xd4\xc3\xb2\xa1", 2, 4, 0, 0, 65535, 1)


@pytest.fixture
def test_settings(temp_storage_dir: str) -> Settings:
    """Settings fixture with netagent enabled for testing."""
    return Settings(
        app_name="TunnelTrace AI Test",
        app_env="testing",
        app_debug=True,
        app_log_level="INFO",
        database_url="sqlite+aiosqlite:///:memory:",
        storage_root=temp_storage_dir,
        cors_allowed_origins=["http://localhost:3000"],
        netagent_enabled=True,
    )


@pytest.fixture
def db_session_factory():
    """Create isolated async in-memory SQLite database session factory."""
    reset_privileged_agent_client()
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    import asyncio

    async def _init_tables():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_init_tables())
    yield session_factory

    async def _dispose():
        await engine.dispose()

    asyncio.run(_dispose())
    reset_privileged_agent_client()


@pytest.fixture
def test_app(test_settings: Settings, db_session_factory):
    """FastAPI application configured with test database session override."""
    from app.integrations.privileged_agent import (
        LocalPrivilegedAgentClient,
        set_privileged_agent_client,
    )

    set_privileged_agent_client(LocalPrivilegedAgentClient(enabled=True))
    app_instance = create_app(settings=test_settings)

    async def _override_get_db():
        async with db_session_factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app_instance.dependency_overrides[get_db_session] = _override_get_db
    yield app_instance
    set_privileged_agent_client(None)


@pytest.fixture
def api_client(test_app) -> TestClient:
    """Synchronous test client."""
    with TestClient(app=test_app, base_url="http://testserver") as client:
        yield client


def test_upload_valid_pcap(api_client: TestClient):
    """Verify uploading a valid PCAP file returns 201 Created and correct SHA-256."""
    header = _make_pcap_header()
    expected_sha = hashlib.sha256(header).hexdigest().lower()

    files = {"file": ("test_sample.pcap", io.BytesIO(header), "application/vnd.tcpdump.pcap")}
    res = api_client.post("/api/v1/captures", files=files)

    assert res.status_code == 201
    data = res.json()
    assert "capture_id" in data
    assert data["capture_format"] == "PCAP"
    assert data["capture_source"] == "OFFLINE_UPLOAD"
    assert data["file_size_bytes"] == 24
    assert data["sha256"] == expected_sha
    assert data["validation_state"] == "VALIDATED"


def test_upload_trailing_slash_and_alias_endpoints(api_client: TestClient):
    """Verify both trailing slash (/captures/) and alias (/captures/upload) accept POST without 405."""
    header = _make_pcap_header()

    # Test trailing slash
    files_slash = {"file": ("test_slash.pcap", io.BytesIO(header), "application/vnd.tcpdump.pcap")}
    res_slash = api_client.post("/api/v1/captures/", files=files_slash)
    assert res_slash.status_code == 201
    assert "capture_id" in res_slash.json()

    # Test /upload alias
    files_alias = {"file": ("test_alias.pcap", io.BytesIO(header), "application/vnd.tcpdump.pcap")}
    res_alias = api_client.post("/api/v1/captures/upload", files=files_alias)
    assert res_alias.status_code == 201
    assert "capture_id" in res_alias.json()


def test_upload_empty_capture_rejected(api_client: TestClient):
    """Verify zero-byte upload returns 400 CAPTURE_EMPTY."""
    files = {"file": ("empty.pcap", io.BytesIO(b""), "application/octet-stream")}
    res = api_client.post("/api/v1/captures", files=files)

    assert res.status_code == 400
    data = res.json()
    assert data["error"]["code"] == "CAPTURE_EMPTY"


def test_upload_invalid_magic_rejected(api_client: TestClient):
    """Verify binary garbage upload is rejected with CAPTURE_INVALID_FORMAT."""
    garbage = b"This is not a valid packet capture header payload."
    files = {"file": ("corrupt.pcap", io.BytesIO(garbage), "application/octet-stream")}
    res = api_client.post("/api/v1/captures", files=files)

    assert res.status_code == 400
    data = res.json()
    assert data["error"]["code"] == "CAPTURE_INVALID_FORMAT"


def test_upload_path_traversal_filename_safe(api_client: TestClient):
    """Verify path traversal in original filename is stripped and harmless."""
    header = _make_pcap_header()
    files = {"file": ("../../../../etc/passwd", io.BytesIO(header), "application/octet-stream")}
    res = api_client.post("/api/v1/captures", files=files)

    assert res.status_code == 201
    data = res.json()
    assert data["original_filename"] == "passwd"


def test_get_capture_metadata(api_client: TestClient):
    """Verify retrieving capture metadata by UUID."""
    header = _make_pcap_header()
    files = {"file": ("meta_test.pcap", io.BytesIO(header), "application/octet-stream")}
    create_res = api_client.post("/api/v1/captures", files=files)
    capture_id = create_res.json()["capture_id"]

    res = api_client.get(f"/api/v1/captures/{capture_id}")
    assert res.status_code == 200
    data = res.json()
    assert data["capture_id"] == capture_id
    assert data["file_size_bytes"] == 24


def test_get_capture_not_found(api_client: TestClient):
    """Verify querying non-existent capture returns 404 CAPTURE_NOT_FOUND."""
    fake_id = uuid.uuid4()
    res = api_client.get(f"/api/v1/captures/{fake_id}")

    assert res.status_code == 404
    data = res.json()
    assert data["error"]["code"] == "CAPTURE_NOT_FOUND"


def test_create_and_query_analysis(api_client: TestClient):
    """Verify registering analysis run and querying its execution status and summary."""
    header = _make_pcap_header()
    files = {"file": ("analysis_test.pcap", io.BytesIO(header), "application/octet-stream")}
    create_res = api_client.post("/api/v1/captures", files=files)
    capture_id = create_res.json()["capture_id"]

    # 1. Enqueue analysis
    analysis_res = api_client.post("/api/v1/analyses", json={"capture_id": capture_id})
    assert analysis_res.status_code == 202
    analysis_data = analysis_res.json()
    analysis_id = analysis_data["analysis_id"]
    assert analysis_data["status"] == "COMPLETED"
    assert analysis_data["parser_engine"] == "tshark"

    # 2. Query analysis status
    status_res = api_client.get(f"/api/v1/analyses/{analysis_id}")
    assert status_res.status_code == 200
    assert status_res.json()["status"] == "COMPLETED"

    # 3. Query protocol summary (empty 24-byte PCAP has no packets -> NO_IPSEC_FOUND)
    summary_res = api_client.get(f"/api/v1/analyses/{analysis_id}/protocol")
    assert summary_res.status_code == 200
    summary = summary_res.json()
    assert summary["ipsec_detected"] is False
    assert summary["outcome"] == "NO_IPSEC_FOUND"
    assert summary["parser"]["engine"] == "tshark"


def test_analysis_target_not_found(api_client: TestClient):
    """Verify creating analysis for non-existent capture returns 404."""
    fake_id = uuid.uuid4()
    res = api_client.post("/api/v1/analyses", json={"capture_id": str(fake_id)})

    assert res.status_code == 404
    assert res.json()["error"]["code"] == "CAPTURE_NOT_FOUND"


def test_live_captures_list_interfaces(api_client: TestClient):
    """Verify listing allowlisted interfaces returns 200 OK without protected host interfaces."""
    res = api_client.get("/api/v1/live-captures/interfaces")
    assert res.status_code == 200
    ifaces = res.json()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0
    # Confirm protected host interfaces are never exposed
    for iface in ifaces:
        assert iface["interface_id"] not in ("eth0", "docker0", "Wi-Fi", "wlan0")
        assert iface["capture_allowed"] is True


def test_live_captures_reject_unauthorized_interface(api_client: TestClient):
    """Verify attempting live capture on physical host interface is blocked."""
    res = api_client.post(
        "/api/v1/live-captures/start",
        json={"interface_id": "eth0", "duration_sec": 5},
    )
    assert res.status_code in (400, 403)
    assert res.json()["error"]["code"] == "LIVE_INTERFACE_NOT_ALLOWED"
