"""Unit and API tests for Phase 0 Truth Reconciliation, Deduplication, Recompute, and Score Parity."""

import asyncio
import io
import struct
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings
from app.db.base import Base
from app.db.session import get_db_session
from app.main import create_app


def _make_pcap_header() -> bytes:
    """Create minimal valid 24-byte PCAP global header."""
    return struct.pack("<4sHHIIII", b"\xd4\xc3\xb2\xa1", 2, 4, 0, 0, 65535, 1)


@pytest.fixture
def test_settings(temp_storage_dir: str) -> Settings:
    return Settings(
        app_name="TunnelTrace AI Test",
        app_env="testing",
        app_debug=True,
        app_log_level="INFO",
        database_url="sqlite+aiosqlite:///:memory:",
        storage_root=temp_storage_dir,
        cors_allowed_origins=["http://localhost:3000"],
    )


@pytest.fixture
def db_session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async def _init_tables():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_init_tables())
    yield session_factory

    async def _dispose():
        await engine.dispose()

    asyncio.run(_dispose())


@pytest.fixture
def client(test_settings: Settings, db_session_factory):
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
    with TestClient(app_instance) as c:
        yield c
    app_instance.dependency_overrides.clear()


def test_deduplication_on_upload(client):
    """Uploading the same valid capture twice returns already_analyzed flag and reuses run."""
    pcap_data = _make_pcap_header()

    # First upload
    files = {"file": ("test_dedup.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
    r1 = client.post("/api/v1/captures", files=files)
    assert r1.status_code == 201
    cap_id1 = r1.json()["capture_id"]

    # Create an analysis for this capture
    r_an = client.post("/api/v1/analyses", json={"capture_id": cap_id1})
    assert r_an.status_code == 202
    an_data = r_an.json()
    assert an_data["pipeline_version"] == "2.0.0"

    # Second upload of the EXACT same content
    files2 = {"file": ("test_dedup.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
    r2 = client.post("/api/v1/captures", files=files2)
    assert r2.status_code == 201
    data2 = r2.json()
    assert data2["already_analyzed"] is True
    assert data2["existing_analysis_id"] == an_data["analysis_id"]

    # Requesting analysis creation without force_rerun returns existing run
    r_an_dup = client.post("/api/v1/analyses", json={"capture_id": cap_id1, "force_rerun": False})
    assert r_an_dup.status_code == 202
    assert r_an_dup.json()["analysis_id"] == an_data["analysis_id"]


def test_archive_and_delete_analysis(client):
    """Operator can archive and permanently delete junk analysis runs."""
    pcap_data = _make_pcap_header()
    files = {"file": ("junk_run.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
    r_cap = client.post("/api/v1/captures", files=files)
    cap_id = r_cap.json()["capture_id"]

    r_an = client.post("/api/v1/analyses", json={"capture_id": cap_id, "force_rerun": True})
    an_id = r_an.json()["analysis_id"]

    # Archive run
    r_arch = client.post(f"/api/v1/analyses/{an_id}/archive?archive=true")
    assert r_arch.status_code == 200
    assert r_arch.json()["is_archived"] is True

    # By default, list_analyses hides archived runs
    r_list = client.get("/api/v1/analyses")
    assert r_list.status_code == 200
    ids = [item["analysis_id"] for item in r_list.json()]
    assert an_id not in ids

    # With include_archived=true, it is visible
    r_list_arch = client.get("/api/v1/analyses?include_archived=true")
    assert r_list_arch.status_code == 200
    ids_arch = [item["analysis_id"] for item in r_list_arch.json()]
    assert an_id in ids_arch

    # Delete run
    r_del = client.delete(f"/api/v1/analyses/{an_id}")
    assert r_del.status_code == 204

    # Confirm 404
    r_get = client.get(f"/api/v1/analyses/{an_id}")
    assert r_get.status_code == 404


def test_score_and_coverage_catalog_truthfulness(client):
    """Catalog list does not report bare 100/100 on partial or insufficient evidence."""
    r_list = client.get("/api/v1/analyses?include_archived=true")
    assert r_list.status_code == 200
    items = r_list.json()
    for item in items:
        cov = item.get("coverage_percentage")
        score = item.get("security_score")
        risk = item.get("risk_tier")
        if cov is not None and cov < 50.0:
            assert score is None, f"Run {item['analysis_id']} has cov {cov}% but score {score}"
            assert risk == "INSUFFICIENT_EVIDENCE", f"Run {item['analysis_id']} expected INSUFFICIENT_EVIDENCE"
