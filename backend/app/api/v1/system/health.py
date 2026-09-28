"""System health endpoints: Liveness and Readiness probes."""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field

from app.core.config import settings
from app.db.health import check_database_health
from app.integrations.privileged_agent import get_privileged_agent_client
from app.services.redis_service import check_redis_health
from app.services.storage import get_storage_provider

router = APIRouter(prefix="/health", tags=["System Health"])


class LivenessResponse(BaseModel):
    """Liveness probe response model."""

    status: str = Field("UP", description="Process liveness state")
    timestamp: str = Field(..., description="UTC ISO-8601 timestamp")
    service: str = Field("tunneltrace-api", description="Service identifier")


class ReadinessResponse(BaseModel):
    """Readiness probe response model detailing core and future subsystem states."""

    status: str = Field(..., description="Overall readiness: READY or NOT_READY")
    timestamp: str = Field(..., description="UTC ISO-8601 timestamp")
    stage: str = Field("STAGE_1_BOOTSTRAP", description="Active implementation stage")
    dependencies: dict[str, Any] = Field(
        ..., description="Status of required and future subsystems"
    )


def check_storage_health() -> dict[str, Any]:
    """Execute live storage health probe."""
    return get_storage_provider().check_health()


@router.get(
    "/live",
    response_model=LivenessResponse,
    status_code=status.HTTP_200_OK,
    summary="Process Liveness Probe",
    description="Returns HTTP 200 if the FastAPI application process is alive. Does not depend on downstream infrastructure.",
)
async def get_liveness() -> LivenessResponse:
    """Liveness check confirming web server event loop responsiveness."""
    return LivenessResponse(
        status="UP",
        timestamp=datetime.now(timezone.utc).isoformat(),
        service="tunneltrace-api",
    )


@router.get(
    "",
    response_model=ReadinessResponse,
    include_in_schema=False,
)
@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Application Readiness Probe",
    description="Evaluates connectivity to mandatory Stage-1 dependencies (PostgreSQL, Redis, Storage). Returns 200 if READY, 503 if NOT_READY.",
)
async def get_readiness(response: Response) -> ReadinessResponse:
    """Readiness probe checking real PostgreSQL, Redis, and local storage connectivity."""
    # Check mandatory Stage-1 dependencies
    db_result = await check_database_health()
    redis_result = await check_redis_health()
    storage_result = check_storage_health()

    # Check Stage 3 subsystems
    from app.protocol.tshark.binary import get_toolchain
    toolchain = get_toolchain()
    tshark_ver = toolchain.get_version("tshark")
    tshark_status = "UP" if ("Wireshark" in tshark_ver or "TShark" in tshark_ver) else "NOT_AVAILABLE"

    agent_client = get_privileged_agent_client()
    agent_result = await agent_client.get_status()

    # Dynamic check for Stage 8 Policy-as-Code Engine
    try:
        from app.security.policy.registry import PolicyRegistry
        policy_registry = PolicyRegistry()
        rules = policy_registry.get_all_rules()
        policy_status = {
            "status": "UP",
            "rule_count": len(rules),
            "bundle_version": getattr(settings, "CURRENT_POLICY_VERSION", "1.0.0"),
            "stage": "STAGE_8",
        }
    except Exception as exc:
        policy_status = {"status": "DEGRADED", "error": str(exc), "stage": "STAGE_8"}

    # Dynamic check for Stage 7 ML Flow Classification Engine
    try:
        from pathlib import Path
        import json
        manifest_path = Path("models/active/model_manifest.json")
        if not manifest_path.exists():
            manifest_path = Path(__file__).resolve().parents[4] / "models" / "active" / "model_manifest.json"

        if manifest_path.exists():
            with open(manifest_path, encoding="utf-8") as mf:
                m_data = json.load(mf)
            is_active = m_data.get("is_active", False)
            art_state = m_data.get("artifact_state", "EXPERIMENTAL")
            ml_status = {
                "status": "READY" if is_active else "EXPERIMENTAL",
                "bundle_id": m_data.get("bundle_id"),
                "bundle_version": m_data.get("bundle_version"),
                "artifact_state": art_state,
                "is_active": is_active,
                "note": "Production inference" if is_active else "Experimental model bundle; validation in progress",
                "stage": "STAGE_7",
            }
        else:
            ml_status = {"status": "NOT_CONFIGURED", "stage": "STAGE_7"}
    except Exception as exc:
        ml_status = {"status": "DEGRADED", "error": str(exc), "stage": "STAGE_7"}

    is_dev = getattr(settings, "APP_ENV", "development") != "production"
    redis_up = redis_result.get("status") == "UP"
    queue_mode = "DISTRIBUTED_REDIS" if redis_up else ("IN_PROCESS_EAGER" if is_dev else "UNAVAILABLE")

    dependencies = {
        "database": db_result,
        "redis": redis_result,
        "storage": storage_result,
        "queue_mode": {
            "mode": queue_mode,
            "redis_status": redis_result.get("status"),
            "is_fallback": not redis_up,
            "details": "Local synchronous mode (in-process eager execution; background queue unavailable)" if not redis_up else "Distributed Redis broker active",
        },
        "tshark": {
            "status": tshark_status,
            "version": tshark_ver,
            "engine": "tshark",
            "stage": "STAGE_3",
        },
        "live_capture": {
            "status": "AVAILABLE" if agent_result.available else "UNAVAILABLE",
            "stage": "STAGE_3",
        },
        "privileged_agent": agent_result.model_dump(),
        "ml_engine": ml_status,
        "policy_engine": policy_status,
    }

    db_up = db_result.get("status") == "UP"
    storage_up = storage_result.get("status") == "UP"

    # In development, database and storage are sufficient with eager in-process execution.
    # In production, distributed Redis is also mandatory.
    is_ready = db_up and storage_up and (redis_up or is_dev)

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        overall_status = "NOT_READY"
    else:
        response.status_code = status.HTTP_200_OK
        overall_status = "READY" if redis_up else "READY_LOCAL_DEV"

    return ReadinessResponse(
        status=overall_status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        stage="STAGE_3_CAPTURE_FORENSICS",
        dependencies=dependencies,
    )
