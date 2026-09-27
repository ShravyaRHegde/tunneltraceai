"""System health endpoints: Liveness and Readiness probes."""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field

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

    dependencies = {
        "database": db_result,
        "redis": redis_result,
        "storage": storage_result,
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
        "ml_engine": {"status": "NOT_CONFIGURED", "stage": "STAGE_6"},
        "policy_engine": {"status": "NOT_CONFIGURED", "stage": "STAGE_8"},
    }

    # Stage-3 readiness criteria: Database, Redis, and Storage must all be UP
    is_ready = (
        db_result.get("status") == "UP"
        and redis_result.get("status") == "UP"
        and storage_result.get("status") == "UP"
    )

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        overall_status = "NOT_READY"
    else:
        response.status_code = status.HTTP_200_OK
        overall_status = "READY"

    return ReadinessResponse(
        status=overall_status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        stage="STAGE_3_CAPTURE_FORENSICS",
        dependencies=dependencies,
    )
