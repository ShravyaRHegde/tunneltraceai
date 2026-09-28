from fastapi import APIRouter

from app.api.v1.analyses.router import router as analyses_router
from app.api.v1.captures.router import router as captures_router
from app.api.v1.datasets.router import router as datasets_router
from app.api.v1.live_captures.router import router as live_captures_router
from app.api.v1.reconstruction.router import router as reconstruction_router
from app.api.v1.remediation.router import router as remediation_router
from app.api.v1.reporting.router import router as reporting_router
from app.api.v1.security.router import router as security_router
from app.api.v1.system.health import router as health_router
from app.api.v1.websocket.router import router as ws_router

api_v1_router = APIRouter(prefix="/v1")

# Mount system health endpoints
api_v1_router.include_router(health_router, prefix="/system")

# Mount Stage 3 capture and protocol forensics endpoints
api_v1_router.include_router(captures_router)
api_v1_router.include_router(analyses_router)
api_v1_router.include_router(live_captures_router)

# Mount Stage 4 reconstruction endpoints
api_v1_router.include_router(reconstruction_router)

# Mount Stage 5 dataset factory and benchmark endpoints
api_v1_router.include_router(datasets_router)

# Mount Stage 8 security, compliance, evidence and scoring endpoints
api_v1_router.include_router(security_router)

# Mount Stage 9 reporting endpoints
api_v1_router.include_router(reporting_router)

# Mount Stage 10 twin and closed-loop remediation endpoints
api_v1_router.include_router(remediation_router)

# Mount Stage 9 realtime WebSocket endpoints
api_v1_router.include_router(ws_router)

# Mount Stage 11 Grounded AI Analyst and RAG endpoints
from app.api.v1.ai.router import router as ai_router
api_v1_router.include_router(ai_router)

# Mount Stage 2 Authorized Asset Discovery endpoints
from app.api.v1.discovery.router import router as discovery_router
api_v1_router.include_router(discovery_router)

# Mount Stage 3 IKE/IPsec Negotiation Assessment endpoints
from app.api.v1.protocol.ike_router import router as ike_router
api_v1_router.include_router(ike_router)

# Mount External Vulnerability Assessment Reports (Greenbone/OpenVAS) endpoints
from app.api.v1.vulnerabilities.router import router as vulnerabilities_router
api_v1_router.include_router(vulnerabilities_router)

# Mount Continuous Monitoring endpoints
from app.api.v1.monitoring.router import router as monitoring_router
api_v1_router.include_router(monitoring_router)

# Mount Configuration and Certificate Inventory endpoints
from app.api.v1.inventory.router import router as inventory_router
api_v1_router.include_router(inventory_router, prefix="/inventory")

# Mount Lab Testbed Scenarios and Verification endpoints
from app.api.v1.lab.router import router as lab_router
api_v1_router.include_router(lab_router)
