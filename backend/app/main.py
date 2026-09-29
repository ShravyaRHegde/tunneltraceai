"""FastAPI application factory, lifespan management, and global middleware configuration."""

import logging
import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.api.v1.router import api_v1_router
from app.core.config import Settings, get_settings
from app.core.errors import (
    TunnelTraceError,
    tunneltrace_error_handler,
    unhandled_exception_handler,
)
from app.core.logging import configure_logging
from app.core.request_context import clear_request_id, set_request_id
from app.db.session import close_db_connections
from app.services.redis_service import close_redis_connection
from app.services.storage import get_storage_provider

logger = logging.getLogger(__name__)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Middleware attaching a unique correlation request ID to every HTTP transaction."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        req_id = request.headers.get("X-Request-ID") or f"req_{uuid.uuid4().hex[:16]}"
        set_request_id(req_id)
        start_time = time.perf_counter()

        try:
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            response.headers["X-Request-ID"] = req_id
            response.headers["X-Response-Time"] = f"{duration_ms}ms"
            return response
        finally:
            clear_request_id()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager managing startup initialization and graceful shutdown."""
    settings = getattr(app.state, "settings", None) or get_settings()

    # Initialize structured logging
    configure_logging(log_level=settings.APP_LOG_LEVEL, app_env=settings.APP_ENV)
    logger.info(f"Starting {settings.APP_NAME} in '{settings.APP_ENV}' mode.")

    # Initialize local storage hierarchy
    storage = get_storage_provider()
    logger.info(f"Initialized storage provider with root: '{storage.root_path}'")

    yield

    # Graceful shutdown of persistent network pools
    logger.info("Initiating graceful shutdown sequence.")
    await close_db_connections()
    await close_redis_connection()
    logger.info("Shutdown sequence complete.")


def create_app(settings: Settings | None = None) -> FastAPI:
    """FastAPI application factory building a configured, production-ready ASGI instance."""
    app_settings = settings or get_settings()

    # Disable interactive API docs in production environments unless debug is forced
    docs_url = "/docs" if (app_settings.APP_DEBUG or not app_settings.is_production) else None
    redoc_url = "/redoc" if (app_settings.APP_DEBUG or not app_settings.is_production) else None
    openapi_url = (
        "/openapi.json" if (app_settings.APP_DEBUG or not app_settings.is_production) else None
    )

    app = FastAPI(
        title="TunnelTrace AI API",
        description="Explainable IPsec VPN Security Intelligence & Protocol Assessment Platform",
        version="0.1.0",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )
    app.state.settings = app_settings

    # 1. Attach Request Context & Traceability Middleware
    app.add_middleware(RequestContextMiddleware)

    # 2. Attach CORS Middleware with Strict Origin Allowlist
    cors_kwargs = {
        "allow_origins": app_settings.CORS_ALLOWED_ORIGINS,
        "allow_credentials": app_settings.CORS_ALLOW_CREDENTIALS,
        "allow_methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        "allow_headers": ["*"],
        "expose_headers": ["X-Request-ID", "X-Response-Time"],
    }
    if app_settings.CORS_ORIGIN_REGEX:
        cors_kwargs["allow_origin_regex"] = app_settings.CORS_ORIGIN_REGEX
    app.add_middleware(CORSMiddleware, **cors_kwargs)

    # 3. Register Domain and Catch-all Exception Handlers
    app.add_exception_handler(TunnelTraceError, tunneltrace_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_exception_handler)

    # 4. Mount API v1 Routers under /api prefix
    app.include_router(api_v1_router, prefix="/api")

    # 5. Cloud deployment health probes (Render, AWS ALB, Docker HEALTHCHECK)
    @app.get("/health", tags=["System"])
    @app.get("/api/v1/health", tags=["System"])
    async def root_health_check() -> dict[str, str]:
        return {"status": "healthy", "service": "TunnelTrace AI", "version": "0.1.0"}

    return app


# Root app instance for default uvicorn execution
app = create_app()
