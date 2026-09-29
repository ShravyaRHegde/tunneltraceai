"""Typed application configuration management using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Canonical configuration model for TunnelTrace AI."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --------------------------------------------------------------------------
    # Application Runtime Settings
    # --------------------------------------------------------------------------
    APP_NAME: str = Field(default="TunnelTrace AI", description="System application name")
    APP_ENV: str = Field(
        default="development", description="Environment: development, test, production"
    )
    APP_DEBUG: bool = Field(default=False, description="Enable debug mode (disables in production)")
    APP_HOST: str = Field(default="127.0.0.1", description="Host address for loopback binding")
    APP_PORT: int = Field(default=8000, description="HTTP listening port")
    APP_LOG_LEVEL: str = Field(default="INFO", description="Log level: DEBUG, INFO, WARNING, ERROR")
    APP_SECRET_KEY: SecretStr = Field(
        default=SecretStr("insecure-local-dev-secret-change-in-production-min32chars"),
        description="Internal encryption and session signing key",
    )
    API_V1_PREFIX: str = Field(default="/api/v1", description="API version namespace prefix")
    CURRENT_PIPELINE_VERSION: str = Field(default="2.0.0", description="Current analysis pipeline version")
    CURRENT_POLICY_VERSION: str = Field(default="1.0.0", description="Current security policy baseline version")

    # --------------------------------------------------------------------------
    # Database Settings (PostgreSQL 15+ with pgvector)
    # --------------------------------------------------------------------------
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://tunneltrace_user:tunneltrace_dev_password@127.0.0.1:5432/tunneltrace_db",
        description="Async SQLAlchemy database connection URI",
    )
    DATABASE_POOL_SIZE: int = Field(default=10, description="SQLAlchemy connection pool size")
    DATABASE_MAX_OVERFLOW: int = Field(
        default=5, description="Max overflow connections beyond pool size"
    )
    DATABASE_POOL_TIMEOUT: float = Field(
        default=30.0, description="Seconds to wait before giving up on acquiring connection"
    )
    DATABASE_ECHO: bool = Field(default=False, description="Log raw SQL queries for debugging")

    # --------------------------------------------------------------------------
    # Redis Settings (Caching & Asynchronous Broker)
    # --------------------------------------------------------------------------
    REDIS_URL: str = Field(
        default="redis://127.0.0.1:6379/0",
        description="Redis connection URI for broker and transient data",
    )
    REDIS_SOCKET_TIMEOUT: float = Field(
        default=2.0, description="Timeout in seconds for Redis socket operations"
    )
    REDIS_MAX_CONNECTIONS: int = Field(
        default=10, description="Maximum concurrent connection pool size for Redis"
    )
    REDIS_TIMEOUT: float = Field(
        default=2.0, description="General timeout in seconds for Redis operations"
    )

    # --------------------------------------------------------------------------
    # Celery Worker Settings
    # --------------------------------------------------------------------------
    CELERY_TASK_SERIALIZER: str = Field(
        default="json", description="Task payload serialization format (strict JSON)"
    )
    CELERY_RESULT_SERIALIZER: str = Field(
        default="json", description="Result payload serialization format"
    )
    CELERY_ACCEPT_CONTENT: list[str] = Field(
        default_factory=lambda: ["json"], description="Accepted serializers"
    )

    # --------------------------------------------------------------------------
    # Local Storage Settings
    # --------------------------------------------------------------------------
    STORAGE_ROOT: Path = Field(
        default=Path("./storage"),
        description="Root filesystem path for non-DB storage (captures, reports, temp files)",
    )

    # --------------------------------------------------------------------------
    # HTTP & CORS Security Settings
    # --------------------------------------------------------------------------
    CORS_ALLOWED_ORIGINS: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:3002",
            "http://127.0.0.1:3002",
        ],
        description="List of allowed CORS origins (never wildcard * in production)",
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True, description="Allow credentials in CORS")
    CORS_ORIGIN_REGEX: str | None = Field(
        default=r"https://.*\.vercel\.app",
        description="Optional regex pattern for allowed CORS origins (e.g. Vercel deployments)",
    )

    # --------------------------------------------------------------------------
    # Stage 3: Capture Ingestion & Protocol Forensics Settings
    # --------------------------------------------------------------------------
    CAPTURE_MAX_UPLOAD_BYTES: int = Field(
        default=250 * 1024 * 1024,
        description="Implementation safety default for maximum upload size in bytes (not official product limit)",
    )
    CAPTURE_MAX_DURATION_SEC: int = Field(
        default=300,
        description="Implementation safety default for live capture duration limit in seconds",
    )
    CAPTURE_MAX_BYTES: int = Field(
        default=500 * 1024 * 1024,
        description="Implementation safety default for live capture maximum byte volume",
    )
    TSHARK_TIMEOUT_SEC: float = Field(
        default=60.0,
        description="Implementation safety default for TShark subprocess execution timeout",
    )
    TSHARK_PATH: str | None = Field(
        default=None,
        description="Optional custom path to TShark binary",
    )
    CAPINFOS_PATH: str | None = Field(
        default=None,
        description="Optional custom path to Capinfos binary",
    )

    # --------------------------------------------------------------------------
    # Stage 2: Authorized Asset Discovery Settings (Nmap)
    # --------------------------------------------------------------------------
    DISCOVERY_ENABLED: bool = Field(
        default=True,
        description="Master toggle for active network discovery subsystem",
    )
    DISCOVERY_ALLOW_UNAUTHENTICATED_LOCAL: bool = Field(
        default=True,
        description="Permit local test mode discovery without enterprise identity provider",
    )
    DISCOVERY_MAX_TARGETS: int = Field(
        default=8,
        description="Conservative hard cap on total expanded IP targets per discovery job",
    )
    DISCOVERY_MAX_PORTS: int = Field(
        default=16,
        description="Conservative hard cap on total permitted ports per discovery job",
    )
    DISCOVERY_TIMEOUT_SEC: float = Field(
        default=30.0,
        description="Execution timeout in seconds for Nmap discovery subprocess",
    )
    DISCOVERY_MAX_OUTPUT_BYTES: int = Field(
        default=1_048_576,
        description="Maximum allowed XML output size in bytes (1 MB default)",
    )
    DISCOVERY_RATE_LIMIT_PPS: int = Field(
        default=100,
        description="Maximum packet rate per second passed to Nmap --max-rate",
    )
    NMAP_PATH: str | None = Field(
        default=None,
        description="Optional custom path to Nmap binary",
    )

    # --------------------------------------------------------------------------
    # Stage 3: Authorized IKE/IPsec Negotiation Assessment Settings (IKE-scan)
    # --------------------------------------------------------------------------
    IKE_ASSESSMENT_ENABLED: bool = Field(
        default=True,
        description="Master toggle for active IKE negotiation assessment subsystem",
    )
    IKE_SCAN_PATH: str | None = Field(
        default=None,
        description="Optional custom path to ike-scan binary",
    )
    IKE_SCAN_TIMEOUT_SEC: float = Field(
        default=15.0,
        description="Execution timeout in seconds for ike-scan subprocess",
    )
    IKE_SCAN_MAX_RETRY: int = Field(
        default=2,
        description="Maximum retransmission retries passed to ike-scan --retry",
    )
    IKE_SCAN_BACKOFF_SEC: float = Field(
        default=2.0,
        description="Backoff factor passed to ike-scan --backoff",
    )
    IKE_SCAN_MAX_OUTPUT_BYTES: int = Field(
        default=262_144,
        description="Maximum allowed stdout size in bytes for ike-scan (256 KB default)",
    )
    IKE_SCAN_ALLOW_EXPERIMENTAL_V2: bool = Field(
        default=True,
        description="Allow explicitly requested experimental IKEv2 default proposal probe",
    )

    # --------------------------------------------------------------------------
    # Future Subsystem Boundaries (Placeholders for upcoming stages)
    # --------------------------------------------------------------------------
    NETAGENT_ENABLED: bool = Field(
        default=False, description="Whether privileged network agent is enabled"
    )
    NETAGENT_ENDPOINT: str = Field(
        default="http://127.0.0.1:8001", description="Privileged agent endpoint"
    )
    POLICIES_DIR: Path = Field(
        default=Path("./policies/active"), description="Directory for Policy-as-Code rules"
    )
    MODELS_DIR: Path = Field(
        default=Path("./models/active"), description="Directory for ML model artifacts"
    )

    # --------------------------------------------------------------------------
    # Stage 11: Grounded AI Analyst / Local RAG Settings
    # --------------------------------------------------------------------------
    OLLAMA_BASE_URL: str = Field(
        default="http://localhost:11434", description="Base URL for local Ollama runtime"
    )
    AI_PRIMARY_MODEL: str = Field(
        default="qwen3:4b-instruct-2507-q4_K_M",
        description="Primary local chat LLM (empirically benchmarked for fast structured generation)",
    )
    AI_FALLBACK_MODEL: str = Field(
        default="gemma3:4b",
        description="Secondary fallback local chat LLM",
    )
    AI_EMBEDDING_MODEL: str = Field(
        default="nomic-embed-text",
        description="Local embedding model name in Ollama",
    )
    AI_EMBEDDING_DIM: int = Field(
        default=768,
        description="Vector dimension for embeddings (768 for nomic-embed-text)",
    )
    AI_REQUEST_TIMEOUT_SEC: float = Field(
        default=6.0,
        description="Local LLM inference timeout in seconds (bounded to avoid UI hanging)",
    )
    AI_MAX_CONCURRENCY: int = Field(
        default=2,
        description="Maximum concurrent generation requests to local model runtime",
    )
    STANDARDS_DIR: Path = Field(
        default=Path("./knowledge/standards"),
        description="Directory containing approved markdown standards documents",
    )
    AI_SYSTEM_PROMPT_VERSION: str = Field(
        default="v1.0.0-grounded",
        description="Version identifier for strict grounding prompt template",
    )
    AI_RETRIEVAL_TOP_K: int = Field(
        default=5,
        description="Default number of chunks to retrieve for semantic search",
    )
    AI_RETRIEVAL_SIMILARITY_THRESHOLD: float = Field(
        default=0.40,
        description="Cosine similarity threshold for standards retrieval",
    )
    AI_ENABLE_LEXICAL_SEARCH: bool = Field(
        default=True,
        description="Enable lexical/keyword hybrid retrieval alongside pgvector",
    )

    # --------------------------------------------------------------------------
    # Continuous Monitoring Settings
    # --------------------------------------------------------------------------
    MONITORING_ENABLED: bool = Field(
        default=True,
        description="Master toggle for the continuous monitoring subsystem",
    )
    MONITORING_DEFAULT_FRESHNESS_WINDOW_SECONDS: int = Field(
        default=60,
        description="Time in seconds without events before a sensor is declared STALE",
    )
    MONITORING_DEFAULT_REPORTING_INTERVAL_SECONDS: int = Field(
        default=30,
        description="Expected heartbeat/reporting cadence in seconds for sensors",
    )
    MONITORING_MAX_BATCH_SIZE: int = Field(
        default=100,
        description="Maximum event count permitted in a single ingestion batch",
    )
    MONITORING_MAX_EVENT_PAYLOAD_BYTES: int = Field(
        default=65536,
        description="Maximum byte size permitted for an individual event payload",
    )
    MONITORING_ALLOW_UNAUTHENTICATED_LOCAL: bool = Field(
        default=True,
        description="Allow local development/test clients to submit events without sensor token",
    )
    MONITORING_CLOCK_SKEW_TOLERANCE_SECONDS: float = Field(
        default=5.0,
        description="Clock skew threshold in seconds triggering DEGRADED quality warning",
    )

    # --------------------------------------------------------------------------
    # Data Retention & Lifecycle Settings
    # --------------------------------------------------------------------------
    RETENTION_PCAP_DAYS: int = Field(
        default=30,
        description="Default retention period in days for raw packet captures (0 for indefinite)",
    )
    RETENTION_REPORT_DAYS: int = Field(
        default=90,
        description="Default retention period in days for generated HTML/PDF reports",
    )
    RETENTION_TEMP_FILES_HOURS: int = Field(
        default=24,
        description="Default retention period in hours for temporary staging files in storage/tmp",
    )
    RETENTION_AUDIT_LOG_DAYS: int = Field(
        default=365,
        description="Default retention period in days for operational security audit records",
    )

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        """Fail closed on insecure configurations in production mode."""
        if self.is_production:
            secret = self.APP_SECRET_KEY.get_secret_value()
            if secret == "insecure-local-dev-secret-change-in-production-min32chars":
                raise ValueError(
                    "Security Violation: APP_SECRET_KEY must be overridden with a secure secret in production (APP_ENV=production)."
                )
            if len(secret) < 32:
                raise ValueError(
                    "Security Violation: APP_SECRET_KEY must be at least 32 characters in production."
                )
            if self.APP_DEBUG:
                raise ValueError("Security Violation: APP_DEBUG must be False in production.")
            if "*" in self.CORS_ALLOWED_ORIGINS:
                raise ValueError(
                    "Security Violation: Wildcard '*' in CORS_ALLOWED_ORIGINS is prohibited in production."
                )
            if self.MONITORING_ALLOW_UNAUTHENTICATED_LOCAL:
                raise ValueError(
                    "Security Violation: MONITORING_ALLOW_UNAUTHENTICATED_LOCAL must be False in production."
                )
            if self.DISCOVERY_ALLOW_UNAUTHENTICATED_LOCAL:
                raise ValueError(
                    "Security Violation: DISCOVERY_ALLOW_UNAUTHENTICATED_LOCAL must be False in production."
                )
        return self

    @field_validator("CORS_ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: object) -> list[str]:
        if isinstance(v, str):
            import json

            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return [str(item) for item in parsed]
            except Exception:
                return [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, (list, tuple, set)):
            return [str(origin) for origin in v]
    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def resolve_database_url(cls, v: object) -> str:
        if isinstance(v, str) and v.strip():
            url = v.strip()
            if url.startswith("postgresql") and "127.0.0.1:5432" in url:
                for candidate in [
                    Path("/app/backend/soc_dev.sqlite"),
                    Path("backend/soc_dev.sqlite"),
                    Path("soc_dev.sqlite"),
                ]:
                    if candidate.exists():
                        return f"sqlite+aiosqlite:///{candidate.resolve().as_posix()}"
            return url
        for candidate in [
            Path("/app/backend/soc_dev.sqlite"),
            Path("backend/soc_dev.sqlite"),
            Path("soc_dev.sqlite"),
        ]:
            if candidate.exists():
                return f"sqlite+aiosqlite:///{candidate.resolve().as_posix()}"
        return "postgresql+asyncpg://tunneltrace_user:tunneltrace_dev_password@127.0.0.1:5432/tunneltrace_db"

    @property
    def sync_database_url(self) -> str:
        """Derive synchronous database URL for Alembic migrations and synchronous drivers."""
        url = self.DATABASE_URL
        if url.startswith("postgresql+asyncpg://"):
            return url.replace("postgresql+asyncpg://", "postgresql://", 1)
        return url

    @property
    def is_production(self) -> bool:
        """Check whether the active environment is production."""
        return self.APP_ENV.lower() == "production"

    @property
    def CELERY_BROKER_URL(self) -> str:
        """Celery broker URI matching Redis configuration."""
        return self.REDIS_URL

    @property
    def CELERY_RESULT_BACKEND(self) -> str:
        """Celery result backend URI matching Redis configuration."""
        return self.REDIS_URL

    # --------------------------------------------------------------------------
    # Lowercase property accessors for uniform API ergonomics
    # --------------------------------------------------------------------------
    @property
    def app_name(self) -> str:
        return self.APP_NAME

    @property
    def app_env(self) -> str:
        return self.APP_ENV

    @property
    def app_debug(self) -> bool:
        return self.APP_DEBUG

    @property
    def app_host(self) -> str:
        return self.APP_HOST

    @property
    def app_port(self) -> int:
        return self.APP_PORT

    @property
    def app_log_level(self) -> str:
        return self.APP_LOG_LEVEL

    @property
    def api_v1_prefix(self) -> str:
        return self.API_V1_PREFIX

    @property
    def database_url(self) -> str:
        return self.DATABASE_URL

    @property
    def database_pool_size(self) -> int:
        return self.DATABASE_POOL_SIZE

    @property
    def redis_url(self) -> str:
        return self.REDIS_URL

    @property
    def redis_socket_timeout(self) -> float:
        return self.REDIS_SOCKET_TIMEOUT

    @property
    def redis_max_connections(self) -> int:
        return self.REDIS_MAX_CONNECTIONS

    @property
    def storage_root(self) -> Path:
        return self.STORAGE_ROOT

    @property
    def cors_allowed_origins(self) -> list[str]:
        return self.CORS_ALLOWED_ORIGINS

    @property
    def netagent_enabled(self) -> bool:
        return self.NETAGENT_ENABLED

    @property
    def netagent_endpoint(self) -> str:
        return self.NETAGENT_ENDPOINT

    @property
    def discovery_enabled(self) -> bool:
        return self.DISCOVERY_ENABLED

    @property
    def nmap_path(self) -> str | None:
        return self.NMAP_PATH

    def masked_dict(self) -> dict[str, object]:
        """Return configuration dictionary with all credentials safely masked."""
        data = self.model_dump()
        # Redact secrets
        if "APP_SECRET_KEY" in data:
            data["APP_SECRET_KEY"] = "***REDACTED***"
        if "DATABASE_URL" in data and isinstance(data["DATABASE_URL"], str):
            import re

            data["DATABASE_URL"] = re.sub(
                r"://([^:]+):([^@]+)@", r"://\1:***@", data["DATABASE_URL"]
            )
        if "REDIS_URL" in data and isinstance(data["REDIS_URL"], str):
            import re

            data["REDIS_URL"] = re.sub(r"://:([^@]+)@", r"://:***@", data["REDIS_URL"])

        # Populate lowercase aliases for uniform consumer access
        for key in list(data.keys()):
            data[key.lower()] = data[key]

        return data

    def __repr__(self) -> str:
        masked = self.masked_dict()
        return f"Settings({masked})"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Singleton getter for application settings."""
    return Settings()


# Convenient module-level alias
settings: Settings = get_settings()
