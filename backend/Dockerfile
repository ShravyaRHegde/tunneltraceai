# ==============================================================================
# TunnelTrace AI — Hardened Backend Dockerfile (Class A Unprivileged)
# ==============================================================================
# Multi-stage build to produce a minimal, non-root runtime image
# Runtime user: appuser (UID: 10001, GID: 10001)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build & Dependencies
# ------------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install .

# ------------------------------------------------------------------------------
# Stage 2: Final Runtime Image
# ------------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/install/bin:${PATH}" \
    PYTHONPATH="/app:${PYTHONPATH}"

# Install minimal runtime shared libraries, TShark, and create non-root user
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* && \
    groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser && \
    mkdir -p /var/lib/tunneltrace/storage /app && \
    chown -R 10001:10001 /var/lib/tunneltrace/storage /app

# Copy installed Python packages from builder
COPY --from=builder /install /install

# Copy application source code
COPY --chown=10001:10001 app /app/app
COPY --chown=10001:10001 alembic /app/alembic
COPY --chown=10001:10001 alembic.ini /app/alembic.ini
COPY --chown=10001:10001 pyproject.toml /app/pyproject.toml

# Switch to unprivileged non-root user
USER 10001:10001

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:create_app --factory --host 0.0.0.0 --port ${PORT:-8000}"]
