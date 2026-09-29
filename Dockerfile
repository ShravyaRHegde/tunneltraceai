# ==============================================================================
# TunnelTrace AI — Production Backend Dockerfile (Class A)
# Optimized for Local-First, Render, and Cloud Container Deployments
# Smart India Hackathon 2026 | NTRO Problem Statement ID: 26160
# ==============================================================================
FROM python:3.11-slim-bookworm AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app/backend:/app:${PYTHONPATH}" \
    DEBIAN_FRONTEND=noninteractive \
    APP_ENV=production \
    APP_DEBUG=false \
    STORAGE_ROOT="/app/storage" \
    DATABASE_URL="sqlite+aiosqlite:////app/backend/soc_dev.sqlite"

# 1. Install system utilities and TShark for packet forensics
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    libpcap-dev \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 2. Install PyTorch CPU-only first (saves ~2GB image weight and build memory)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# 3. Copy requirements and install Python dependencies
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 4. Copy repository assets required for runtime
COPY backend /app/backend
COPY policies /app/policies
COPY models /app/models
COPY knowledge /app/knowledge
COPY tests/fixtures/captures /app/tests/fixtures/captures

# 5. Create storage directories and set permissions for non-root execution
RUN mkdir -p /app/storage/captures /app/storage/reports /app/storage/tmp /app/captures/golden && \
    groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser && \
    chown -R 10001:10001 /app

# 6. Switch to unprivileged user (Class A security model)
USER 10001:10001

# 7. Expose default port
EXPOSE 8000

# 8. Start uvicorn dynamically binding to $PORT (Render injects $PORT, fallback 8000)
CMD ["sh", "-c", "uvicorn app.main:create_app --factory --host 0.0.0.0 --port ${PORT:-8000}"]
