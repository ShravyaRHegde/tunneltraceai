# ==============================================================================
# TunnelTrace AI — Execution Class B strongSwan Lab Runner Dockerfile
# Smart India Hackathon 2026 | NTRO Problem Statement 26160
# ==============================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan \
    strongswan-swanctl \
    strongswan-pki \
    iproute2 \
    iptables \
    iputils-ping \
    tcpdump \
    tshark \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Install minimal Python dependencies for lab runner
RUN pip3 install --no-cache-dir \
    pyyaml \
    pydantic>=2.0 \
    requests

CMD ["python3", "-m", "lab.agent.doctor"]
