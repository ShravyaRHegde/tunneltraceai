#!/usr/bin/env bash
# ==============================================================================
# TunnelTrace AI — Automated WSL2 / Linux strongSwan Lab Runner
# Smart India Hackathon 2026 | NTRO Problem Statement 26160
# ==============================================================================
# Executes isolated IPsec testbed scenarios inside Linux network namespaces.
#
# Usage:
#   sudo bash scripts/run_lab_wsl2.sh [SCENARIO_ID]
#
# Examples:
#   sudo bash scripts/run_lab_wsl2.sh scn-01-tunnel-v4-gcm-pfs
#   sudo bash scripts/run_lab_wsl2.sh scn-05-tunnel-v4-netem
# ==============================================================================

set -euo pipefail

SCENARIO="${1:-scn-01-tunnel-v4-gcm-pfs}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "========================================================================"
echo "🛡️ TunnelTrace AI — Testbed Experiment Runner (WSL2 / Linux)"
echo "Target Scenario: ${SCENARIO}"
echo "Project Root:    ${PROJECT_ROOT}"
echo "========================================================================"

# 1. Privilege Check
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: Lab execution requires root / CAP_NET_ADMIN privileges." >&2
    echo "   Please re-run with: sudo bash scripts/run_lab_wsl2.sh ${SCENARIO}" >&2
    exit 1
fi

# 2. Dependency Checks
command -v ip >/dev/null 2>&1 || { echo "❌ iproute2 (ip) is required but not installed. Run: apt-get install -y iproute2" >&2; exit 1; }
command -v tcpdump >/dev/null 2>&1 || { echo "❌ tcpdump is required but not installed. Run: apt-get install -y tcpdump" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "❌ python3 is required. Run: apt-get install -y python3" >&2; exit 1; }

# 3. Pre-flight Environment Doctor
cd "${PROJECT_ROOT}"
echo "🔍 Running preflight environment checks..."
python3 -m lab.agent.doctor || {
    echo "⚠️ Preflight doctor reported issues. Continuing with scenario execution..."
}

# 4. Execute Experiment
echo "🚀 Executing scenario: ${SCENARIO} inside isolated namespaces..."
python3 -m lab.agent.operations.runner --scenario "${SCENARIO}"

echo "========================================================================"
echo "✅ Scenario execution complete."
echo "   Artifacts written to storage/lab/runs/"
echo "   Ingest WAN capture via: POST /api/v1/captures"
echo "========================================================================"
