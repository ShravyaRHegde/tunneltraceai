"""Truth Reconciliation Audit Script for TunnelTrace AI.

Walks every stored analysis run in the database and re-summarizes:
- Analysis ID & Created At
- Capture SHA-256 & Filename
- Pipeline & Policy Versions
- Stored Posture Score & Coverage %
- Actual Risk Tier & Evaluation Counts
"""

import asyncio
import os
import sys

# Ensure root and backend directory in sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

db_path = os.path.join(backend_dir, "soc_dev.sqlite").replace("\\", "/")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.models.capture import AnalysisRun, Capture
from app.db.models.security import (
    ComplianceEvaluationModel,
    RiskAssessmentModel,
    ScoreAssessmentModel,
    SecurityFindingModel,
)
from app.db.session import get_session_factory


async def run_audit():
    print("=" * 110)
    print("TUNNELTRACE AI — TRUTH RECONCILIATION AUDIT (PHASE 0)")
    print("=" * 110)

    factory = get_session_factory()
    async with factory() as db:
        stmt = (
            select(AnalysisRun)
            .options(selectinload(AnalysisRun.capture))
            .order_by(AnalysisRun.created_at.asc())
        )
        res = await db.execute(stmt)
        analyses = res.scalars().all()

        print(f"Total analysis runs stored in database: {len(analyses)}\n")

        headers = [
            "Analysis ID",
            "Created At (UTC)",
            "Capture Filename",
            "SHA256 (prefix)",
            "Pkts",
            "Stored Score",
            "Coverage",
            "Risk Tier",
            "Pass/Fail/Unk",
            "Pipeline/Policy Ver",
        ]
        row_fmt = "{:<12} | {:<16} | {:<22} | {:<10} | {:<5} | {:<12} | {:<8} | {:<14} | {:<13} | {:<15}"

        print(row_fmt.format(*headers))
        print("-" * 140)

        runs_by_sha = {}

        for a in analyses:
            c = a.capture
            c_sha = c.sha256_hash if c else "UNKNOWN"
            c_fn = (c.original_filename or "unknown")[:22] if c else "None"
            pkts = str(c.packet_count or 0) if c else "0"
            created = a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else "Unknown"

            # Query ScoreAssessmentModel
            stmt_score = (
                select(ScoreAssessmentModel)
                .where(ScoreAssessmentModel.analysis_id == a.id)
                .order_by(ScoreAssessmentModel.created_at.desc())
            )
            score_row = (await db.execute(stmt_score)).scalars().first()

            # Query RiskAssessmentModel
            stmt_risk = (
                select(RiskAssessmentModel)
                .where(RiskAssessmentModel.analysis_id == a.id)
                .order_by(RiskAssessmentModel.created_at.desc())
            )
            risk_row = (await db.execute(stmt_risk)).scalars().first()

            # Query Compliance evaluations
            stmt_comp = (
                select(ComplianceEvaluationModel)
                .where(ComplianceEvaluationModel.analysis_id == a.id)
            )
            evals = (await db.execute(stmt_comp)).scalars().all()
            pass_c = sum(1 for e in evals if e.compliance_state == "PASS")
            fail_c = sum(1 for e in evals if e.compliance_state == "FAIL")
            unk_c = sum(1 for e in evals if e.compliance_state == "UNKNOWN")
            comp_str = f"{pass_c}P / {fail_c}F / {unk_c}U"

            score_str = "None"
            cov_str = "N/A"
            if score_row:
                score_str = f"{score_row.overall_score:.1f} ({score_row.status[:5]})"
                cov_str = f"{score_row.coverage_percentage:.1f}%"

            risk_str = risk_row.overall_risk_tier if risk_row else "None"
            pipe_ver = getattr(a, "pipeline_version", getattr(a, "schema_version", "1.0.0"))
            pol_ver = score_row.score_policy_version if score_row else getattr(risk_row, "risk_policy_version", "1.0.0")
            ver_str = f"pipe:{pipe_ver}/pol:{pol_ver}"

            print(
                row_fmt.format(
                    str(a.id)[:12],
                    created,
                    c_fn,
                    c_sha[:10],
                    pkts,
                    score_str,
                    cov_str,
                    risk_str[:14],
                    comp_str,
                    ver_str,
                )
            )

            runs_by_sha.setdefault(c_sha, []).append({
                "id": str(a.id),
                "created": created,
                "fn": c_fn,
                "score": score_str,
                "cov": cov_str,
                "risk": risk_str,
                "ver": ver_str,
            })

        print("-" * 140)
        print("\nDUPLICATE INGESTION ANALYSIS BY CAPTURE SHA-256:")
        for sha, runs in runs_by_sha.items():
            if len(runs) > 1:
                print(f"\n[!] Capture SHA-256: {sha} ({runs[0]['fn']}) ingested {len(runs)} times:")
                for r in runs:
                    print(f"    - Run {r['id']} | Created: {r['created']} | Score: {r['score']} | Cov: {r['cov']} | Risk: {r['risk']} | {r['ver']}")
            else:
                print(f"[-] Capture SHA-256: {sha[:16]}... ({runs[0]['fn']}): 1 unique run ({runs[0]['id']})")

        print("\n" + "=" * 110)


if __name__ == "__main__":
    asyncio.run(run_audit())
