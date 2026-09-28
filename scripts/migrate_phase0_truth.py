"""Phase 0 Database Schema & Truth Reconciliation Migration.

Adds pipeline_version, policy_version, and is_archived columns to analysis_runs,
and reconciles legacy scores with current strict integrity gates.
"""

import sqlite3
import os
import sys

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
db_path = os.path.join(root_dir, "backend", "soc_dev.sqlite")

print(f"Connecting to database: {db_path}")
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# 1. Inspect existing columns
cursor.execute("PRAGMA table_info(analysis_runs)")
columns = [row[1] for row in cursor.fetchall()]
print(f"Existing analysis_runs columns: {columns}")

if "pipeline_version" not in columns:
    print("Adding column 'pipeline_version' to analysis_runs...")
    cursor.execute("ALTER TABLE analysis_runs ADD COLUMN pipeline_version VARCHAR(32) DEFAULT '1.0.0'")

if "policy_version" not in columns:
    print("Adding column 'policy_version' to analysis_runs...")
    cursor.execute("ALTER TABLE analysis_runs ADD COLUMN policy_version VARCHAR(32) DEFAULT '1.0.0'")

if "is_archived" not in columns:
    print("Adding column 'is_archived' to analysis_runs...")
    cursor.execute("ALTER TABLE analysis_runs ADD COLUMN is_archived BOOLEAN DEFAULT 0")

conn.commit()

# 2. Reconcile legacy scores in score_assessments
# If coverage_percentage < 50.0, the stored score should reflect INSUFFICIENT_EVIDENCE
print("\nReconciling legacy score_assessments records...")
cursor.execute("""
    UPDATE score_assessments
    SET status = 'INSUFFICIENT_EVIDENCE'
    WHERE coverage_percentage < 50.0 AND status != 'INSUFFICIENT_EVIDENCE'
""")
affected_scores = cursor.rowcount
print(f"Updated {affected_scores} score assessment record(s) to INSUFFICIENT_EVIDENCE.")

conn.commit()

# 3. Verify
cursor.execute("PRAGMA table_info(analysis_runs)")
updated_cols = [row[1] for row in cursor.fetchall()]
print(f"\nUpdated columns in analysis_runs: {updated_cols}")

cursor.execute("SELECT id, pipeline_version, policy_version, is_archived FROM analysis_runs LIMIT 5")
for row in cursor.fetchall():
    print(f"Run {row[0][:8]}... | pipe:{row[1]} | pol:{row[2]} | archived:{row[3]}")

conn.close()
print("\nPhase 0 schema migration successful!")
