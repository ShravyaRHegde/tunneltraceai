"use client";

import React, { useState, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { StatusBadge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  CopyableValue,
} from "@/components/ui/table";
import { Plus, Search, Layers, ChevronRight, ChevronDown, AlertCircle, RefreshCw, Archive, Trash2, RotateCcw } from "lucide-react";
import { formatCoverage } from "@/lib/format";
import { ScoreDisplay } from "@/components/ui/score-display";

function AnalysesListContent() {
  const [search, setSearch] = useState("");
  const [includeArchived, setIncludeArchived] = useState(false);
  const [groupByHash, setGroupByHash] = useState(true);
  const [expandedClusters, setExpandedClusters] = useState<Record<string, boolean>>({});
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);
  const searchParams = useSearchParams();
  const action = searchParams.get("action");

  const {
    data: analyses,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ["analyses-list", includeArchived],
    queryFn: () => api.analyses.list(includeArchived),
  });

  const handleArchive = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setActionInProgress(id);
    try {
      await api.analyses.archive(id);
      refetch();
    } catch (err: any) {
      alert(`Failed to archive run: ${err.message}`);
    } finally {
      setActionInProgress(null);
    }
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm(`Permanently delete analysis run ${id.slice(0, 8)}? This cannot be undone.`)) {
      return;
    }
    setActionInProgress(id);
    try {
      await api.analyses.delete(id);
      refetch();
    } catch (err: any) {
      alert(`Failed to delete run: ${err.message}`);
    } finally {
      setActionInProgress(null);
    }
  };

  const filteredAnalyses = (analyses || []).filter((item) => {
    const q = search.toLowerCase();
    return (
      item.analysis_id.toLowerCase().includes(q) ||
      (item.capture_filename && item.capture_filename.toLowerCase().includes(q)) ||
      (item.capture_sha256 && item.capture_sha256.toLowerCase().includes(q))
    );
  });

interface ClusterDisposition {
  type: "DETERMINISTIC" | "VARIED" | "NOT_COMPARABLE" | "INCOMPLETE";
  label: string;
  reason: string;
  badgeClass: string;
}

function evaluateClusterDisposition(runs: any[]): ClusterDisposition {
  if (runs.length <= 1) {
    return {
      type: "DETERMINISTIC",
      label: "SINGLE RUN",
      reason: "Single ingest",
      badgeClass: "text-neutral-500 bg-neutral-100 dark:bg-neutral-800 border-neutral-300 dark:border-neutral-700",
    };
  }

  // 1. Check for non-completed runs
  const nonCompleted = runs.filter((r) => r.status !== "COMPLETED");
  if (nonCompleted.length > 0) {
    return {
      type: "INCOMPLETE",
      label: "INCOMPLETE",
      reason: `${nonCompleted.length} replay run(s) did not complete`,
      badgeClass: "text-rose-700 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800",
    };
  }

  // 2. Check for pipeline / policy version divergence
  const pipeVers = new Set(runs.map((r) => r.pipeline_version || "1.0.0"));
  const polVers = new Set(runs.map((r) => r.policy_version || "1.0.0"));
  if (pipeVers.size > 1 || polVers.size > 1) {
    return {
      type: "NOT_COMPARABLE",
      label: "NOT COMPARABLE",
      reason: `Pipeline [${Array.from(pipeVers).join(", ")}] / Policy [${Array.from(polVers).join(", ")}] versions diverge`,
      badgeClass: "text-neutral-700 dark:text-neutral-300 bg-neutral-100 dark:bg-neutral-800 border-neutral-300 dark:border-neutral-700",
    };
  }

  // 3. Assessability check
  const assessable = runs.filter((r) => r.security_score !== null && r.security_score !== undefined);
  if (assessable.length > 0 && assessable.length < runs.length) {
    return {
      type: "NOT_COMPARABLE",
      label: "NOT COMPARABLE",
      reason: "Some replays assessable, others insufficient evidence",
      badgeClass: "text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800",
    };
  }

  if (assessable.length === 0) {
    return {
      type: "DETERMINISTIC",
      label: "DETERMINISTIC",
      reason: "Consistently unassessable (zero observable evidence across all replays)",
      badgeClass: "text-emerald-800 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800",
    };
  }

  // 4. Score variance check
  const scores = assessable.map((r) => r.security_score as number);
  const minScore = Math.min(...scores);
  const maxScore = Math.max(...scores);
  if (minScore !== maxScore) {
    return {
      type: "VARIED",
      label: `VARIANCE (${minScore}–${maxScore})`,
      reason: `Score delta between runs: ${minScore} to ${maxScore}`,
      badgeClass: "text-amber-900 dark:text-amber-300 bg-amber-100 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800",
    };
  }

  // 5. Findings count variance check
  const crits = new Set(runs.map((r) => r.critical_findings));
  const highs = new Set(runs.map((r) => r.high_findings));
  if (crits.size > 1 || highs.size > 1) {
    return {
      type: "VARIED",
      label: "FINDINGS VARIED",
      reason: "Finding counts diverge between runs",
      badgeClass: "text-amber-900 dark:text-amber-300 bg-amber-100 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800",
    };
  }

  return {
    type: "DETERMINISTIC",
    label: "DETERMINISTIC",
    reason: "Identical security score, findings, and evidence under matching pipeline & policy versions",
    badgeClass: "text-emerald-800 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800",
  };
}

  const clusters = React.useMemo(() => {
    if (!groupByHash) return null;
    const map = new Map<string, { key: string; sha256?: string; filename: string; runs: typeof filteredAnalyses }>();

    for (const run of filteredAnalyses) {
      const key = run.capture_sha256 ? run.capture_sha256 : run.analysis_id;
      if (!map.has(key)) {
        map.set(key, {
          key,
          sha256: run.capture_sha256,
          filename: run.capture_filename || "Live / Unnamed Stream",
          runs: [],
        });
      }
      map.get(key)!.runs.push(run);
    }

    return Array.from(map.values()).map((c) => {
      const sorted = [...c.runs].sort(
        (a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime()
      );
      const latest = sorted[0];
      const scores = sorted
        .map((r) => r.security_score)
        .filter((s): s is number => s !== null && s !== undefined);
      const minScore = scores.length > 0 ? Math.min(...scores) : null;
      const maxScore = scores.length > 0 ? Math.max(...scores) : null;
      const disposition = evaluateClusterDisposition(sorted);

      return {
        key: c.key,
        sha256: c.sha256,
        filename: c.filename,
        latestRun: latest,
        runs: sorted,
        isCluster: sorted.length > 1,
        disposition,
        minScore,
        maxScore,
      };
    });
  }, [filteredAnalyses, groupByHash]);

  return (
    <div className="space-y-6">
      {/* Top Banner & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <Layers className="w-5 h-5 text-[#FF3D00]" />
            <h1 className="text-xl font-bold tracking-tight text-neutral-900 dark:text-white uppercase font-mono">
              Analysis History & Workbench Sessions
            </h1>
          </div>
          <p className="text-xs text-neutral-500 mt-1">
            Authoritative IPsec protocol analysis, traffic inference, security assessments, and evidence runs.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => refetch()}
            className="p-2 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-700 dark:text-neutral-300"
            title="Refresh list"
            aria-label="Refresh list"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <Link
            href="/analyses/new"
            className="flex items-center space-x-1.5 bg-[#FF3D00] hover:bg-[#e03600] text-white text-xs font-mono font-bold px-4 py-2 border border-[#FF3D00] transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span className="uppercase">New Analysis</span>
          </Link>
        </div>
      </div>

      {/* Select Run Explanation Banner */}
      {action === "select_run" && (
        <div className="p-4 bg-blue-50 dark:bg-blue-950/40 border-l-4 border-blue-500 text-blue-900 dark:text-blue-200 text-xs font-mono space-y-1">
          <div className="flex items-center space-x-2 font-bold uppercase tracking-wider text-blue-800 dark:text-blue-300">
            <Layers className="w-4 h-4 shrink-0" />
            <span>Select an Active Analysis Run</span>
          </div>
          <p>
            You requested a run-specific investigation view (such as Findings, Evidence DAG, or Audit Report) while outside of an active analysis workspace. 
            Choose an existing analysis session below to inspect its results, or ingest a new capture.
          </p>
        </div>
      )}

      {/* Search & Filter Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-neutral-400 absolute left-3 top-2.5" />
          <input
            id="search-analyses"
            name="search-analyses"
            aria-label="Search by analysis ID, filename, or SHA-256"
            type="text"
            placeholder="Search by analysis ID, filename, or SHA-256..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-xs bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 font-mono text-neutral-900 dark:text-white placeholder-neutral-400 focus:outline-none focus:border-[#FF3D00]"
          />
        </div>

        <div className="flex items-center space-x-4">
          <label htmlFor="group-by-hash" className="flex items-center space-x-2 text-xs font-mono cursor-pointer text-neutral-600 dark:text-neutral-400 select-none">
            <input
              id="group-by-hash"
              name="group-by-hash"
              type="checkbox"
              checked={groupByHash}
              onChange={(e) => setGroupByHash(e.target.checked)}
              className="rounded border-neutral-300 text-[#FF3D00] focus:ring-[#FF3D00]"
            />
            <span>Group Replays by Hash</span>
          </label>

          <label htmlFor="include-archived" className="flex items-center space-x-2 text-xs font-mono cursor-pointer text-neutral-600 dark:text-neutral-400 select-none">
            <input
              id="include-archived"
              name="include-archived"
              type="checkbox"
              checked={includeArchived}
              onChange={(e) => setIncludeArchived(e.target.checked)}
              className="rounded border-neutral-300 text-[#FF3D00] focus:ring-[#FF3D00]"
            />
            <span>Show Archived Runs</span>
          </label>
        </div>
      </div>

      {/* Main Table View */}
      <Card
        title={`Recorded Analyses (${filteredAnalyses.length}${
          groupByHash && clusters ? ` in ${clusters.length} capture groups` : ""
        })`}
      >
        {isLoading ? (
          <div className="py-12 text-center text-xs font-mono text-neutral-500 animate-pulse">
            Querying analysis catalog from database...
          </div>
        ) : isError ? (
          <div className="py-8 text-center text-xs font-mono text-rose-600 space-y-2">
            <AlertCircle className="w-6 h-6 mx-auto text-rose-600" />
            <p>Failed to load analysis history: {(error as any)?.message || "Unknown error"}</p>
            <button
              onClick={() => refetch()}
              className="px-3 py-1 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-800 dark:text-neutral-200"
            >
              Retry
            </button>
          </div>
        ) : filteredAnalyses.length === 0 ? (
          <div className="py-12 text-center space-y-3">
            <Layers className="w-8 h-8 mx-auto text-neutral-400" />
            <div className="space-y-1">
              <p className="text-sm font-semibold text-neutral-800 dark:text-neutral-200">
                No analysis runs recorded yet
              </p>
              <p className="text-xs text-neutral-500 max-w-md mx-auto">
                Ingest a PCAP/PCAPNG capture file or initiate an authorized live capture to begin IPsec protocol analysis.
              </p>
            </div>
            <Link
              href="/analyses/new"
              className="inline-flex items-center space-x-1.5 bg-[#FF3D00] text-white text-xs font-mono font-bold px-4 py-2 border border-[#FF3D00]"
            >
              <Plus className="w-4 h-4" />
              <span className="uppercase">Ingest First Capture</span>
            </Link>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <tr>
                <TableHead>Analysis ID</TableHead>
                <TableHead>Capture Source</TableHead>
                <TableHead>Status / Stage</TableHead>
                <TableHead>Security Score</TableHead>
                <TableHead>Coverage</TableHead>
                <TableHead>Risk Tier</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </tr>
            </TableHeader>
            <TableBody>
              {groupByHash && clusters
                ? clusters.map((cluster) => {
                    const run = cluster.latestRun;
                    const isExpanded = !!expandedClusters[cluster.key];
                    return (
                      <React.Fragment key={cluster.key}>
                        <TableRow
                          className={run.is_archived ? "opacity-60 bg-neutral-50/50 dark:bg-neutral-900/20" : ""}
                        >
                          <TableCell mono>
                            <CopyableValue value={run.analysis_id} truncate label="Analysis ID" />
                          </TableCell>
                          <TableCell>
                            <div className="space-y-1">
                              <div className="flex items-center space-x-2">
                                <Link
                                  href={`/analyses/${run.analysis_id}/overview`}
                                  className="font-semibold text-neutral-900 dark:text-white hover:text-[#FF3D00] dark:hover:text-[#FF3D00] transition-colors"
                                >
                                  {cluster.filename}
                                </Link>
                                {run.is_synthetic_demo && (
                                  <span
                                    className="px-1.5 py-0.2 bg-amber-100 text-amber-900 dark:bg-amber-950/40 dark:text-amber-300 border border-amber-400 text-[9px] font-mono font-bold tracking-wider uppercase"
                                    title="Results were seeded for demonstration reference rather than computed from live packet analysis"
                                  >
                                    DEMONSTRATION / SEEDED REFERENCE
                                  </span>
                                )}
                              </div>
                              <div className="text-[10px] text-neutral-400 font-mono">
                                SHA: {cluster.sha256 ? `${cluster.sha256.slice(0, 10)}...` : "N/A"}
                              </div>
                              {cluster.isCluster && (
                                <div className="flex items-center gap-1.5 pt-0.5">
                                  <button
                                    type="button"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setExpandedClusters((prev) => ({
                                        ...prev,
                                        [cluster.key]: !prev[cluster.key],
                                      }));
                                    }}
                                    className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-mono font-bold bg-neutral-100 hover:bg-neutral-200 dark:bg-neutral-800 dark:hover:bg-neutral-700 text-neutral-800 dark:text-neutral-200 border border-neutral-300 dark:border-neutral-700 transition-colors"
                                    title="Inspect replay execution history for this capture hash"
                                  >
                                    {isExpanded ? (
                                      <ChevronDown className="w-3 h-3 text-[#FF3D00]" />
                                    ) : (
                                      <ChevronRight className="w-3 h-3 text-[#FF3D00]" />
                                    )}
                                    <span>{cluster.runs.length} REPLAY RUNS</span>
                                  </button>
                                  <span
                                    className={`px-1.5 py-0.2 text-[9px] font-mono font-bold border ${cluster.disposition.badgeClass}`}
                                    title={cluster.disposition.reason}
                                  >
                                    {cluster.disposition.label}
                                  </span>
                                </div>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-col space-y-1">
                              <StatusBadge status={run.status} />
                              <span className="text-[10px] font-mono text-neutral-500">
                                {run.current_stage || "INITIALIZING"}
                              </span>
                            </div>
                          </TableCell>
                          <TableCell mono>
                            <ScoreDisplay
                              score={run.security_score}
                              coverage={run.coverage_percentage}
                              riskTier={run.risk_tier}
                              status={run.status}
                              size="sm"
                            />
                          </TableCell>
                          <TableCell mono className="text-xs font-mono font-bold text-neutral-800 dark:text-neutral-200">
                            {formatCoverage(run.coverage_percentage)}
                          </TableCell>
                          <TableCell>
                            <span
                              className={`px-1.5 py-0.5 text-[10px] font-mono font-bold border ${
                                run.risk_tier === "LOW"
                                  ? "bg-emerald-50 text-emerald-800 border-emerald-300 dark:bg-emerald-950/30 dark:text-emerald-300"
                                  : run.risk_tier === "MEDIUM"
                                  ? "bg-amber-50 text-amber-800 border-amber-300 dark:bg-amber-950/30 dark:text-amber-300"
                                  : run.risk_tier === "INSUFFICIENT_EVIDENCE"
                                  ? "bg-amber-100 text-amber-900 border-amber-400 dark:bg-amber-950/50 dark:text-amber-300"
                                  : "bg-rose-50 text-rose-800 border-rose-300 dark:bg-rose-950/30 dark:text-rose-300"
                              }`}
                            >
                              {run.risk_tier || "UNKNOWN"}
                            </span>
                          </TableCell>
                          <TableCell mono>
                            <div className="flex items-center space-x-1">
                              <span className="text-xs text-neutral-500 font-mono">v{run.pipeline_version || "1.0.0"}</span>
                              {run.is_outdated_version && (
                                <span
                                  className="px-1 py-0.2 bg-amber-100 dark:bg-amber-950/50 text-amber-800 dark:text-amber-300 border border-amber-300 text-[9px] font-mono font-bold"
                                  title="Older pipeline version. Open and recompute for v2.0.0."
                                >
                                  OUTDATED
                                </span>
                              )}
                            </div>
                          </TableCell>
                          <TableCell mono className="text-neutral-500 text-[11px]">
                            {run.created_at ? new Date(run.created_at).toLocaleDateString() : "N/A"}
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex items-center justify-end space-x-1.5">
                              <Link
                                href={`/analyses/${run.analysis_id}/overview`}
                                className="inline-flex items-center space-x-1 px-2 py-1 text-xs font-mono font-bold bg-neutral-100 hover:bg-neutral-200 dark:bg-neutral-800 dark:hover:bg-neutral-700 text-neutral-900 dark:text-white border border-neutral-300 dark:border-neutral-700 transition-colors"
                                title="Open analysis workspace"
                              >
                                <span>OPEN</span>
                                <ChevronRight className="w-3 h-3" />
                              </Link>
                              <button
                                onClick={(e) => handleArchive(run.analysis_id, e)}
                                disabled={actionInProgress === run.analysis_id}
                                className="p-1 text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200 border border-transparent hover:border-neutral-300 dark:hover:border-neutral-700 transition-colors"
                                title={run.is_archived ? "Unarchive run" : "Archive run from catalog"}
                                aria-label={run.is_archived ? "Unarchive" : "Archive"}
                              >
                                {run.is_archived ? <RotateCcw className="w-3.5 h-3.5" /> : <Archive className="w-3.5 h-3.5" />}
                              </button>
                              <button
                                onClick={(e) => handleDelete(run.analysis_id, e)}
                                disabled={actionInProgress === run.analysis_id}
                                className="p-1 text-neutral-400 hover:text-rose-600 dark:hover:text-rose-400 border border-transparent hover:border-rose-300 dark:hover:border-rose-800 transition-colors"
                                title="Delete run"
                                aria-label="Delete"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </TableCell>
                        </TableRow>

                        {/* Expandable sub-rows for prior replays of this hash */}
                        {cluster.isCluster &&
                          isExpanded &&
                          cluster.runs.slice(1).map((subRun, subIdx) => (
                            <TableRow
                              key={`${subRun.analysis_id}-${subIdx}`}
                              className={`bg-neutral-50/70 dark:bg-neutral-900/40 border-l-2 border-[#FF3D00] ${
                                subRun.is_archived ? "opacity-60" : ""
                              }`}
                            >
                              <TableCell mono className="pl-6">
                                <div className="flex items-center space-x-1.5">
                                  <span className="text-[10px] font-mono text-neutral-400">
                                    ↳ Run #{cluster.runs.length - subIdx - 1}:
                                  </span>
                                  <CopyableValue value={subRun.analysis_id} truncate label="Analysis ID" />
                                </div>
                              </TableCell>
                              <TableCell>
                                <div className="text-[11px] text-neutral-500 font-mono">
                                  Prior replay execution
                                </div>
                              </TableCell>
                              <TableCell>
                                <div className="flex flex-col space-y-0.5">
                                  <StatusBadge status={subRun.status} />
                                  <span className="text-[9px] font-mono text-neutral-400">
                                    {subRun.current_stage || "COMPLETED"}
                                  </span>
                                </div>
                              </TableCell>
                              <TableCell mono>
                                <ScoreDisplay
                                  score={subRun.security_score}
                                  coverage={subRun.coverage_percentage}
                                  riskTier={subRun.risk_tier}
                                  status={subRun.status}
                                  size="sm"
                                />
                              </TableCell>
                              <TableCell mono className="text-xs font-mono text-neutral-700 dark:text-neutral-300">
                                {formatCoverage(subRun.coverage_percentage)}
                              </TableCell>
                              <TableCell>
                                <span className="px-1.5 py-0.5 text-[9px] font-mono font-bold border bg-neutral-100 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300">
                                  {subRun.risk_tier || "UNKNOWN"}
                                </span>
                              </TableCell>
                              <TableCell mono className="text-[11px] text-neutral-500">
                                v{subRun.pipeline_version || "1.0.0"}
                              </TableCell>
                              <TableCell mono className="text-neutral-400 text-[10px]">
                                {subRun.created_at ? new Date(subRun.created_at).toLocaleString() : "N/A"}
                              </TableCell>
                              <TableCell className="text-right">
                                <div className="flex items-center justify-end space-x-1.5">
                                  <Link
                                    href={`/analyses/${subRun.analysis_id}/overview`}
                                    className="inline-flex items-center space-x-1 px-1.5 py-0.5 text-[11px] font-mono font-bold bg-neutral-100 hover:bg-neutral-200 dark:bg-neutral-800 dark:hover:bg-neutral-700 text-neutral-900 dark:text-white border border-neutral-300 dark:border-neutral-700"
                                  >
                                    <span>OPEN</span>
                                    <ChevronRight className="w-2.5 h-2.5" />
                                  </Link>
                                  <button
                                    onClick={(e) => handleArchive(subRun.analysis_id, e)}
                                    disabled={actionInProgress === subRun.analysis_id}
                                    className="p-1 text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200"
                                    title={subRun.is_archived ? "Unarchive run" : "Archive run"}
                                  >
                                    {subRun.is_archived ? (
                                      <RotateCcw className="w-3 h-3" />
                                    ) : (
                                      <Archive className="w-3 h-3" />
                                    )}
                                  </button>
                                  <button
                                    onClick={(e) => handleDelete(subRun.analysis_id, e)}
                                    disabled={actionInProgress === subRun.analysis_id}
                                    className="p-1 text-neutral-400 hover:text-rose-600 dark:hover:text-rose-400"
                                    title="Delete run"
                                  >
                                    <Trash2 className="w-3 h-3" />
                                  </button>
                                </div>
                              </TableCell>
                            </TableRow>
                          ))}
                      </React.Fragment>
                    );
                  })
                : filteredAnalyses.map((run, idx) => (
                    <TableRow key={`${run.analysis_id}-${idx}`} className={run.is_archived ? "opacity-60 bg-neutral-50/50 dark:bg-neutral-900/20" : ""}>
                      <TableCell mono>
                        <CopyableValue value={run.analysis_id} truncate label="Analysis ID" />
                      </TableCell>
                      <TableCell>
                        <div className="space-y-0.5">
                          <div className="flex items-center space-x-2">
                            <Link
                              href={`/analyses/${run.analysis_id}/overview`}
                              className="font-semibold text-neutral-900 dark:text-white hover:text-[#FF3D00] dark:hover:text-[#FF3D00] transition-colors"
                            >
                              {run.capture_filename || "Live / Unnamed Stream"}
                            </Link>
                            {run.is_synthetic_demo && (
                              <span className="px-1.5 py-0.2 bg-amber-100 text-amber-900 dark:bg-amber-950/40 dark:text-amber-300 border border-amber-400 text-[9px] font-mono font-bold tracking-wider uppercase">
                                DEMO
                              </span>
                            )}
                          </div>
                          <div className="text-[10px] text-neutral-400 font-mono">
                            SHA: {run.capture_sha256 ? `${run.capture_sha256.slice(0, 10)}...` : "N/A"}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col space-y-1">
                          <StatusBadge status={run.status} />
                          <span className="text-[10px] font-mono text-neutral-500">
                            {run.current_stage || "INITIALIZING"}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell mono>
                        <ScoreDisplay
                          score={run.security_score}
                          coverage={run.coverage_percentage}
                          riskTier={run.risk_tier}
                          status={run.status}
                          size="sm"
                        />
                      </TableCell>
                      <TableCell mono className="text-xs font-mono font-bold text-neutral-800 dark:text-neutral-200">
                        {formatCoverage(run.coverage_percentage)}
                      </TableCell>
                      <TableCell>
                        <span
                          className={`px-1.5 py-0.5 text-[10px] font-mono font-bold border ${
                            run.risk_tier === "LOW"
                              ? "bg-emerald-50 text-emerald-800 border-emerald-300 dark:bg-emerald-950/30 dark:text-emerald-300"
                              : run.risk_tier === "MEDIUM"
                              ? "bg-amber-50 text-amber-800 border-amber-300 dark:bg-amber-950/30 dark:text-amber-300"
                              : run.risk_tier === "INSUFFICIENT_EVIDENCE"
                              ? "bg-amber-100 text-amber-900 border-amber-400 dark:bg-amber-950/50 dark:text-amber-300"
                              : "bg-rose-50 text-rose-800 border-rose-300 dark:bg-rose-950/30 dark:text-rose-300"
                          }`}
                        >
                          {run.risk_tier || "UNKNOWN"}
                        </span>
                      </TableCell>
                      <TableCell mono>
                        <div className="flex items-center space-x-1">
                          <span className="text-xs text-neutral-500 font-mono">v{run.pipeline_version || "1.0.0"}</span>
                          {run.is_outdated_version && (
                            <span
                              className="px-1 py-0.2 bg-amber-100 dark:bg-amber-950/50 text-amber-800 dark:text-amber-300 border border-amber-300 text-[9px] font-mono font-bold"
                              title="Older pipeline version. Open and recompute for v2.0.0."
                            >
                              OUTDATED
                            </span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell mono className="text-neutral-500 text-[11px]">
                        {run.created_at ? new Date(run.created_at).toLocaleDateString() : "N/A"}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end space-x-1.5">
                          <Link
                            href={`/analyses/${run.analysis_id}/overview`}
                            className="inline-flex items-center space-x-1 px-2 py-1 text-xs font-mono font-bold bg-neutral-100 hover:bg-neutral-200 dark:bg-neutral-800 dark:hover:bg-neutral-700 text-neutral-900 dark:text-white border border-neutral-300 dark:border-neutral-700 transition-colors"
                            title="Open analysis workspace"
                          >
                            <span>OPEN</span>
                            <ChevronRight className="w-3 h-3" />
                          </Link>
                          <button
                            onClick={(e) => handleArchive(run.analysis_id, e)}
                            disabled={actionInProgress === run.analysis_id}
                            className="p-1 text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200 border border-transparent hover:border-neutral-300 dark:hover:border-neutral-700 transition-colors"
                            title={run.is_archived ? "Unarchive run" : "Archive run from catalog"}
                            aria-label={run.is_archived ? "Unarchive" : "Archive"}
                          >
                            {run.is_archived ? <RotateCcw className="w-3.5 h-3.5" /> : <Archive className="w-3.5 h-3.5" />}
                          </button>
                          <button
                            onClick={(e) => handleDelete(run.analysis_id, e)}
                            disabled={actionInProgress === run.analysis_id}
                            className="p-1 text-neutral-400 hover:text-rose-600 dark:hover:text-rose-400 border border-transparent hover:border-rose-300 dark:hover:border-rose-800 transition-colors"
                            title="Delete run"
                            aria-label="Delete"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
            </TableBody>
          </Table>
        )}
      </Card>
    </div>
  );
}

export default function AnalysesListPage() {
  return (
    <Suspense fallback={<div className="py-12 text-center text-xs font-mono text-neutral-500 animate-pulse">Loading analysis history...</div>}>
      <AnalysesListContent />
    </Suspense>
  );
}
