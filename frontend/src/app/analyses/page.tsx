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
import { Plus, Search, Layers, ChevronRight, AlertCircle, RefreshCw } from "lucide-react";

function AnalysesListContent() {
  const [search, setSearch] = useState("");
  const searchParams = useSearchParams();
  const action = searchParams.get("action");

  const {
    data: analyses,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ["analyses-list"],
    queryFn: () => api.analyses.list(),
  });

  const filteredAnalyses = (analyses || []).filter((item) => {
    const q = search.toLowerCase();
    return (
      item.analysis_id.toLowerCase().includes(q) ||
      (item.capture_filename && item.capture_filename.toLowerCase().includes(q)) ||
      (item.capture_sha256 && item.capture_sha256.toLowerCase().includes(q))
    );
  });

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
      <div className="flex items-center space-x-2 max-w-md">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-neutral-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search by analysis ID, filename, or SHA-256..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-xs bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 font-mono text-neutral-900 dark:text-white placeholder-neutral-400 focus:outline-none focus:border-[#FF3D00]"
          />
        </div>
      </div>

      {/* Main Table View */}
      <Card title={`Recorded Analyses (${filteredAnalyses.length})`}>
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
                <TableHead>Findings (Crit / High)</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </tr>
            </TableHeader>
            <TableBody>
              {filteredAnalyses.map((run) => (
                <TableRow key={run.analysis_id}>
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
                            DEMO FIXTURE
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
                    {run.security_score !== null && run.security_score !== undefined ? (
                      <span className="font-bold text-neutral-900 dark:text-white">
                        {run.security_score}
                        <span className="text-neutral-400 font-normal">/100</span>
                      </span>
                    ) : (
                      <span className="text-neutral-400 text-xs">UNKNOWN</span>
                    )}
                  </TableCell>
                  <TableCell mono>
                    <span className="font-bold text-red-600 dark:text-red-400">
                      {run.critical_findings || 0}
                    </span>
                    <span className="text-neutral-400"> / </span>
                    <span className="font-bold text-rose-600 dark:text-rose-400">
                      {run.high_findings || 0}
                    </span>
                  </TableCell>
                  <TableCell mono className="text-neutral-500 text-[11px]">
                    {run.created_at ? new Date(run.created_at).toLocaleString() : "N/A"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Link
                      href={`/analyses/${run.analysis_id}/overview`}
                      className="inline-flex items-center space-x-1 px-2.5 py-1 text-xs font-mono font-bold bg-neutral-100 hover:bg-neutral-200 dark:bg-neutral-800 dark:hover:bg-neutral-700 text-neutral-900 dark:text-white border border-neutral-300 dark:border-neutral-700 transition-colors"
                    >
                      <span>OPEN</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </Link>
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
