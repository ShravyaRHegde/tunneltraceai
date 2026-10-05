"use client";

import React, { use, useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  Position,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import { CopyableValue } from "@/components/ui/table";
import { SocWorkflowBanner } from "@/components/soc/soc-workflow-banner";
import {
  FileSearch,
  AlertCircle,
  Network,
  ListTree,
  AlertTriangle,
  HelpCircle,
  ArrowRight,
  Shield,
  Layers,
  History,
  CheckCircle2,
  XCircle,
  RefreshCw,
  ExternalLink,
  FileText,
  Table2,
} from "lucide-react";

function EvidenceExplorerContent({
  analysisId,
}: {
  analysisId: string;
}) {
  const searchParams = useSearchParams();
  const highlightedFindingId = searchParams.get("findingId");
  const viewParam = searchParams.get("view");

  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [viewMode, setViewMode] = useState<"graph" | "table" | "lineage" | "replay">(
    viewParam === "replay" || viewParam === "lineage" || viewParam === "table" ? viewParam : "graph"
  );
  const [isReanalyzing, setIsReanalyzing] = useState(false);
  const [reanalysisResult, setReanalysisResult] = useState<any | null>(null);
  const [reanalysisError, setReanalysisError] = useState<string | null>(null);

  useEffect(() => {
    if (viewParam === "replay" || viewParam === "lineage" || viewParam === "graph" || viewParam === "table") {
      setViewMode(viewParam);
    }
  }, [viewParam]);

  const {
    data: evidence,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["evidence-graph", analysisId],
    queryFn: () => api.analyses.getEvidenceGraph(analysisId),
  });

  const {
    data: replayLineage,
    isLoading: isLoadingReplay,
    refetch: refetchReplay,
  } = useQuery({
    queryKey: ["replay-lineage", analysisId],
    queryFn: () => api.analyses.getReplayLineage(analysisId),
  });

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  useEffect(() => {
    if (evidence) {
      const rawNodes = evidence.nodes?.length ? evidence.nodes : (evidence as any).react_flow?.nodes || [];
      const rawEdges = evidence.edges?.length ? evidence.edges : (evidence as any).react_flow?.edges || [];

      if (rawNodes.length > 0) {
        const typeColors: Record<string, string> = {
          finding: "#E11D48",
          security_finding: "#E11D48",
          rule: "#D97706",
          policy_rule: "#D97706",
          fact: "#2563EB",
          security_fact: "#2563EB",
          observation: "#059669",
          protocol_observation: "#059669",
          compliance_evaluation: "#0D9488",
          evidence_gap: "#D97706",
          packet: "#7C3AED",
          frame: "#7C3AED",
          capture: "#4B5563",
          threat: "#DC2626",
          risk_result: "#E11D48",
          fingerprintability_component: "#6366F1",
          esp_flow: "#0284C7",
          scenario: "#059669",
          replay_run: "#4B5563",
        };

        const getEvidenceTier = (nodeType: string): number => {
          const t = (nodeType || "").toLowerCase();
          if (t.includes("capture") || t.includes("scenario")) return 0;
          if (t.includes("packet") || t.includes("frame")) return 1;
          if (t.includes("observation") || t.includes("esp_flow")) return 2;
          if (t.includes("fact")) return 3;
          if (t.includes("rule")) return 4;
          if (t.includes("eval") || t.includes("gap")) return 5;
          if (t.includes("finding")) return 6;
          if (t.includes("threat") || t.includes("risk")) return 7;
          if (t.includes("score") || t.includes("fingerprint") || t.includes("remediation")) return 8;
          return 3;
        };

        const presentTiers: number[] = Array.from(
          new Set<number>(
            rawNodes.map((n: any) =>
              getEvidenceTier(n.node_type || n.type || n.data?.nodeType || "")
            )
          )
        ).sort((a: number, b: number) => a - b);
        const tierToColIndex = new Map(presentTiers.map((tier, idx) => [tier, idx]));

        const NODE_WIDTH = 230;
        const HORIZ_GAP = 240;
        const VERT_STEP = 160;

        const tierCounts: Record<number, number> = {};
        presentTiers.forEach((t: number) => {
          tierCounts[t] = 0;
        });

        const formattedNodes: Node[] = rawNodes.map((n: any) => {
          const nodeType = String(n.node_type || n.type || n.data?.nodeType || "NODE").toLowerCase();
          const rawLabel = n.label || n.data?.label || n.id;
          const entityId = n.entity_id || n.data?.finding_id || n.data?.rule_id || n.data?.fact_id || n.data?.subject_id || n.id;
          const tier = getEvidenceTier(nodeType);
          const yIndex = tierCounts[tier] || 0;
          tierCounts[tier] = yIndex + 1;

          const colIndex = tierToColIndex.get(tier) ?? 0;
          const xPos = 40 + colIndex * (NODE_WIDTH + HORIZ_GAP);
          const yPos = 40 + yIndex * VERT_STEP;

          const isHighlight =
            highlightedFindingId && (entityId === highlightedFindingId || n.id === highlightedFindingId);

          const borderColor = typeColors[nodeType] || typeColors[nodeType.replace(/_/g, "")] || "#64748B";

          return {
            id: n.id,
            type: "default",
            sourcePosition: Position.Right,
            targetPosition: Position.Left,
            data: {
              label: `${(n.node_type || n.type || n.data?.nodeType || "NODE").toUpperCase()}\n${rawLabel}`,
              nodeType: n.node_type || n.type || n.data?.nodeType || "NODE",
              labelRaw: rawLabel,
              entityId,
              properties: n.properties || n.data || {},
            },
            position: { x: xPos, y: yPos },
            style: {
              background: isHighlight ? "#FF3D00" : "#FFFFFF",
              color: isHighlight ? "#FFFFFF" : "#0F172A",
              border: isHighlight ? "2px solid #FF3D00" : `1.5px solid ${borderColor}`,
              borderRadius: "4px",
              boxShadow: "0 2px 6px rgba(0,0,0,0.08)",
              fontFamily: "monospace",
              fontSize: "11px",
              padding: "10px 12px",
              width: NODE_WIDTH,
            },
          };
        });

        const validNodeIds = new Set(formattedNodes.map((n) => n.id));

        const formattedEdges: Edge[] = rawEdges
          .map((e: any, idx: number) => {
            const src = e.source || e.source_id || e.source_node_id || "";
            const tgt = e.target || e.target_id || e.target_node_id || "";
            const lbl = e.label || e.relation_type || e.relation || "";
            return {
              id: e.id || `e-${idx}-${src}-${tgt}`,
              source: src,
              target: tgt,
              label: lbl,
              type: "smoothstep",
              style: { stroke: "#64748B", strokeWidth: 1.5 },
              labelStyle: {
                fill: "#1E293B",
                fontSize: 9,
                fontFamily: "ui-monospace, monospace",
                fontWeight: 600,
                letterSpacing: "0.03em",
              },
              labelBgStyle: {
                fill: "#F8FAFC",
                fillOpacity: 0.95,
                stroke: "#CBD5E1",
                strokeWidth: 1,
                rx: 3,
                ry: 3,
              },
              labelBgPadding: [6, 2] as [number, number],
            };
          })
          .filter((e: any) => e.source && e.target && validNodeIds.has(e.source) && validNodeIds.has(e.target));

        setNodes(formattedNodes);
        setEdges(formattedEdges);
      }
    }
  }, [evidence, highlightedFindingId, setNodes, setEdges]);

  const onNodeClick = (_: any, node: Node) => {
    const rawNode =
      (evidence?.nodes || []).find((n) => n.id === node.id) ||
      (evidence as any)?.react_flow?.nodes?.find((n: any) => n.id === node.id) ||
      node;

    const nodeType = (rawNode as any).node_type || (rawNode as any).type || (rawNode as any).data?.nodeType || "NODE";
    const label = (rawNode as any).label || (rawNode as any).data?.labelRaw || (rawNode as any).data?.label || rawNode.id;
    const entityId = (rawNode as any).entity_id || (rawNode as any).data?.entityId || (rawNode as any).data?.subject_id || (rawNode as any).data?.rule_id || rawNode.id;
    const properties = (rawNode as any).properties || (rawNode as any).data?.properties || (rawNode as any).data || {};

    setSelectedNode({
      id: rawNode.id,
      node_type: nodeType,
      label,
      entity_id: entityId,
      properties,
    });
  };

  const computedGaps = React.useMemo(() => {
    if (evidence?.evidence_gaps && evidence.evidence_gaps.length > 0) {
      return evidence.evidence_gaps;
    }
    const rawNodes = evidence?.nodes?.length ? evidence.nodes : (evidence as any)?.react_flow?.nodes || [];
    return (rawNodes || [])
      .filter((n: any) => {
        const t = String(n.type || n.node_type || n.data?.nodeType || "").toLowerCase();
        return t.includes("gap");
      })
      .map((n: any) => ({
        fact_name: n.data?.rule_id || (Array.isArray(n.data?.missing_fields) ? n.data.missing_fields.join(", ") : null) || n.label || "Missing Protocol Evidence",
        rationale: n.data?.reason || n.data?.recommended_action || "Required protocol evidence missing or unobserved in passive capture.",
      }));
  }, [evidence]);

  if (isLoading) {
    return (
      <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
        Assembling cryptographic evidence DAG and tracing forensic packet provenance...
      </div>
    );
  }

  if (isError || !evidence) {
    return (
      <div className="p-6 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 text-center space-y-2 font-mono text-xs text-rose-600">
        <AlertCircle className="w-6 h-6 mx-auto" />
        <p>Failed to load evidence graph: {(error as any)?.message || "Unknown error"}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* SOC Analyst Lifecycle Banner */}
      <SocWorkflowBanner
        activeStep={viewMode === "replay" ? 6 : 5}
        analysisId={analysisId}
      />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <FileSearch className="w-5 h-5 text-[#FF3D00]" />
            <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
              Forensic Evidence Explorer & Lineage DAG
            </h1>
          </div>
          <p className="text-xs text-neutral-500 mt-1">
            <strong className="text-neutral-700 dark:text-neutral-300">What this shows:</strong> The immutable evidence chain linking findings to policy rules, protocol facts, packet frame numbers, and capture SHA-256 digests. Also shows evidence gaps where data was absent.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Quick SOC Journey Navigation */}
          <div className="flex items-center space-x-1.5">
            <Link
              href={`/analyses/${analysisId}/security`}
              className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-mono border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-700 dark:text-neutral-300"
            >
              <Shield className="w-3.5 h-3.5" />
              <span>Findings Triage</span>
            </Link>
            <Link
              href={`/analyses/${analysisId}/reports`}
              className="flex items-center space-x-1 px-2.5 py-1.5 text-xs font-mono bg-neutral-900 text-white dark:bg-white dark:text-neutral-900 hover:opacity-90"
            >
              <FileText className="w-3.5 h-3.5 text-[#FF3D00]" />
              <span>Generate Report</span>
            </Link>
          </div>

          {/* View Switcher */}
          <div className="flex items-center space-x-1 border border-neutral-300 dark:border-neutral-800 p-0.5 bg-white dark:bg-[#141416]">
          <button
            onClick={() => setViewMode("graph")}
            className={`flex items-center space-x-1.5 px-3 py-1.5 text-xs font-mono font-bold uppercase transition-colors ${
              viewMode === "graph"
                ? "bg-[#FF3D00] text-white"
                : "text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            <span>Interactive DAG</span>
          </button>
          <button
            onClick={() => setViewMode("table")}
            className={`flex items-center space-x-1.5 px-3 py-1.5 text-xs font-mono font-bold uppercase transition-colors ${
              viewMode === "table"
                ? "bg-[#FF3D00] text-white"
                : "text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
            }`}
          >
            <Table2 className="w-3.5 h-3.5" />
            <span>Table View</span>
          </button>
          <button
            onClick={() => setViewMode("lineage")}
            className={`flex items-center space-x-1.5 px-3 py-1.5 text-xs font-mono font-bold uppercase transition-colors ${
              viewMode === "lineage"
                ? "bg-[#FF3D00] text-white"
                : "text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
            }`}
          >
            <ListTree className="w-3.5 h-3.5" />
            <span>Textual Traversal</span>
          </button>
          <button
            onClick={() => setViewMode("replay")}
            className={`flex items-center space-x-1.5 px-3 py-1.5 text-xs font-mono font-bold uppercase transition-colors ${
              viewMode === "replay"
                ? "bg-[#FF3D00] text-white"
                : "text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
            }`}
          >
            <History className="w-3.5 h-3.5" />
            <span>Replay Lineage</span>
          </button>
        </div>
        </div>
      </div>

      {viewMode === "replay" ? (
        <div className="space-y-6">
          {/* Top Status & Integrity Banner */}
          <div className="p-4 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono text-neutral-400">ANALYSIS LINEAGE:</span>
                  <span className="font-mono text-sm font-bold text-neutral-900 dark:text-white">{analysisId}</span>
                  <span className="px-2 py-0.5 font-mono text-[10px] bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700">
                    {replayLineage?.replay_mode || "ORIGINAL_INGESTION"}
                  </span>
                </div>
                <div className="text-xs text-neutral-500 font-mono mt-1 flex flex-wrap items-center gap-3">
                  <span>Capture: {replayLineage?.capture_filename || "unknown"}</span>
                  <span>•</span>
                  <span>SHA-256: {replayLineage?.capture_sha256 ? `${replayLineage.capture_sha256.slice(0, 16)}...` : "unknown"}</span>
                </div>
              </div>

              {/* Artifact Integrity Gate */}
              <div className="flex items-center space-x-2">
                {replayLineage?.capture_integrity_verified ? (
                  <div className="flex items-center space-x-1.5 px-3 py-1.5 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400 text-xs font-mono">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>INTEGRITY VERIFIED (SHA-256 MATCH)</span>
                  </div>
                ) : (
                  <div className="flex items-center space-x-1.5 px-3 py-1.5 bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800 text-rose-700 dark:text-rose-400 text-xs font-mono">
                    <XCircle className="w-4 h-4" />
                    <span>INTEGRITY MISMATCH / FAIL-CLOSED</span>
                  </div>
                )}
              </div>
            </div>

            {/* Re-Analyze Action Button */}
            <div className="pt-2 border-t border-neutral-200 dark:border-neutral-800 flex items-center justify-between">
              <p className="text-xs text-neutral-500">
                Trigger an immutable forensic re-analysis of the same verified capture artifact to test deterministic reproducibility.
              </p>
              <button
                onClick={async () => {
                  setIsReanalyzing(true);
                  setReanalysisError(null);
                  try {
                    const res = await api.analyses.reAnalyze(analysisId);
                    setReanalysisResult(res);
                    refetchReplay();
                  } catch (err: any) {
                    setReanalysisError(err?.message || "Re-analysis failed");
                  } finally {
                    setIsReanalyzing(false);
                  }
                }}
                disabled={isReanalyzing || !replayLineage?.capture_integrity_verified}
                className="flex items-center space-x-2 px-4 py-2 bg-[#FF3D00] hover:bg-[#E63700] disabled:bg-neutral-400 text-white text-xs font-mono font-bold uppercase transition-colors"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isReanalyzing ? "animate-spin" : ""}`} />
                <span>{isReanalyzing ? "Re-Analyzing..." : "Trigger Forensic Re-Analysis"}</span>
              </button>
            </div>

            {reanalysisResult && (
              <div className="p-3 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-800 text-xs font-mono text-emerald-700 dark:text-emerald-400 flex items-center justify-between">
                <div>
                  <span className="font-bold">Re-Analysis Created: {reanalysisResult.child_analysis_id}</span>
                  <span className="ml-2">({reanalysisResult.comparison_status})</span>
                </div>
                <a
                  href={`/analyses/${reanalysisResult.child_analysis_id}/evidence`}
                  className="flex items-center space-x-1 underline hover:text-emerald-300"
                >
                  <span>Open Child Run</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            )}

            {reanalysisError && (
              <div className="p-3 bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800 text-xs font-mono text-rose-700 dark:text-rose-400">
                <span className="font-bold">Re-Analysis Error:</span> {reanalysisError}
              </div>
            )}
          </div>

          {/* Grid of Lineage & Comparison Details */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Left: Provenance Lineage */}
            <Card title="Lineage & Parent/Child Relationships">
              <div className="space-y-4 text-xs font-mono">
                <div>
                  <span className="text-neutral-400 uppercase text-[10px] block">Parent Analysis ID</span>
                  {replayLineage?.parent_analysis_id ? (
                    <div className="flex items-center space-x-2 mt-1">
                      <span className="text-neutral-900 dark:text-white font-bold">{replayLineage.parent_analysis_id}</span>
                      <a
                        href={`/analyses/${replayLineage.parent_analysis_id}/evidence`}
                        className="text-[#FF3D00] hover:underline flex items-center space-x-0.5"
                      >
                        <span>View</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  ) : (
                    <span className="text-neutral-500 italic mt-1 block">None (Root capture ingestion)</span>
                  )}
                </div>

                <div>
                  <span className="text-neutral-400 uppercase text-[10px] block">Child Replay Runs ({replayLineage?.child_runs?.length || 0})</span>
                  {replayLineage?.child_runs && replayLineage.child_runs.length > 0 ? (
                    <div className="divide-y divide-neutral-200 dark:divide-neutral-800 border border-neutral-200 dark:border-neutral-800 mt-1">
                      {replayLineage.child_runs.map((c) => (
                        <div key={c.analysis_id} className="p-2 flex items-center justify-between">
                          <div>
                            <span className="font-bold text-neutral-900 dark:text-white">{c.analysis_id.slice(0, 8)}...</span>
                            <span className="ml-2 text-[10px] text-neutral-500">[{c.replay_mode || "REPLAY"}]</span>
                          </div>
                          <a
                            href={`/analyses/${c.analysis_id}/evidence`}
                            className="text-[#FF3D00] hover:underline flex items-center space-x-0.5"
                          >
                            <span>Inspect</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-neutral-500 italic mt-1 block">No child replays generated yet.</span>
                  )}
                </div>

                <div>
                  <span className="text-neutral-400 uppercase text-[10px] block">Version Pins & Toolchain</span>
                  <div className="p-2 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-1 mt-1">
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Parser:</span>
                      <span className="font-bold">{replayLineage?.version_pins?.parser_engine} ({replayLineage?.version_pins?.parser_version})</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Schema:</span>
                      <span className="font-bold">{replayLineage?.version_pins?.schema_version}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">Policy:</span>
                      <span className="font-bold">{replayLineage?.version_pins?.pinned_policy_bundle_version || "NIST SP 800-77 (Default)"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500">ML Classifier:</span>
                      <span className="font-bold">{replayLineage?.version_pins?.pinned_model_bundle_id || "NOT_CONFIGURED"}</span>
                    </div>
                  </div>
                </div>
              </div>
            </Card>

            {/* Right: Latest Deterministic Comparison */}
            <Card title="Deterministic Comparison Verification">
              {replayLineage?.latest_comparison ? (
                <div className="space-y-4 text-xs font-mono">
                  <div className="flex items-center justify-between pb-2 border-b border-neutral-200 dark:border-neutral-800">
                    <span className="text-neutral-400 uppercase text-[10px]">Outcome</span>
                    <span
                      className={`px-2 py-0.5 font-bold uppercase text-[11px] ${
                        replayLineage.latest_comparison.comparison_status === "EXACT_MATCH" || replayLineage.latest_comparison.comparison_status === "SEMANTIC_MATCH"
                          ? "bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800"
                          : "bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-400 border border-rose-300 dark:border-rose-800"
                      }`}
                    >
                      {replayLineage.latest_comparison.comparison_status}
                    </span>
                  </div>

                  <p className="text-neutral-600 dark:text-neutral-300 leading-relaxed">
                    {replayLineage.latest_comparison.summary}
                  </p>

                  {replayLineage.latest_comparison.metrics && (
                    <div>
                      <span className="text-neutral-400 uppercase text-[10px] block mb-1">Metrics Verification</span>
                      <div className="grid grid-cols-2 gap-2">
                        {Object.entries(replayLineage.latest_comparison.metrics).map(([k, v]) => (
                          <div key={k} className="p-2 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800">
                            <span className="text-[10px] text-neutral-400 uppercase block">{k.replace(/_/g, " ")}</span>
                            <span className="font-bold text-neutral-900 dark:text-white text-sm">{String(v)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {replayLineage.latest_comparison.differences && (
                    <div className="p-3 bg-rose-50 dark:bg-rose-950/30 border border-rose-300 dark:border-rose-800 space-y-1">
                      <span className="font-bold text-rose-700 dark:text-rose-400 uppercase text-[10px] block">Discrepancies Detected</span>
                      <pre className="text-[10px] overflow-x-auto text-neutral-800 dark:text-neutral-200">
                        {JSON.stringify(replayLineage.latest_comparison.differences, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              ) : (
                <div className="py-12 text-center text-xs font-mono text-neutral-500 space-y-2">
                  <History className="w-8 h-8 text-neutral-400 mx-auto" />
                  <p>No comparison recorded yet.</p>
                  <p className="text-[10px] text-neutral-400">Trigger a forensic re-analysis above to compute itemized deterministic diffs.</p>
                </div>
              )}
            </Card>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Main Workspace (12 cols) */}
        <div className={selectedNode ? "lg:col-span-8" : "lg:col-span-12"}>
          {viewMode === "table" ? (
            <Card title={`Evidence Node Table Fallback (${(evidence?.nodes || []).length})`}>
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="border-b border-neutral-300 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900 text-neutral-500">
                      <th className="p-2.5">Tier / Type</th>
                      <th className="p-2.5">Label</th>
                      <th className="p-2.5">Entity ID</th>
                      <th className="p-2.5">Properties</th>
                      <th className="p-2.5 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800">
                    {(evidence?.nodes || []).length === 0 ? (
                      <tr>
                        <td colSpan={5} className="p-6 text-center text-neutral-400 font-mono">
                          No evidence nodes reconstructed for this run.
                        </td>
                      </tr>
                    ) : (
                      (evidence?.nodes || []).map((n, idx) => {
                        const nodeType = n.node_type || (n as any).type || (n as any).data?.nodeType || "NODE";
                        const label = n.label || (n as any).data?.labelRaw || (n as any).data?.label || n.id;
                        const entityId = n.entity_id || (n as any).data?.entityId || (n as any).data?.subject_id || (n as any).data?.rule_id || n.id;
                        const props = n.properties || (n as any).data?.properties || (n as any).data || {};

                        return (
                          <tr
                            key={`${n.id}-${idx}`}
                            onClick={() => setSelectedNode({ id: n.id, node_type: nodeType, label, entity_id: entityId, properties: props })}
                            className={`cursor-pointer hover:bg-neutral-100 dark:hover:bg-neutral-900 transition-colors ${
                              selectedNode?.id === n.id ? "bg-neutral-100 dark:bg-neutral-800/80 font-bold border-l-2 border-l-[#FF3D00]" : ""
                            }`}
                          >
                            <td className="p-2.5">
                              <span className="px-1.5 py-0.5 text-[10px] font-bold bg-neutral-200 dark:bg-neutral-800 uppercase rounded-xs">
                                {nodeType}
                              </span>
                            </td>
                            <td className="p-2.5 font-bold text-neutral-900 dark:text-white">{label}</td>
                            <td className="p-2.5 text-neutral-500">{entityId}</td>
                            <td className="p-2.5 text-[11px] text-neutral-400 truncate max-w-xs">
                              {props && Object.keys(props).length > 0 ? Object.keys(props).join(", ") : "None"}
                            </td>
                            <td className="p-2.5 text-right">
                              <span className="text-[10px] text-[#FF3D00] font-bold">INSPECT →</span>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </Card>
          ) : viewMode === "graph" ? (
            <Card title="Evidence Lineage DAG (React Flow)">
              <div className="h-[600px] w-full border border-neutral-200 dark:border-neutral-800 bg-[#0E0E10]">
                {nodes.length > 0 ? (
                  <ReactFlow
                    nodes={nodes}
                    edges={edges}
                    onNodesChange={onNodesChange}
                    onEdgesChange={onEdgesChange}
                    onNodeClick={onNodeClick}
                    fitView
                  >
                    <Background color="#333" gap={16} />
                    <Controls />
                    <MiniMap
                      nodeColor="#FF3D00"
                      maskColor="rgba(0,0,0,0.7)"
                      style={{ background: "#111" }}
                    />
                  </ReactFlow>
                ) : (
                  <div className="h-full flex flex-col items-center justify-center font-mono text-xs text-neutral-500 space-y-2">
                    <Layers className="w-8 h-8 text-neutral-600" />
                    <p>No evidence nodes reconstructed for this run.</p>
                  </div>
                )}
              </div>
            </Card>
          ) : (
            <Card title={`Textual Evidence Lineage Nodes (${(evidence?.nodes || []).length})`}>
              <div className="divide-y divide-neutral-200 dark:divide-neutral-800 text-xs">
                {(evidence?.nodes || []).map((node, idx) => {
                  const nodeType = node.node_type || (node as any).type || (node as any).data?.nodeType || "NODE";
                  const label = node.label || (node as any).data?.labelRaw || (node as any).data?.label || node.id;
                  const entityId = node.entity_id || (node as any).data?.entityId || (node as any).data?.subject_id || (node as any).data?.rule_id || node.id;
                  const props = node.properties || (node as any).data?.properties || (node as any).data || {};

                  return (
                    <div
                      key={`${node.id}-${idx}`}
                      onClick={() => setSelectedNode({ id: node.id, node_type: nodeType, label, entity_id: entityId, properties: props })}
                      className={`py-3 px-2 flex items-center justify-between cursor-pointer hover:bg-neutral-50 dark:hover:bg-neutral-900/60 ${
                        selectedNode?.id === node.id ? "bg-neutral-100 dark:bg-neutral-800/80 font-bold border-l-2 border-l-[#FF3D00]" : ""
                      }`}
                    >
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className="px-1.5 py-0.5 font-mono text-[10px] bg-neutral-200 dark:bg-neutral-800 uppercase">
                            {nodeType}
                          </span>
                          <span className="font-mono text-neutral-900 dark:text-white">
                            {label}
                          </span>
                        </div>
                        <div className="text-[10px] font-mono text-neutral-500">
                          Entity ID: {entityId}
                        </div>
                      </div>
                      <ArrowRight className="w-4 h-4 text-neutral-400" />
                    </div>
                  );
                })}
              </div>
            </Card>
          )}

          {/* Evidence Gaps Section */}
          {computedGaps.length > 0 && (
            <div className="mt-6">
              <Card
                title={`Identified Evidence Gaps & Missing Handshake Context (${computedGaps.length})`}
                variant="subtle"
              >
                <div className="space-y-2">
                  {computedGaps.map((gap: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 flex items-start space-x-3 text-xs"
                    >
                      <HelpCircle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                      <div>
                        <span className="font-mono font-bold text-neutral-900 dark:text-white">
                          Fact Required: {gap.fact_name}
                        </span>
                        <p className="text-neutral-500 mt-0.5">{gap.rationale}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            </div>
          )}
        </div>

        {/* Right Inspector Drawer */}
        {selectedNode && (
          <div className="lg:col-span-4">
            <InspectorDrawer
              isOpen={!!selectedNode}
              onClose={() => setSelectedNode(null)}
              title={selectedNode?.label || selectedNode?.id || "Evidence Node"}
              subtitle={`Node Type: ${(selectedNode?.node_type || (selectedNode as any)?.type || (selectedNode as any)?.data?.node_type || "NODE").toUpperCase()}`}
              badge={
                <span className="px-1.5 py-0.5 font-mono text-[10px] bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700">
                  {selectedNode?.node_type || (selectedNode as any)?.type || "NODE"}
                </span>
              }
            >
              <div className="space-y-4 font-mono text-xs">
                <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-1">
                  <div className="text-[10px] text-neutral-400 uppercase">Entity Reference</div>
                  <CopyableValue value={selectedNode.entity_id} label="Entity ID" />
                </div>

                <div>
                  <span className="text-[10px] uppercase text-neutral-400 block mb-1">
                    Forensic Properties
                  </span>
                  <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 space-y-1">
                    {selectedNode.properties ? (
                      Object.entries(selectedNode.properties).map(([k, v]) => (
                        <div key={k} className="flex justify-between py-0.5 border-b border-neutral-100 dark:border-neutral-800 last:border-0">
                          <span className="text-neutral-500">{k}:</span>
                          <span className="font-bold truncate max-w-[160px]">
                            {typeof v === "object" ? JSON.stringify(v) : String(v)}
                          </span>
                        </div>
                      ))
                    ) : (
                      <span className="text-neutral-500">No extra properties recorded.</span>
                    )}
                  </div>
                </div>

                {/* Byte Offset Verification */}
                <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-[11px] text-neutral-500">
                  <span className="font-bold block text-neutral-800 dark:text-neutral-200 mb-0.5">
                    Byte Offset Status:
                  </span>
                  {selectedNode.properties?.byte_offset !== undefined
                    ? `0x${Number(selectedNode.properties.byte_offset).toString(16)} (Validated)`
                    : "Byte offset unavailable from parser layer (zero-hallucination guarantee)."}
                </div>
              </div>
            </InspectorDrawer>
          </div>
        )}
      </div>
      )}
    </div>
  );
}

export default function EvidenceExplorerPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);

  return (
    <Suspense
      fallback={
        <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
          Loading forensic evidence explorer...
        </div>
      }
    >
      <EvidenceExplorerContent analysisId={analysisId} />
    </Suspense>
  );
}
