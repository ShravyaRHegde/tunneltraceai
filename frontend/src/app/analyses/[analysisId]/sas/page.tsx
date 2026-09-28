"use client";

import React, { use, useState, useEffect } from "react";
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
  Handle,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  CopyableValue,
} from "@/components/ui/table";
import { ChildSecurityAssociationDTO } from "@/lib/api/types";
import {
  GitBranch,
  Table as TableIcon,
  Network,
  AlertCircle,
  Shield,
  Layers,
  KeyRound,
  Lock,
  Activity,
  Maximize2,
} from "lucide-react";

interface SANodeData {
  tier: number;
  entityType: string;
  typeLabel: string;
  evidenceState: string;
  isNotObserved: boolean;
  isInferred: boolean;
  label: string;
  reason?: string;
  rawNode: any;
  [key: string]: any;
}

function SANode({ data, selected }: { data: SANodeData; selected?: boolean }) {
  const {
    typeLabel,
    isNotObserved,
    isInferred,
    label,
    reason,
    rawNode,
  } = data;
  const rawData = rawNode?.data || {};
  const nodeId = rawNode?.id || "";

  // Neutral icon per protocol entity type
  const renderIcon = () => {
    switch (data.tier) {
      case 0:
        return <Network className="w-3.5 h-3.5 text-neutral-500 dark:text-neutral-400 shrink-0" />;
      case 1:
        return <KeyRound className="w-3.5 h-3.5 text-neutral-500 dark:text-neutral-400 shrink-0" />;
      case 2:
        return <Shield className="w-3.5 h-3.5 text-neutral-500 dark:text-neutral-400 shrink-0" />;
      case 3:
        return <Lock className="w-3.5 h-3.5 text-neutral-500 dark:text-neutral-400 shrink-0" />;
      case 4:
        return <Activity className="w-3.5 h-3.5 text-neutral-500 dark:text-neutral-400 shrink-0" />;
      default:
        return <Layers className="w-3.5 h-3.5 text-neutral-500 dark:text-neutral-400 shrink-0" />;
    }
  };

  return (
    <div
      className={`w-[236px] p-2.5 rounded text-left transition-all duration-150 border select-none font-mono ${
        isNotObserved
          ? "bg-neutral-50/85 dark:bg-[#121215] border-dashed border-neutral-400 dark:border-neutral-700 text-neutral-500 dark:text-neutral-400 opacity-85"
          : isInferred
          ? "bg-white dark:bg-[#161619] border-neutral-300 dark:border-neutral-700/80 shadow-xs"
          : "bg-white dark:bg-[#161619] border-neutral-300 dark:border-neutral-700/80 shadow-xs"
      } ${
        selected
          ? "!border-[#FF3D00] !ring-2 !ring-[#FF3D00]/25 shadow-md"
          : "hover:border-neutral-400 dark:hover:border-neutral-500"
      }`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!w-2 !h-2 !border-2 !border-white dark:!border-[#161619] !bg-neutral-400 dark:!bg-neutral-500 !-left-1"
      />

      {/* Top Header: Neutral Entity Type + Dedicated Evidence Badge */}
      <div className="flex items-center justify-between gap-1.5 pb-2 border-b border-neutral-200/80 dark:border-neutral-800">
        <div className="flex items-center gap-1.5 min-w-0">
          {renderIcon()}
          <span className="text-[10px] font-bold tracking-wider text-neutral-600 dark:text-neutral-300 uppercase truncate">
            {typeLabel}
          </span>
        </div>

        {/* Evidence Status Chip */}
        {isNotObserved ? (
          <span
            className="inline-flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800 text-neutral-500 dark:text-neutral-400 border border-dashed border-neutral-300 dark:border-neutral-700 shrink-0"
            title="Absent from capture (e.g. handshake occurred prior to capture)"
          >
            <span className="w-1.5 h-1.5 rounded-full border border-neutral-400 dark:border-neutral-500"></span>
            NOT OBSERVED
          </span>
        ) : isInferred ? (
          <span
            className="inline-flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/30 shrink-0"
            title="Inferred from observed traffic or Child SAs"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
            INFERRED
          </span>
        ) : (
          <span
            className="inline-flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/30 shrink-0"
            title="Directly observed in capture packet frames"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            OBSERVED
          </span>
        )}
      </div>

      {/* Node Body: Primary Headline */}
      <div className="pt-2">
        <div
          className={`font-semibold text-xs leading-snug truncate ${
            isNotObserved
              ? "text-neutral-500 dark:text-neutral-400 italic"
              : "text-neutral-900 dark:text-neutral-100"
          }`}
          title={label}
        >
          {label}
        </div>

        {/* Entity-Specific Facts */}
        <div className="mt-1.5 space-y-1 text-[11px]">
          {data.tier === 0 && (
            <>
              <div className="flex justify-between items-center text-neutral-600 dark:text-neutral-400">
                <span className="text-[10px] text-neutral-400 dark:text-neutral-500">ROLE:</span>
                <span className="font-semibold text-neutral-800 dark:text-neutral-200 uppercase text-[10px]">
                  {rawData.role || "ENDPOINT"}
                </span>
              </div>
              <div className="flex justify-between items-center text-neutral-600 dark:text-neutral-400">
                <span className="text-[10px] text-neutral-400 dark:text-neutral-500">IP ADDR:</span>
                <span className="font-bold text-neutral-900 dark:text-neutral-100 text-[11px]">
                  {rawData.ip || nodeId.replace("peer-", "")}
                </span>
              </div>
            </>
          )}

          {data.tier === 1 && (
            <>
              <div className="flex justify-between items-center text-neutral-600 dark:text-neutral-400">
                <span className="text-[10px] text-neutral-400 dark:text-neutral-500">SPIs:</span>
                <span className="font-mono text-[10px] text-neutral-700 dark:text-neutral-300">
                  {isNotObserved
                    ? "Unobserved"
                    : rawData.initiator_spi || rawData.responder_spi
                    ? `${rawData.initiator_spi ? `${rawData.initiator_spi.slice(0, 6)}...` : "—"} ⇄ ${
                        rawData.responder_spi ? `${rawData.responder_spi.slice(0, 6)}...` : "—"
                      }`
                    : "Unobserved"}
                </span>
              </div>
              <div className="flex justify-between items-center text-neutral-600 dark:text-neutral-400">
                <span className="text-[10px] text-neutral-400 dark:text-neutral-500">TRANSPORT:</span>
                <span className="text-neutral-800 dark:text-neutral-200 text-[10px] font-semibold">
                  {isNotObserved ? "Unobserved" : rawData.nat_t ? "NAT-T (UDP 4500)" : "Standard (UDP 500)"}
                </span>
              </div>
            </>
          )}

          {data.tier === 2 && (
            <>
              <div className="flex justify-between items-center text-neutral-600 dark:text-neutral-400">
                <span className="text-[10px] text-neutral-400 dark:text-neutral-500">CIPHER:</span>
                <span className="font-bold text-neutral-800 dark:text-neutral-200 text-[10.5px]">
                  {rawData.cipher || (isNotObserved ? "None / Unobserved" : "Not Negotiated")}
                </span>
              </div>
              <div className="flex justify-between items-center text-neutral-600 dark:text-neutral-400">
                <span className="text-[10px] text-neutral-400 dark:text-neutral-500">DH / PRF:</span>
                <span className="text-neutral-700 dark:text-neutral-300 text-[10px] truncate max-w-[150px]">
                  {rawData.dh_group || (isNotObserved ? "Unobserved" : "N/A")}
                </span>
              </div>
            </>
          )}

          {data.tier === 3 && (
            <>
              <div className="flex justify-between items-center text-neutral-600 dark:text-neutral-400">
                <span className="text-[10px] text-neutral-400 dark:text-neutral-500">INBOUND SPI:</span>
                <span className="font-mono text-[10px] text-neutral-800 dark:text-neutral-200 font-bold">
                  {rawData.inbound_spi || (isNotObserved ? "Unobserved" : "N/A")}
                </span>
              </div>
              <div className="flex justify-between items-center text-neutral-600 dark:text-neutral-400">
                <span className="text-[10px] text-neutral-400 dark:text-neutral-500">OUTBOUND SPI:</span>
                <span className="font-mono text-[10px] text-neutral-800 dark:text-neutral-200 font-bold">
                  {rawData.outbound_spi || (isNotObserved ? "Unobserved" : "N/A")}
                </span>
              </div>
            </>
          )}

          {data.tier === 4 && (
            <>
              <div className="flex justify-between items-center text-neutral-600 dark:text-neutral-400">
                <span className="text-[10px] text-neutral-400 dark:text-neutral-500">VOLUME:</span>
                <span className="font-bold text-neutral-800 dark:text-neutral-200 text-[10.5px]">
                  {isNotObserved
                    ? "0 pkts (Unobserved)"
                    : rawData.packet_count !== undefined
                    ? `${rawData.packet_count} pkts · ${rawData.byte_count ?? 0} B`
                    : "0 pkts"}
                </span>
              </div>
              <div className="flex justify-between items-center text-neutral-600 dark:text-neutral-400">
                <span className="text-[10px] text-neutral-400 dark:text-neutral-500">STREAM:</span>
                <span className="font-semibold text-[10px] text-neutral-700 dark:text-neutral-300">
                  {isNotObserved ? "Not Observed" : rawData.association || "Single Flow"}
                </span>
              </div>
            </>
          )}
        </div>

        {/* Reason notice for unobserved/missing entities */}
        {reason && (
          <div className="mt-2 p-1.5 rounded bg-amber-500/10 dark:bg-amber-950/30 border border-amber-500/20 text-amber-800 dark:text-amber-300 text-[10px] leading-tight">
            {reason}
          </div>
        )}

        {/* Quieter identifier footer */}
        <div
          className="mt-2 pt-1.5 border-t border-neutral-100 dark:border-neutral-800/80 text-[9.5px] text-neutral-400 dark:text-neutral-500 font-mono flex items-center justify-between"
          title={nodeId}
        >
          <span className="truncate">
            {nodeId.startsWith("0x")
              ? `${nodeId.slice(0, 10)}...${nodeId.slice(-4)}`
              : nodeId.length > 22
              ? `${nodeId.slice(0, 18)}...`
              : nodeId}
          </span>
          <span className="text-[9px] text-neutral-400 uppercase">TIER {data.tier + 1}</span>
        </div>
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!w-2 !h-2 !border-2 !border-white dark:!border-[#161619] !bg-neutral-400 dark:!bg-neutral-500 !-right-1"
      />
    </div>
  );
}

const nodeTypes = {
  saNode: SANode,
};

export default function SecurityAssociationExplorerPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");
  const [selectedSa, setSelectedSa] = useState<ChildSecurityAssociationDTO | null>(null);
  const [selectedNode, setSelectedNode] = useState<{ id: string; type: string; label: string; data?: any } | null>(null);
  const [isDark, setIsDark] = useState<boolean>(false);

  // Dynamic theme observer to switch React Flow styles seamlessly
  useEffect(() => {
    const checkDark = () => {
      setIsDark(document.documentElement.classList.contains("dark"));
    };
    checkDark();
    const observer = new MutationObserver(checkDark);
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"],
    });
    return () => observer.disconnect();
  }, []);

  // Fetch SA List (tabular data)
  const {
    data: saList,
    isLoading: isListLoading,
  } = useQuery({
    queryKey: ["sas-list", analysisId],
    queryFn: () => api.analyses.getSas(analysisId),
  });

  // Fetch SA Graph (nodes and edges)
  const {
    data: saGraph,
    isLoading: isGraphLoading,
  } = useQuery({
    queryKey: ["sas-graph", analysisId],
    queryFn: () => api.analyses.getSaGraph(analysisId),
  });

  // React Flow state
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [rfInstance, setRfInstance] = useState<any>(null);

  // Count nodes by tier and evidence state
  const tierCounts = React.useMemo(() => {
    const counts = { peers: 0, sessions: 0, ikeSas: 0, childSas: 0, flows: 0, observed: 0, total: 0 };
    if (!saGraph?.nodes) return counts;
    counts.total = saGraph.nodes.length;
    saGraph.nodes.forEach((n: any) => {
      const t = (n.type || "").toLowerCase();
      const nid = (n.id || "").toLowerCase();
      const ev = n.data?.evidence_state || n.evidence_state;
      if (ev === "OBSERVED") counts.observed++;

      if (t.includes("peer") || nid.includes("peer")) counts.peers++;
      else if (t.includes("session") || nid.includes("session")) counts.sessions++;
      else if (t.includes("ike") && !t.includes("child")) counts.ikeSas++;
      else if (t.includes("child") || nid.includes("child")) counts.childSas++;
      else if (t.includes("flow") || nid.includes("flow") || t.includes("esp")) counts.flows++;
    });
    if (saList && saList.length > counts.childSas) {
      counts.childSas = saList.length;
    }
    return counts;
  }, [saGraph, saList]);

  useEffect(() => {
    if (saGraph && saGraph.nodes && saGraph.edges) {
      // Classify node tier for hierarchical left-to-right topology (0..4)
      const getTier = (type: string, id: string): number => {
        const t = (type || "").toLowerCase();
        const nid = (id || "").toLowerCase();
        if (t.includes("peer") || nid.includes("peer")) return 0;
        if (t.includes("session") || nid.includes("session")) return 1;
        if (t.includes("ike") && !t.includes("child")) return 2;
        if (t.includes("child") || nid.includes("child")) return 3;
        if (t.includes("flow") || nid.includes("flow") || t.includes("esp")) return 4;
        return 2;
      };

      const NODE_WIDTH = 236;
      const HORIZ_GAP = 140;
      const VERT_STEP = 145;

      // Group nodes into distinct tiers
      const tiers: Record<number, any[]> = { 0: [], 1: [], 2: [], 3: [], 4: [] };
      saGraph.nodes.forEach((n) => {
        const tier = getTier(n.type, n.id);
        tiers[tier].push(n);
      });

      // Align baseline center with Tier 0 (Peers) group
      const tier0Count = tiers[0].length || 1;
      const calculatedCenter = 40 + ((tier0Count - 1) * VERT_STEP) / 2;

      // Unobserved node set for styling connected edges
      const unobservedNodeIds = new Set<string>();
      saGraph.nodes.forEach((n) => {
        const ev = n.data?.evidence_state || (n as any).evidence_state;
        if (ev === "NOT_OBSERVED" || n.id.includes("unobserved")) {
          unobservedNodeIds.add(n.id);
        }
      });

      const tierLabels: Record<number, string> = {
        0: "Peer Gateway",
        1: "IKE Session",
        2: "IKE SA (Control)",
        3: "Child SA (Data)",
        4: "ESP Flow",
      };

      const formattedNodes: Node[] = [];

      for (let tier = 0; tier <= 4; tier++) {
        const nodesInTier = tiers[tier];
        const count = nodesInTier.length;
        if (count === 0) continue;

        // Vertically center nodes in this tier around calculatedCenter
        const startY = calculatedCenter - ((count - 1) * VERT_STEP) / 2;

        nodesInTier.forEach((n, idx) => {
          const xPos = 40 + tier * (NODE_WIDTH + HORIZ_GAP);
          const yPos = startY + idx * VERT_STEP;

          const evState = n.data?.evidence_state || (n as any).evidence_state || "";
          const isNotObserved = evState === "NOT_OBSERVED" || n.id.includes("unobserved");
          const isInferred = evState.includes("INFERRED");

          formattedNodes.push({
            id: n.id,
            type: "saNode",
            position: { x: xPos, y: yPos },
            data: {
              tier,
              entityType: n.type,
              typeLabel: tierLabels[tier] || n.type,
              evidenceState: evState,
              isNotObserved,
              isInferred,
              label: n.label || n.type,
              reason: n.data?.reason,
              rawNode: n,
            },
          });
        });
      }

      // Ensure no nodes are placed higher than padding margin
      const minY = Math.min(...formattedNodes.map((n) => n.position.y));
      if (minY < 40) {
        const offset = 40 - minY;
        formattedNodes.forEach((n) => {
          n.position.y += offset;
        });
      }

      const formattedEdges: Edge[] = saGraph.edges.map((e) => {
        const isDashed = unobservedNodeIds.has(e.source) || unobservedNodeIds.has(e.target);
        const strokeColor = isDark
          ? isDashed ? "#52525B" : "#71717A"
          : isDashed ? "#94A3B8" : "#64748B";

        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label,
          type: "smoothstep",
          pathOptions: { borderRadius: 12 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            width: 12,
            height: 12,
            color: strokeColor,
          },
          style: {
            stroke: strokeColor,
            strokeWidth: isDashed ? 1.5 : 2,
            strokeDasharray: isDashed ? "5,5" : undefined,
          },
          labelStyle: {
            fill: isDark
              ? isDashed ? "#A1A1AA" : "#F4F4F5"
              : isDashed ? "#64748B" : "#0F172A",
            fontSize: 8.5,
            fontFamily: "ui-monospace, monospace",
            fontWeight: 700,
            letterSpacing: "0.03em",
          },
          labelBgStyle: {
            fill: isDark ? "#141416" : "#FFFFFF",
            fillOpacity: 0.98,
            stroke: isDark
              ? isDashed ? "#3F3F46" : "#52525B"
              : isDashed ? "#CBD5E1" : "#94A3B8",
            strokeWidth: 1,
            rx: 4,
            ry: 4,
          },
          labelBgPadding: [6, 2.5] as [number, number],
        };
      });

      setNodes(formattedNodes);
      setEdges(formattedEdges);
    }
  }, [saGraph, isDark, setNodes, setEdges]);

  const onNodeClick = (_: any, node: Node) => {
    const raw = (node.data as any)?.rawNode;
    setSelectedNode(raw || { id: node.id, type: node.type || "node", label: String(node.id) });

    const matched = (saList || []).find(
      (sa) => sa.id === node.id || sa.inbound_spi === node.id || sa.outbound_spi === node.id || node.id.includes(sa.id)
    );
    setSelectedSa(matched || null);
  };

  const isLoading = isListLoading || isGraphLoading;

  return (
    <div className="space-y-6">
      {/* Header & View Mode Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <GitBranch className="w-5 h-5 text-[#FF3D00]" />
            <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
              Security Association (SA) Topology & Flow Explorer
            </h1>
          </div>
          <p className="text-xs text-neutral-500 mt-1">
            <strong className="text-neutral-700 dark:text-neutral-300">What this shows:</strong> The hierarchical relationship from peer gateways to IKE sessions, Child SAs, and directional ESP flows. Nodes not captured in the PCAP are explicitly shown with dashed borders as NOT OBSERVED.
          </p>
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
            <span>Topology Graph</span>
          </button>
          <button
            onClick={() => setViewMode("table")}
            className={`flex items-center space-x-1.5 px-3 py-1.5 text-xs font-mono font-bold uppercase transition-colors ${
              viewMode === "table"
                ? "bg-[#FF3D00] text-white"
                : "text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
            }`}
          >
            <TableIcon className="w-3.5 h-3.5" />
            <span>SA Table Fallback</span>
          </button>
        </div>
      </div>

      {/* Main Workspace (12 cols: 8/7 cols canvas/table + 4/5 cols inspector) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className={selectedSa || selectedNode ? "lg:col-span-8" : "lg:col-span-12"}>
          {isLoading ? (
            <div className="py-24 text-center font-mono text-xs text-neutral-500 animate-pulse border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416]">
              Traversing SA session graph and directional SPI associations...
            </div>
          ) : viewMode === "graph" ? (
            <Card
              title="SA & ESP Flow Topology Pipeline"
              actions={
                <button
                  onClick={() => rfInstance?.fitView({ padding: 0.15, duration: 400 })}
                  className="flex items-center space-x-1 px-2.5 py-1 text-[11px] font-mono font-medium border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-[#18181B] hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-700 dark:text-neutral-200 transition-colors shadow-xs"
                  title="Fit all topology nodes into viewport"
                >
                  <Maximize2 className="w-3 h-3 text-[#FF3D00]" />
                  <span>Fit View</span>
                </button>
              }
            >
              {/* Summary Metric Strip */}
              <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 px-4 py-2 bg-neutral-100/60 dark:bg-[#101013] border-b border-neutral-200 dark:border-neutral-800 text-xs font-mono">
                <div>
                  <div className="text-[10px] text-neutral-400 uppercase font-semibold">Peers</div>
                  <div className="font-bold text-neutral-800 dark:text-neutral-200">{tierCounts.peers}</div>
                </div>
                <div>
                  <div className="text-[10px] text-neutral-400 uppercase font-semibold">Sessions</div>
                  <div className="font-bold text-neutral-800 dark:text-neutral-200">{tierCounts.sessions}</div>
                </div>
                <div>
                  <div className="text-[10px] text-neutral-400 uppercase font-semibold">IKE SAs</div>
                  <div className="font-bold text-neutral-800 dark:text-neutral-200">{tierCounts.ikeSas}</div>
                </div>
                <div>
                  <div className="text-[10px] text-neutral-400 uppercase font-semibold">Child SAs</div>
                  <div className="font-bold text-neutral-800 dark:text-neutral-200">{tierCounts.childSas}</div>
                </div>
                <div>
                  <div className="text-[10px] text-neutral-400 uppercase font-semibold">ESP Flows</div>
                  <div className="font-bold text-neutral-800 dark:text-neutral-200">{tierCounts.flows}</div>
                </div>
                <div>
                  <div className="text-[10px] text-neutral-400 uppercase font-semibold">Observed</div>
                  <div className="font-bold text-emerald-700 dark:text-emerald-400">
                    {tierCounts.observed} / {tierCounts.total}
                  </div>
                </div>
              </div>

              {/* Refined Dual-Section Legend Bar: Pipeline Stages & Evidence States */}
              <div className="px-4 py-2.5 bg-neutral-50/90 dark:bg-[#141417] border-b border-neutral-200 dark:border-neutral-800 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
                {/* Left: 5-Stage Hierarchy Pipeline */}
                <div className="flex items-center gap-1.5 flex-wrap text-[11px]">
                  <span className="text-neutral-400 dark:text-neutral-500 uppercase font-bold text-[10px] mr-1">
                    PIPELINE STAGES:
                  </span>
                  <span className="px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 border border-neutral-200 dark:border-neutral-700 font-semibold">1. Peer</span>
                  <span className="text-neutral-400 dark:text-neutral-600">→</span>
                  <span className="px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 border border-neutral-200 dark:border-neutral-700 font-semibold">2. IKE Session</span>
                  <span className="text-neutral-400 dark:text-neutral-600">→</span>
                  <span className="px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 border border-neutral-200 dark:border-neutral-700 font-semibold">3. IKE SA</span>
                  <span className="text-neutral-400 dark:text-neutral-600">→</span>
                  <span className="px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 border border-neutral-200 dark:border-neutral-700 font-semibold">4. Child SA</span>
                  <span className="text-neutral-400 dark:text-neutral-600">→</span>
                  <span className="px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 border border-neutral-200 dark:border-neutral-700 font-semibold">5. ESP Flow</span>
                </div>

                {/* Right: Evidence Encoding (3 distinct states) */}
                <div className="flex items-center gap-3 text-[11px] flex-wrap">
                  <span className="text-neutral-400 dark:text-neutral-500 uppercase font-bold text-[10px]">
                    EVIDENCE:
                  </span>
                  <div className="flex items-center gap-1.5" title="Directly observed in captured packet frames">
                    <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                    <span className="text-neutral-700 dark:text-neutral-300 font-medium">Observed in PCAP</span>
                  </div>
                  <div className="flex items-center gap-1.5" title="Inferred or synthesized from correlated IPsec traffic">
                    <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                    <span className="text-neutral-700 dark:text-neutral-300 font-medium">Inferred / Synthesized</span>
                  </div>
                  <div className="flex items-center gap-1.5" title="Absent from packet capture (e.g. handshake occurred before capture)">
                    <span className="w-2 h-2 rounded-full border border-dashed border-neutral-400 dark:border-neutral-500 bg-neutral-200/50 dark:bg-neutral-800"></span>
                    <span className="text-neutral-500 dark:text-neutral-400 italic">Not Observed (Missing)</span>
                  </div>
                </div>
              </div>

              {/* React Flow Canvas */}
              <div className="h-[500px] w-full bg-[#F8FAFC] dark:bg-[#0D0D11] rounded-b relative overflow-hidden">
                {nodes.length > 0 ? (
                  <ReactFlow
                    nodes={nodes}
                    edges={edges}
                    nodeTypes={nodeTypes}
                    onNodesChange={onNodesChange}
                    onEdgesChange={onEdgesChange}
                    onNodeClick={onNodeClick}
                    onInit={(instance) => setRfInstance(instance)}
                    colorMode={isDark ? "dark" : "light"}
                    fitView
                    fitViewOptions={{ padding: 0.10, includeHiddenNodes: false }}
                    minZoom={0.25}
                    maxZoom={2.0}
                    defaultEdgeOptions={{ type: "smoothstep" }}
                  >
                    <Background
                      color={isDark ? "#27272A" : "#CBD5E1"}
                      gap={22}
                      size={1}
                    />
                    <Controls
                      position="bottom-left"
                      showInteractive={false}
                      className={`!border rounded shadow-md font-mono text-xs ${
                        isDark
                          ? "!bg-[#18181B] !border-neutral-700 !text-neutral-200 fill-neutral-200 [&_button]:!bg-[#18181B] [&_button]:!border-neutral-700 [&_button]:!fill-neutral-300 [&_button:hover]:!bg-neutral-800"
                          : "!bg-white !border-neutral-300 !text-neutral-700 fill-neutral-700 [&_button]:!bg-white [&_button]:!border-neutral-200 [&_button]:!fill-neutral-600 [&_button:hover]:!bg-neutral-100"
                      }`}
                    />
                    <MiniMap
                      position="bottom-right"
                      nodeColor={(n) => {
                        const raw = (n.data as any)?.rawNode;
                        const ev = raw?.data?.evidence_state || "";
                        if (ev === "NOT_OBSERVED" || n.id.includes("unobserved")) return isDark ? "#3F3F46" : "#94A3B8";
                        if (ev.includes("INFERRED")) return "#F59E0B";
                        return "#10B981";
                      }}
                      maskColor={isDark ? "rgba(13, 13, 17, 0.75)" : "rgba(240, 244, 248, 0.65)"}
                      style={{
                        background: isDark ? "#141417" : "#FFFFFF",
                        border: isDark ? "1px solid #333338" : "1px solid #CBD5E1",
                        borderRadius: "4px",
                        width: 140,
                        height: 80,
                      }}
                    />
                  </ReactFlow>
                ) : (
                  <div className="h-full flex flex-col items-center justify-center font-mono text-xs text-neutral-500 space-y-2 p-6 text-center">
                    <Layers className="w-8 h-8 text-neutral-400" />
                    <p className="font-bold text-neutral-700 dark:text-neutral-300">
                      No Security Associations Reconstructed
                    </p>
                    <p className="text-[11px] text-neutral-400 max-w-md">
                      This capture artifact contains no IKE negotiation or ESP encrypted flows. Security Association hierarchies are only formed when IPsec handshake or data packets are observed.
                    </p>
                  </div>
                )}
              </div>
            </Card>
          ) : (
            <Card title={`Child Security Associations (${saList?.length || 0})`}>
              {saList && saList.length > 0 ? (
                <Table>
                  <TableHeader>
                    <tr>
                      <TableHead>SA ID</TableHead>
                      <TableHead>Inbound SPI</TableHead>
                      <TableHead>Outbound SPI</TableHead>
                      <TableHead>Mode</TableHead>
                      <TableHead>Encryption</TableHead>
                      <TableHead>PFS</TableHead>
                      <TableHead>State</TableHead>
                    </tr>
                  </TableHeader>
                  <TableBody>
                    {saList.map((sa) => (
                      <TableRow
                        key={sa.id}
                        onClick={() => {
                          setSelectedSa(sa);
                          setSelectedNode(null);
                        }}
                        isSelected={selectedSa?.id === sa.id}
                      >
                        <TableCell mono>
                          <CopyableValue value={sa.id} truncate label="SA ID" />
                        </TableCell>
                        <TableCell mono>
                          <CopyableValue value={sa.inbound_spi} label="Inbound SPI" />
                        </TableCell>
                        <TableCell mono>
                          <CopyableValue value={sa.outbound_spi} label="Outbound SPI" />
                        </TableCell>
                        <TableCell mono>
                          <span className="font-bold">{sa.mode}</span>
                        </TableCell>
                        <TableCell mono>{sa.encryption_algorithm || "UNKNOWN"}</TableCell>
                        <TableCell mono>{sa.pfs_status}</TableCell>
                        <TableCell mono className="text-neutral-400">
                          {sa.lifecycle_state}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <div className="py-12 text-center font-mono text-xs text-neutral-500">
                  No Child Security Associations found.
                </div>
              )}
            </Card>
          )}
        </div>

        {/* Right Contextual Inspector */}
        {(selectedSa || selectedNode) && (
          <div className="lg:col-span-4">
            <InspectorDrawer
              isOpen={!!(selectedSa || selectedNode)}
              onClose={() => {
                setSelectedSa(null);
                setSelectedNode(null);
              }}
              title={
                selectedSa
                  ? `SA: ${selectedSa.inbound_spi}`
                  : `${selectedNode?.type?.toUpperCase() || "NODE"}: ${selectedNode?.label || selectedNode?.id}`
              }
              subtitle={
                selectedSa
                  ? `Protocol: ${selectedSa.protocol}`
                  : `ID: ${selectedNode?.id}`
              }
              badge={
                <span className="px-1.5 py-0.5 font-mono text-[10px] bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700">
                  {selectedSa?.lifecycle_state || selectedNode?.type?.toUpperCase() || "OBSERVED"}
                </span>
              }
            >
              {selectedSa ? (
                <div className="space-y-4">
                  <div>
                    <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                      SPI Identification
                    </span>
                    <div className="space-y-1 font-mono text-xs bg-neutral-50 dark:bg-neutral-900 p-2.5 border border-neutral-200 dark:border-neutral-800">
                      <div className="flex justify-between">
                        <span className="text-neutral-500">Inbound:</span>
                        <CopyableValue value={selectedSa.inbound_spi} label="Inbound SPI" />
                      </div>
                      <div className="flex justify-between">
                        <span className="text-neutral-500">Outbound:</span>
                        <CopyableValue value={selectedSa.outbound_spi} label="Outbound SPI" />
                      </div>
                    </div>
                  </div>

                  <div>
                    <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                      Tunnel Mode & Algorithms
                    </span>
                    <div className="space-y-1 font-mono text-xs bg-neutral-50 dark:bg-neutral-900 p-2.5 border border-neutral-200 dark:border-neutral-800">
                      <div className="flex justify-between">
                        <span className="text-neutral-500">Mode:</span>
                        <span className="font-bold">{selectedSa.mode}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-neutral-500">Encryption:</span>
                        <span>{selectedSa.encryption_algorithm || "UNKNOWN"}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-neutral-500">Integrity:</span>
                        <span>{selectedSa.integrity_algorithm || "UNKNOWN"}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-neutral-500">PFS Status:</span>
                        <span>{selectedSa.pfs_status}</span>
                      </div>
                      {selectedSa.pfs_dh_group && (
                        <div className="flex justify-between">
                          <span className="text-neutral-500">PFS DH Group:</span>
                          <span>{selectedSa.pfs_dh_group}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  <div>
                    <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                      Evidence Verification State
                    </span>
                    <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 font-mono text-xs space-y-1">
                      <div className="flex justify-between">
                        <span className="text-neutral-500">Mode Evidence:</span>
                        <span>{selectedSa.mode_evidence_state}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-neutral-500">PFS Evidence:</span>
                        <span>{selectedSa.pfs_evidence_state}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-neutral-500">Overall:</span>
                        <span>{selectedSa.evidence_state}</span>
                      </div>
                    </div>
                  </div>
                </div>
              ) : selectedNode ? (
                <div className="space-y-4">
                  {(selectedNode.data?.evidence_state === "NOT_OBSERVED" || selectedNode.id.includes("unobserved")) && (
                    <div className="p-3 bg-neutral-100 dark:bg-neutral-800 border-2 border-dashed border-neutral-400 dark:border-neutral-600 rounded text-xs font-mono space-y-1.5">
                      <div className="flex items-center space-x-1.5 text-neutral-800 dark:text-neutral-200 font-bold uppercase text-[11px]">
                        <AlertCircle className="w-4 h-4 text-neutral-500" />
                        <span>Evidence Absent in PCAP</span>
                      </div>
                      <p className="text-neutral-600 dark:text-neutral-300 text-[11px] leading-relaxed">
                        {selectedNode.data?.reason || "This protocol tier was not captured in the packet trace. If the IKE handshake occurred before sniffing started, only subsequent ESP ciphertext flows are present."}
                      </p>
                      <div className="text-[10px] text-neutral-500">
                        Status: <span className="font-bold text-neutral-700 dark:text-neutral-300">NOT ASSESSABLE FROM CAPTURE</span>
                      </div>
                    </div>
                  )}

                  <div>
                    <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                      Node Properties
                    </span>
                    <div className="space-y-1 font-mono text-xs bg-neutral-50 dark:bg-neutral-900 p-2.5 border border-neutral-200 dark:border-neutral-800">
                      <div className="flex justify-between">
                        <span className="text-neutral-500">Identifier:</span>
                        <CopyableValue value={selectedNode.id} label="Node ID" />
                      </div>
                      <div className="flex justify-between">
                        <span className="text-neutral-500">Type:</span>
                        <span className="font-bold">{selectedNode.type}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-neutral-500">Label:</span>
                        <span>{selectedNode.label}</span>
                      </div>
                    </div>
                  </div>

                  {selectedNode.data && (
                    <div>
                      <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-1">
                        Metadata & Metrics
                      </span>
                      <div className="space-y-1 font-mono text-xs bg-neutral-50 dark:bg-neutral-900 p-2.5 border border-neutral-200 dark:border-neutral-800">
                        {Object.entries(selectedNode.data).map(([k, v]) => (
                          <div key={k} className="flex justify-between py-0.5 border-b border-neutral-200 dark:border-neutral-800 last:border-b-0">
                            <span className="text-neutral-500">{k}:</span>
                            <span className="font-semibold">{String(v ?? "N/A")}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : null}
            </InspectorDrawer>
          </div>
        )}
      </div>
    </div>
  );
}
