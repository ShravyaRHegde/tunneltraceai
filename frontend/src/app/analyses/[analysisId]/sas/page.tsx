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
} from "lucide-react";

export default function SecurityAssociationExplorerPage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = use(params);
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");
  const [selectedSa, setSelectedSa] = useState<ChildSecurityAssociationDTO | null>(null);
  const [selectedNode, setSelectedNode] = useState<{ id: string; type: string; label: string; data?: any } | null>(null);

  // Fetch SA List (tabular data)
  const {
    data: saList,
    isLoading: isListLoading,
    isError: isListError,
  } = useQuery({
    queryKey: ["sas-list", analysisId],
    queryFn: () => api.analyses.getSas(analysisId),
  });

  // Fetch SA Graph (nodes and edges)
  const {
    data: saGraph,
    isLoading: isGraphLoading,
    isError: isGraphError,
  } = useQuery({
    queryKey: ["sas-graph", analysisId],
    queryFn: () => api.analyses.getSaGraph(analysisId),
  });

  // React Flow state
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

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

      const NODE_WIDTH = 220;
      const HORIZ_GAP = 180; // 180px gap provides clearance for full edge labels
      const VERT_STEP = 150;

      const tierCounts: Record<number, number> = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 };

      const typeStyles: Record<number, { border: string; bg: string; badge: string; text: string }> = {
        0: { border: "#3B82F6", bg: "#EFF6FF", badge: "PEER", text: "#1E40AF" },
        1: { border: "#8B5CF6", bg: "#F5F3FF", badge: "IKE SESSION", text: "#5B21B6" },
        2: { border: "#F59E0B", bg: "#FFFBEB", badge: "IKE SA", text: "#92400E" },
        3: { border: "#10B981", bg: "#ECFDF5", badge: "CHILD SA", text: "#065F46" },
        4: { border: "#FF3D00", bg: "#FFF7ED", badge: "ESP FLOW", text: "#C2410C" },
      };

      // Unobserved node set for styling connected edges
      const unobservedNodeIds = new Set<string>();
      saGraph.nodes.forEach((n) => {
        const ev = n.data?.evidence_state || (n as any).evidence_state;
        if (ev === "NOT_OBSERVED" || n.id.includes("unobserved")) {
          unobservedNodeIds.add(n.id);
        }
      });

      const formattedNodes: Node[] = saGraph.nodes.map((n) => {
        const tier = getTier(n.type, n.id);
        const yIndex = tierCounts[tier] || 0;
        tierCounts[tier] = yIndex + 1;

        // Strictly fixed 5-column layout: Peer (col 0) -> IKE Session (col 1) -> IKE SA (col 2) -> Child SA (col 3) -> ESP Flow (col 4)
        const xPos = 40 + tier * (NODE_WIDTH + HORIZ_GAP);
        const yPos = 40 + yIndex * VERT_STEP;

        const evState = n.data?.evidence_state || (n as any).evidence_state || "";
        const isNotObserved = evState === "NOT_OBSERVED" || n.id.includes("unobserved");
        const isInferred = evState.includes("INFERRED");

        const baseStyle = typeStyles[tier] || typeStyles[2];

        // Determine border, bg, and badge based on evidence state
        let border = baseStyle.border;
        let borderStyle = "solid";
        let bg = "#FFFFFF";
        let badgeBg = baseStyle.bg;
        let badgeText = baseStyle.text;
        let badgeLabel = baseStyle.badge;

        if (isNotObserved) {
          border = "#94A3B8";
          borderStyle = "dashed";
          bg = "#F8FAFC";
          badgeBg = "#F1F5F9";
          badgeText = "#64748B";
          badgeLabel = `${baseStyle.badge} · NOT OBSERVED`;
        } else if (isInferred) {
          border = "#F59E0B";
          badgeBg = "#FEF3C7";
          badgeText = "#B45309";
          badgeLabel = `${baseStyle.badge} · INFERRED`;
        }

        return {
          id: n.id,
          type: "default",
          sourcePosition: Position.Right,
          targetPosition: Position.Left,
          data: {
            label: (
              <div className="text-left font-mono">
                <div className="flex items-center justify-between mb-1 pb-1 border-b border-neutral-200 dark:border-neutral-700">
                  <span
                    className="text-[9px] font-bold px-1.5 py-0.5 rounded tracking-wider uppercase"
                    style={{ backgroundColor: badgeBg, color: badgeText, border: `1px solid ${border}` }}
                  >
                    {badgeLabel}
                  </span>
                  {isNotObserved && (
                    <span className="text-[9px] text-neutral-400 italic">missing</span>
                  )}
                </div>
                <div className={`font-semibold text-xs leading-tight ${isNotObserved ? "text-neutral-500 italic" : "text-neutral-900 dark:text-neutral-100"}`}>
                  {n.label || n.type}
                </div>
                {n.data?.reason ? (
                  <div className="text-[10px] text-amber-600 dark:text-amber-400 mt-1 leading-snug">
                    {n.data.reason}
                  </div>
                ) : (
                  <div className="text-[10px] text-neutral-500 font-mono mt-1 break-all" title={n.id}>
                    {n.id.startsWith("0x")
                      ? `${n.id.slice(0, 10)}...${n.id.slice(-4)}`
                      : n.id.length > 20
                      ? `${n.id.slice(0, 16)}...`
                      : n.id}
                  </div>
                )}
              </div>
            ),
            rawNode: n,
          },
          position: { x: xPos, y: yPos },
          style: {
            background: bg,
            color: isNotObserved ? "#64748B" : "#0F172A",
            border: `2px ${borderStyle} ${border}`,
            borderRadius: "4px",
            boxShadow: isNotObserved ? "none" : "0 2px 6px rgba(0,0,0,0.08)",
            fontFamily: "monospace",
            fontSize: "11px",
            padding: "10px 12px",
            width: NODE_WIDTH,
            opacity: isNotObserved ? 0.85 : 1.0,
          },
        };
      });

      const formattedEdges: Edge[] = saGraph.edges.map((e) => {
        const isDashed = unobservedNodeIds.has(e.source) || unobservedNodeIds.has(e.target);
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label,
          type: "smoothstep",
          style: {
            stroke: isDashed ? "#94A3B8" : "#64748B",
            strokeWidth: isDashed ? 1.5 : 2,
            strokeDasharray: isDashed ? "5,5" : undefined,
          },
          labelStyle: {
            fill: isDashed ? "#64748B" : "#0F172A",
            fontSize: 10,
            fontFamily: "ui-monospace, monospace",
            fontWeight: 700,
            letterSpacing: "0.04em",
          },
          labelBgStyle: {
            fill: "#FFFFFF",
            fillOpacity: 0.98,
            stroke: isDashed ? "#CBD5E1" : "#94A3B8",
            strokeWidth: 1.5,
            rx: 4,
            ry: 4,
          },
          labelBgPadding: [8, 4] as [number, number],
        };
      });

      setNodes(formattedNodes);
      setEdges(formattedEdges);
    }
  }, [saGraph, setNodes, setEdges]);

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
            <Card title="SA Topology DAG (Hierarchical Layout)">
              {/* Legend Row */}
              <div className="p-3 bg-neutral-100 dark:bg-neutral-900 border-b border-neutral-200 dark:border-neutral-800 space-y-2 text-[10px] font-mono">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-neutral-500 font-bold uppercase">5-Level Hierarchy:</span>
                    <span className="px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">1. Peer</span>
                    <span className="text-neutral-400">→</span>
                    <span className="px-1.5 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200">2. IKE Session</span>
                    <span className="text-neutral-400">→</span>
                    <span className="px-1.5 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200">3. IKE SA</span>
                    <span className="text-neutral-400">→</span>
                    <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">4. Child SA</span>
                    <span className="text-neutral-400">→</span>
                    <span className="px-1.5 py-0.5 rounded bg-orange-50 text-orange-700 border border-orange-200">5. ESP Flow</span>
                  </div>
                  <span className="text-neutral-400">Click node for inspection details</span>
                </div>
                <div className="flex flex-wrap items-center gap-3 pt-1 border-t border-neutral-200 dark:border-neutral-800 text-[10px]">
                  <span className="text-neutral-500 font-bold uppercase">Evidence States:</span>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-sm bg-emerald-50 border border-emerald-500 inline-block"></span>
                    <span className="text-neutral-700 dark:text-neutral-300">Observed in PCAP</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-sm bg-amber-50 border border-amber-500 inline-block"></span>
                    <span className="text-neutral-700 dark:text-neutral-300">Inferred / Synthesized</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-sm bg-slate-100 border border-dashed border-slate-400 inline-block"></span>
                    <span className="text-neutral-700 dark:text-neutral-300">Not Observed (Missing from Capture)</span>
                  </div>
                </div>
              </div>

              <div className="h-[620px] w-full border border-neutral-200 dark:border-neutral-800 bg-[#F8FAFC] dark:bg-[#111113] rounded-b relative">
                {nodes.length > 0 ? (
                  <ReactFlow
                    nodes={nodes}
                    edges={edges}
                    onNodesChange={onNodesChange}
                    onEdgesChange={onEdgesChange}
                    onNodeClick={onNodeClick}
                    fitView
                    fitViewOptions={{ padding: 0.15 }}
                    minZoom={0.2}
                    maxZoom={2.0}
                  >
                    <Background color="#CBD5E1" gap={20} size={1} />
                    <Controls className="bg-white dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-700 shadow-sm" />
                    <MiniMap
                      nodeColor="#FF3D00"
                      maskColor="rgba(240,244,248,0.7)"
                      style={{ background: "#FFFFFF", border: "1px solid #CBD5E1" }}
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
