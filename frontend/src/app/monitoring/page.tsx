"use client";

import React, { useState, useEffect, useRef, Suspense } from "react";
import Link from "next/link";
import { useSearchParams, useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import {
  GatewayResponseDTO,
  SensorResponseDTO,
  RegisterSensorResponseDTO,
  SensorHealthDTO,
  MonitoredSAStateDTO,
  MonitoringEventItemDTO,
} from "@/lib/api/types";
import { Card } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  CopyableValue,
} from "@/components/ui/table";
import { InspectorDrawer } from "@/components/ui/inspector-drawer";
import {
  Radio,
  Activity,
  Server,
  Cpu,
  ShieldCheck,
  AlertTriangle,
  Clock,
  RefreshCw,
  PlusCircle,
  Copy,
  Check,
  XCircle,
  Zap,
  Lock,
  GitBranch,
  Layers,
  ChevronRight,
  Eye,
  EyeOff,
  Trash2,
  ExternalLink,
  FileKey2,
  X,
} from "lucide-react";

function MonitoringContent() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const searchParams = useSearchParams();

  // Navigation tab state
  const [activeTab, setActiveTab] = useState<"fleet" | "gateways" | "sensors" | "sa_states" | "timeline">("fleet");

  // Registration modal states
  const [isRegisterGwOpen, setIsRegisterGwOpen] = useState(false);
  const [isRegisterSensorOpen, setIsRegisterSensorOpen] = useState(false);
  const [issuedTokenModal, setIssuedTokenModal] = useState<RegisterSensorResponseDTO | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [showRawToken, setShowRawToken] = useState(false);
  const [showHistorical, setShowHistorical] = useState(false);

  // Inspector drawers
  const [selectedEvent, setSelectedEvent] = useState<MonitoringEventItemDTO | null>(null);
  const [selectedGatewayDetails, setSelectedGatewayDetails] = useState<GatewayResponseDTO | null>(null);

  // Gateway form state
  const [gwName, setGwName] = useState("");
  const [gwIp, setGwIp] = useState("");
  const [gwScope, setGwScope] = useState("");
  const [gwOperator, setGwOperator] = useState("operator-admin");
  const [gwAuthRef, setGwAuthRef] = useState("CHG-2026-MON-01");

  // Sensor form state
  const [sensorName, setSensorName] = useState("");
  const [sensorType, setSensorType] = useState<"GATEWAY_COLLECTOR" | "CAPTURE_SENSOR">("GATEWAY_COLLECTOR");
  const [sensorGwId, setSensorGwId] = useState("");
  const [sensorScope, setSensorScope] = useState("");
  const [sensorFreshness, setSensorFreshness] = useState(60);

  // Filter state for timeline & SAs
  const [filterEventKind, setFilterEventKind] = useState<string>("");
  const [filterGatewayId, setFilterGatewayId] = useState<string>("");
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [liveEventCount, setLiveEventCount] = useState<number>(0);

  // Initialize from URL search parameters if provided
  useEffect(() => {
    const tabParam = searchParams.get("tab");
    if (tabParam && ["fleet", "gateways", "sensors", "sa_states", "timeline"].includes(tabParam)) {
      setActiveTab(tabParam as any);
    }
    const gwParam = searchParams.get("gateway");
    if (gwParam) {
      setFilterGatewayId(gwParam);
    }
  }, [searchParams]);

  // ---------------------------------------------------------------------------
  // Queries
  // ---------------------------------------------------------------------------

  const { data: gateways = [], isLoading: isLoadingGateways, refetch: refetchGateways } = useQuery({
    queryKey: ["monitoring", "gateways"],
    queryFn: () => api.monitoring.listGateways(),
    refetchInterval: 10000,
  });

  const { data: sensors = [], isLoading: isLoadingSensors, refetch: refetchSensors } = useQuery({
    queryKey: ["monitoring", "sensors"],
    queryFn: () => api.monitoring.listSensors(),
    refetchInterval: 10000,
  });

  const { data: healthList = [], isLoading: isLoadingHealth, refetch: refetchHealth } = useQuery({
    queryKey: ["monitoring", "health"],
    queryFn: () => api.monitoring.getHealth(),
    refetchInterval: 5000,
  });

  const { data: saStates = [], isLoading: isLoadingSAs, refetch: refetchSAs } = useQuery({
    queryKey: ["monitoring", "sa-states", filterGatewayId],
    queryFn: () => api.monitoring.getSAStates(filterGatewayId || undefined),
    refetchInterval: 5000,
  });

  const { data: timelineData, isLoading: isLoadingTimeline, refetch: refetchTimeline } = useQuery({
    queryKey: ["monitoring", "timeline", filterEventKind, filterGatewayId],
    queryFn: () => api.monitoring.getTimeline({
      gateway_id: filterGatewayId || undefined,
      event_kind: filterEventKind || undefined,
      limit: 100,
    }),
    refetchInterval: 10000,
  });

  // ---------------------------------------------------------------------------
  // WebSocket live telemetry subscription
  // ---------------------------------------------------------------------------

  useEffect(() => {
    let ws: WebSocket | null = null;
    let pingInterval: any = null;

    try {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      let host = window.location.hostname + ":8002";
      if (process.env.NEXT_PUBLIC_API_URL) {
        try {
          host = new URL(process.env.NEXT_PUBLIC_API_URL).host;
        } catch {}
      }
      const wsUrl = process.env.NEXT_PUBLIC_WS_URL
        ? `${process.env.NEXT_PUBLIC_WS_URL.replace(/\/ws\/?$/, "").replace(/\/$/, "")}/monitoring/ws`
        : `${protocol}//${host}/api/v1/monitoring/ws`;
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        setWsConnected(true);
        pingInterval = setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send("PING");
          }
        }, 15000);
      };

      ws.onmessage = (event) => {
        if (event.data === "PONG") return;
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === "MONITORING_EVENT") {
            setLiveEventCount((prev) => prev + 1);
            // Invalidate queries so tables refresh seamlessly
            queryClient.invalidateQueries({ queryKey: ["monitoring", "health"] });
            queryClient.invalidateQueries({ queryKey: ["monitoring", "sa-states"] });
            queryClient.invalidateQueries({ queryKey: ["monitoring", "timeline"] });
          }
        } catch {
          // ignore non-json
        }
      };

      ws.onclose = () => {
        setWsConnected(false);
        if (pingInterval) clearInterval(pingInterval);
      };

      ws.onerror = () => {
        setWsConnected(false);
      };
    } catch {
      setWsConnected(false);
    }

    return () => {
      if (pingInterval) clearInterval(pingInterval);
      if (ws) {
        ws.onopen = null;
        ws.onmessage = null;
        ws.onerror = null;
        ws.onclose = null;
        if (ws.readyState === WebSocket.OPEN) {
          ws.close();
        } else if (ws.readyState === WebSocket.CONNECTING) {
          ws.onopen = () => {
            try { ws?.close(); } catch {}
          };
        }
      }
    };
  }, [queryClient]);

  // ---------------------------------------------------------------------------
  // Mutations
  // ---------------------------------------------------------------------------

  const registerGatewayMutation = useMutation({
    mutationFn: (data: any) => api.monitoring.registerGateway(data),
    onSuccess: () => {
      refetchGateways();
      setIsRegisterGwOpen(false);
      setGwName("");
      setGwIp("");
      setGwScope("");
    },
  });

  const registerSensorMutation = useMutation({
    mutationFn: (data: any) => api.monitoring.registerSensor(data),
    onSuccess: (res: RegisterSensorResponseDTO) => {
      refetchSensors();
      refetchHealth();
      setIsRegisterSensorOpen(false);
      setIssuedTokenModal(res);
      setSensorName("");
      setSensorScope("");
    },
  });

  const revokeSensorMutation = useMutation({
    mutationFn: (sensorId: string) => api.monitoring.revokeSensor(sensorId),
    onSuccess: () => {
      refetchSensors();
      refetchHealth();
    },
  });

  const [pulseMessage, setPulseMessage] = useState<string | null>(null);

  const pulseMutation = useMutation({
    mutationFn: () => api.monitoring.triggerPulse(),
    onSuccess: () => {
      refetchGateways();
      refetchSensors();
      refetchHealth();
      refetchSAs();
      refetchTimeline();
      setPulseMessage("Synthetic test telemetry pulse emitted (Grade: SYNTHETIC). WebSocket broadcast dispatched.");
      setTimeout(() => setPulseMessage(null), 4000);
    },
    onError: (err: any) => {
      setPulseMessage(`Failed to send pulse: ${err?.message || "Error"}`);
      setTimeout(() => setPulseMessage(null), 4000);
    },
  });

  // Calculate fleet stats
  const totalGateways = (gateways || []).length;
  const totalSensors = (sensors || []).length;
  const activeSensorsCount = (sensors || []).filter((s) => s.status === "ACTIVE").length;
  const revokedSensorsCount = (sensors || []).filter((s) => s.status === "REVOKED" || s.status === "DISABLED").length;
  const healthyCount = (healthList || []).filter((h) => h.current_health === "HEALTHY").length;
  const degradedCount = (healthList || []).filter((h) => h.current_health === "DEGRADED").length;
  const staleCount = (healthList || []).filter((h) => h.current_health === "STALE").length;
  const unknownCount = (healthList || []).filter((h) => h.current_health === "UNKNOWN").length;
  const activeSAsCount = (saStates || []).filter((sa) => sa.state === "ESTABLISHED" && !sa.is_stale).length;
  const staleSAsCount = (saStates || []).filter((sa) => sa.is_stale).length;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-[#FF3D00]/10 flex items-center justify-center text-[#FF3D00]">
              <Radio className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="text-[10px] font-mono text-neutral-400 uppercase tracking-widest">
                LIVE MONITORING
              </div>
              <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase">
                {activeTab === "timeline" ? "Live Monitoring → Event Timeline" :
                 activeTab === "gateways" ? "Live Monitoring → Gateway Registry" :
                 activeTab === "sensors" ? "Live Monitoring → Sensor Fleet" :
                 activeTab === "sa_states" ? "Live Monitoring → Projected SAs" :
                 "Live Monitoring → Fleet Health & Freshness"}
              </h1>
            </div>
            <span className="text-xs px-2 py-0.5 font-mono uppercase bg-neutral-200 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300">
              CONTINUOUS TELEMETRY
            </span>
          </div>
          <p className="text-sm text-neutral-500 dark:text-neutral-400 mt-1">
            Real-time IKE/IPsec state projections, sensor fleet health, and immutable audit telemetry.
          </p>
        </div>

        {/* Live WebSocket Status & Actions */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113] text-xs font-mono">
            <span
              className={`w-2 h-2 rounded-full ${
                wsConnected
                  ? healthyCount > 0
                    ? "bg-emerald-500 animate-ping"
                    : "bg-amber-500"
                  : "bg-neutral-400"
              }`}
            />
            <span
              className={
                wsConnected
                  ? healthyCount > 0
                    ? "text-emerald-600 dark:text-emerald-400 font-semibold"
                    : "text-amber-600 dark:text-amber-400 font-semibold"
                  : "text-neutral-500"
              }
            >
              {wsConnected
                ? healthyCount > 0
                  ? `LIVE STREAMING (${liveEventCount})`
                  : `WS CONNECTED · EDGE TELEMETRY INACTIVE (${liveEventCount})`
                : "POLLING LOOP (10s)"}
            </span>
          </div>

          {/* Actions: Send Synthetic Test Pulse & Manual Refresh */}
          <button
            onClick={() => pulseMutation.mutate()}
            disabled={pulseMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono font-bold bg-amber-600/90 hover:bg-amber-600 text-white rounded transition-colors shadow-xs disabled:opacity-50"
            title="Run isolated synthetic demo events (Quarantined: does not update operational health or SA state)"
          >
            <Zap className={`w-3.5 h-3.5 ${pulseMutation.isPending ? "animate-spin" : ""}`} />
            <span>{pulseMutation.isPending ? "EMITTING..." : "RUN ISOLATED SYNTHETIC DEMO (QUARANTINED)"}</span>
          </button>

          <button
            onClick={() => {
              refetchGateways();
              refetchSensors();
              refetchHealth();
              refetchSAs();
              refetchTimeline();
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            REFRESH
          </button>
        </div>
      </div>

      {/* Phase 8 Architecture Disclosure: Live Telemetry vs Live Packet Capture */}
      <div className="p-3.5 bg-white dark:bg-[#111113] border border-neutral-300 dark:border-neutral-800 text-xs font-mono space-y-2">
        <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-2">
          <div className="flex items-center space-x-2 text-neutral-900 dark:text-white font-bold">
            <ShieldCheck className="w-4 h-4 text-[#FF3D00]" />
            <span>CONTINUOUS TELEMETRY VS. LIVE PACKET CAPTURE ARCHITECTURE</span>
          </div>
          <span className="text-[10px] px-2 py-0.5 bg-neutral-100 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-400 font-bold uppercase">
            RFC 7296 / NTRO AUDIT DISCLOSURE
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-[11px] text-neutral-600 dark:text-neutral-400 leading-relaxed pt-0.5">
          <div>
            <span className="font-bold text-neutral-900 dark:text-white block mb-0.5">Live Monitoring (Stream Active):</span>
            Ingests authenticated heartbeat telemetry, health metrics, and projected IPsec Security Association states from distributed gateway collectors over WebSocket/REST APIs. Retains verifiable historical state transitions without artificial synthetic data.
          </div>
          <div>
            <span className="font-bold text-neutral-900 dark:text-white block mb-0.5">Live Packet Capture (Host Requirements):</span>
            Direct raw packet capture requires the privileged Linux Capture Daemon running with kernel <code className="bg-neutral-100 dark:bg-neutral-800 px-1 py-0.5 font-bold">CAP_NET_ADMIN</code> / eBPF / strongSwan XFRM access. Windows development hosts operate in offline PCAP forensics mode and receive remote sensor telemetry.
          </div>
        </div>
      </div>

      {/* Pulse Feedback Banner */}
      {pulseMessage && (
        <div className="p-3 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-200 text-xs font-mono flex items-center justify-between">
          <div className="flex items-center space-x-2 font-bold">
            <Check className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
            <span>{pulseMessage}</span>
          </div>
          <button onClick={() => setPulseMessage(null)} className="text-neutral-400 hover:text-neutral-600">×</button>
        </div>
      )}

      {/* Telemetry Freshness & Setup Warning Banner */}
      {healthyCount === 0 && (
        <div className="p-4 bg-amber-50 dark:bg-amber-950/30 border-l-4 border-amber-500 text-amber-900 dark:text-amber-200 text-xs font-mono space-y-2">
          <div className="flex items-center space-x-2 font-bold uppercase tracking-wider text-amber-800 dark:text-amber-300">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Telemetry Inactive: No Gateway Currently Connected</span>
          </div>
          <p className="text-[11px] leading-relaxed">
            {staleCount > 0
              ? `${staleCount} registered sensor(s) have exceeded the 60-second freshness heartbeat threshold. Feeds are currently dormant.`
              : "No telemetry sensors are currently reporting to the TunnelTrace API. The browser WebSocket is connected, waiting for gateway heartbeats."}
            Projected SA records shown below represent retained historical states under the non-deletion invariant; they do not indicate currently established live tunnels.
          </p>
          <div className="p-3 bg-neutral-950 text-neutral-200 rounded border border-neutral-800 space-y-2">
            <div className="text-[10px] text-neutral-400 uppercase font-semibold">Deploy Authorized Gateway Collector (Linux / strongSwan):</div>
            <pre className="text-emerald-400 text-[11px] font-mono block select-all overflow-x-auto whitespace-pre p-2 bg-black/60 rounded">
export SENSOR_TOKEN=&quot;&lt;YOUR_ISSUED_SENSOR_TOKEN&gt;&quot;
python scripts/gateway_collector.py \
  --api-url &quot;http://&lt;TUNNELTRACE_HOST&gt;:8002/api/v1&quot; \
  --gateway &quot;Perimeter-Gateway&quot; \
  --gateway-id &quot;&lt;GATEWAY_UUID&gt;&quot; \
  --sensor-id &quot;&lt;SENSOR_UUID&gt;&quot; \
  --token &quot;$SENSOR_TOKEN&quot; \
  --scope &quot;10.0.0.0/8&quot; \
  --interface eth0
            </pre>
          </div>
          <div className="pt-0.5 flex flex-wrap items-center gap-3 text-[11px]">
            <span className="font-bold text-amber-950 dark:text-amber-100">Alternative:</span>
            <button
              onClick={() => {
                setActiveTab("sensors");
                router.replace("/monitoring?tab=sensors", { scroll: false });
              }}
              className="underline font-bold text-amber-800 dark:text-amber-300 hover:text-amber-950"
            >
              Register a new sensor token in Sensor Fleet →
            </button>
          </div>
        </div>
      )}

      {/* Top Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <Card className="p-3 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113]">
          <div className="text-[10px] font-mono text-neutral-500 uppercase">Monitored Gateways</div>
          <div className="text-xl font-bold font-mono mt-1 text-neutral-900 dark:text-neutral-100">
            {totalGateways}
          </div>
          <div className="text-[10px] text-neutral-400 mt-0.5">Bound boundaries</div>
        </Card>

        <Card className="p-3 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113]">
          <div className="text-[10px] font-mono text-neutral-500 uppercase">Sensors Active</div>
          <div className="text-xl font-bold font-mono mt-1 text-neutral-900 dark:text-neutral-100">
            {activeSensorsCount}
          </div>
          <div className="text-[10px] text-neutral-400 mt-0.5">
            {revokedSensorsCount > 0 ? `${revokedSensorsCount} revoked/disabled` : `${totalSensors} total collectors`}
          </div>
        </Card>

        <Card className="p-3 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113]">
          <div className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 uppercase">Healthy Sensors</div>
          <div className="text-xl font-bold font-mono mt-1 text-emerald-600 dark:text-emerald-400">
            {healthyCount}
          </div>
          <div className="text-[10px] text-neutral-400 mt-0.5">0 drops / 0 gaps</div>
        </Card>

        <Card className="p-3 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113]">
          <div className="text-[10px] font-mono text-amber-500 uppercase">Stale / Degraded</div>
          <div className="text-xl font-bold font-mono mt-1 text-amber-500">
            {staleCount + degradedCount}
          </div>
          <div className="text-[10px] text-neutral-400 mt-0.5">
            {staleCount} stale, {degradedCount} degraded
          </div>
        </Card>

        <Card className="p-3 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113]">
          <div className="text-[10px] font-mono text-blue-500 uppercase">Established SAs</div>
          <div className="text-xl font-bold font-mono mt-1 text-blue-500">
            {activeSAsCount}
          </div>
          <div className="text-[10px] text-neutral-400 mt-0.5">
            {activeSAsCount > 0 ? "Live IPsec tunnels" : "0 active tunnels observed"}
          </div>
        </Card>

        <Card className="p-3 border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113]">
          <div className="text-[10px] font-mono text-neutral-400 uppercase">Historical SAs (Retained)</div>
          <div className="text-xl font-bold font-mono mt-1 text-neutral-400">
            {staleSAsCount}
          </div>
          <div className="text-[10px] text-neutral-400 mt-0.5">Past observed states</div>
        </Card>
      </div>

      {/* Tabs Navigation */}
      <div className="flex border-b border-neutral-300 dark:border-neutral-800 gap-1">
        {[
          { id: "fleet", label: "Fleet Health & Freshness", icon: Activity },
          { id: "sa_states", label: `Projected SAs (${saStates.length})`, icon: GitBranch },
          { id: "timeline", label: "Event Timeline", icon: Layers },
          { id: "gateways", label: `Gateways (${gateways.length})`, icon: Server },
          { id: "sensors", label: `Sensors (${sensors.length})`, icon: Cpu },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => {
                setActiveTab(tab.id as any);
                router.replace(`/monitoring?tab=${tab.id}`, { scroll: false });
              }}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono border-b-2 font-medium transition-all ${
                isActive
                  ? "border-[#FF3D00] text-[#FF3D00] bg-[#FF3D00]/5"
                  : "border-transparent text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-neutral-200"
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: FLEET HEALTH & FRESHNESS                                          */}
      {/* ========================================================================= */}
      {activeTab === "fleet" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold font-mono text-neutral-800 dark:text-neutral-200 uppercase">
              Sensor Fleet Telemetry Freshness Matrix
            </h2>
            <button
              onClick={() => setIsRegisterSensorOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono bg-[#FF3D00] hover:bg-[#e03600] text-white rounded font-medium transition-colors"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              REGISTER SENSOR
            </button>
          </div>

          {!healthList.some((h) => h.current_health === "HEALTHY") && !showHistorical ? (
            <Card className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113] p-8 text-center space-y-4 font-mono">
              <div className="w-12 h-12 mx-auto rounded-full bg-neutral-100 dark:bg-neutral-800 flex items-center justify-center text-neutral-400">
                <Radio className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-neutral-900 dark:text-white uppercase">
                  No Gateway Currently Connected
                </h3>
                <p className="text-xs text-neutral-500 mt-1 max-w-lg mx-auto">
                  Continuous monitoring requires an active strongSwan gateway streaming live telemetry over WebSockets. No active probes are currently transmitting fresh observations.
                </p>
              </div>
              <div className="max-w-xl mx-auto p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-left text-xs space-y-2">
                <div className="text-[11px] font-bold text-neutral-700 dark:text-neutral-300 uppercase">
                  Deploy Collector on Authorized Linux Gateway:
                </div>
                <div className="p-2.5 bg-black/90 text-emerald-400 rounded text-[11px] font-mono select-all overflow-x-auto whitespace-pre">
{`export SENSOR_TOKEN="<YOUR_ISSUED_SENSOR_TOKEN>"
python scripts/gateway_collector.py \\
  --api-url "http://<TUNNELTRACE_HOST>:8002/api/v1" \\
  --gateway "Perimeter-Gateway" \\
  --gateway-id "<GATEWAY_UUID>" \\
  --sensor-id "<SENSOR_UUID>" \\
  --token "$SENSOR_TOKEN" \\
  --scope "10.0.0.0/8" \\
  --interface eth0`}
                </div>
                <div className="text-[10px] text-neutral-500 font-mono">
                  Prerequisites: Linux kernel, root / CAP_NET_ADMIN, strongSwan (swanctl or ip xfrm), and reachable backend API.
                </div>
              </div>
              {healthList.length > 0 && (
                <div className="pt-2">
                  <button
                    onClick={() => setShowHistorical(true)}
                    className="text-xs text-[#FF3D00] hover:underline font-mono inline-flex items-center space-x-1"
                  >
                    <span>View historical retained observations ({healthList.length})</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </Card>
          ) : (
            <div className="space-y-3">
              {!healthList.some((h) => h.current_health === "HEALTHY") && (
                <div className="flex items-center justify-between p-2.5 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 text-xs font-mono text-amber-800 dark:text-amber-300">
                  <div className="flex items-center space-x-2">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>Viewing historical retained observations (no gateway actively streaming).</span>
                  </div>
                  <button
                    onClick={() => setShowHistorical(false)}
                    className="underline text-[11px] hover:text-amber-900 font-bold"
                  >
                    Hide Historical
                  </button>
                </div>
              )}
              <Card className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113] overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="font-mono text-xs">SENSOR</TableHead>
                  <TableHead className="font-mono text-xs">TYPE</TableHead>
                  <TableHead className="font-mono text-xs">GATEWAY BOUNDARY</TableHead>
                  <TableHead className="font-mono text-xs">HEALTH STATE</TableHead>
                  <TableHead className="font-mono text-xs">FRESHNESS & LATENCY</TableHead>
                  <TableHead className="font-mono text-xs">DROPS / GAPS</TableHead>
                  <TableHead className="font-mono text-xs">LAST OBSERVATION</TableHead>
                  <TableHead className="font-mono text-xs text-right">ACTIONS</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {healthList.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-8 text-neutral-400 font-mono text-xs">
                      No sensors registered yet. Click &quot;Register Sensor&quot; to attach telemetry collectors.
                    </TableCell>
                  </TableRow>
                ) : (
                  healthList.map((h) => {
                    const isHealthy = h.current_health === "HEALTHY";
                    const isDegraded = h.current_health === "DEGRADED";
                    const isStale = h.current_health === "STALE";
                    const isDisabled = h.current_health === "DISABLED" || h.current_health === "UNAVAILABLE";

                    let badgeColor = "bg-neutral-200 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300";
                    if (isHealthy) badgeColor = "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20";
                    else if (isDegraded) badgeColor = "bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20";
                    else if (isStale) badgeColor = "bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/20";
                    else if (isDisabled) badgeColor = "bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20";

                    return (
                      <TableRow key={h.sensor_id}>
                        <TableCell className="font-mono text-xs font-semibold">
                          {h.sensor_name}
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-neutral-500">
                          {h.sensor_type}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          <div>{h.gateway_name}</div>
                          <div className="text-[10px] text-neutral-400">{h.authorized_scope}</div>
                        </TableCell>
                        <TableCell>
                          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-mono uppercase font-semibold rounded ${badgeColor}`}>
                            <span className="w-1.5 h-1.5 rounded-full bg-current" />
                            {h.current_health}
                          </span>
                          <div className="text-[10px] text-neutral-500 dark:text-neutral-400 mt-1 max-w-xs truncate">
                            {h.health_reason}
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          <div>Window: {h.freshness_window_seconds}s</div>
                          <div className="text-[10px] text-neutral-400">
                            Skew: {h.clock_skew_seconds > 0 ? `+${h.clock_skew_seconds.toFixed(2)}s` : `${h.clock_skew_seconds.toFixed(2)}s`}
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          <div className={h.total_drops_reported > 0 ? "text-amber-500 font-semibold" : "text-neutral-500"}>
                            Drops: {h.total_drops_reported}
                          </div>
                          <div className={h.sequence_gaps_count > 0 ? "text-amber-500 font-semibold" : "text-neutral-500"}>
                            Gaps: {h.sequence_gaps_count}
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-neutral-500">
                          {h.last_received_at ? new Date(h.last_received_at).toLocaleTimeString() : "Never"}
                        </TableCell>
                        <TableCell className="text-right">
                          <button
                            onClick={() => revokeSensorMutation.mutate(h.sensor_id)}
                            disabled={h.current_health === "DISABLED"}
                            className="px-2 py-1 text-[11px] font-mono text-red-600 hover:bg-red-500/10 rounded disabled:opacity-30"
                          >
                            REVOKE
                          </button>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </Card>
        </div>
      )}
    </div>
  )}

      {/* ========================================================================= */}
      {/* TAB 2: PROJECTED SECURITY ASSOCIATIONS (NON-DELETION INVARIANT)            */}
      {/* ========================================================================= */}
      {activeTab === "sa_states" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold font-mono text-neutral-800 dark:text-neutral-200 uppercase">
                Active & Retained Security Association Projections
              </h2>
              <p className="text-xs text-neutral-500 mt-0.5">
                Rebuildable projections of active IKE and Child SAs. Under sensor staleness, SAs are retained with amber warning, NEVER deleted.
              </p>
            </div>
          </div>

          <Card className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113] overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="font-mono text-xs">GATEWAY / TYPE</TableHead>
                  <TableHead className="font-mono text-xs">INITIATOR SPI / CHILD IN</TableHead>
                  <TableHead className="font-mono text-xs">RESPONDER SPI / CHILD OUT</TableHead>
                  <TableHead className="font-mono text-xs">ENDPOINTS</TableHead>
                  <TableHead className="font-mono text-xs">CIPHER SUITE</TableHead>
                  <TableHead className="font-mono text-xs">LIFECYCLE STATE</TableHead>
                  <TableHead className="font-mono text-xs">LAST EVENT AT</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {saStates.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-neutral-400 font-mono text-xs">
                      No Security Associations currently projected. Telemetry from IKE daemons will populate active tunnels here.
                    </TableCell>
                  </TableRow>
                ) : (
                  saStates.map((sa) => {
                    const isStale = sa.is_stale;
                    const isEst = sa.state === "ESTABLISHED";
                    const isRekey = sa.state === "REKEYED";
                    const isDeleted = sa.state === "DELETED";

                    let stateColor = "bg-neutral-200 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300";
                    if (isStale) stateColor = "bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/30";
                    else if (isEst) stateColor = "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20";
                    else if (isRekey) stateColor = "bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20";
                    else if (isDeleted) stateColor = "bg-neutral-500/10 text-neutral-500 border border-neutral-500/20";

                    return (
                      <TableRow key={sa.id} className={isStale ? "bg-orange-500/5" : ""}>
                        <TableCell className="font-mono text-xs">
                          <div className="font-semibold">{sa.gateway_name}</div>
                          <div className="text-[10px] text-neutral-400 uppercase font-mono">{sa.sa_type}</div>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          <CopyableValue value={sa.initiator_spi} label={sa.initiator_spi} />
                          {sa.child_spi_in && (
                            <div className="text-[10px] text-neutral-400 mt-0.5">
                              In: {sa.child_spi_in}
                            </div>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {sa.responder_spi ? (
                            <CopyableValue value={sa.responder_spi} label={sa.responder_spi} />
                          ) : (
                            <span className="text-neutral-400">—</span>
                          )}
                          {sa.child_spi_out && (
                            <div className="text-[10px] text-neutral-400 mt-0.5">
                              Out: {sa.child_spi_out}
                            </div>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          <div>{sa.local_endpoint || "0.0.0.0"}</div>
                          <div className="text-[10px] text-neutral-400">↔ {sa.remote_endpoint || "0.0.0.0"}</div>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-neutral-600 dark:text-neutral-300">
                          {sa.cipher_suite || "Unknown"}
                        </TableCell>
                        <TableCell>
                          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-mono uppercase font-semibold rounded ${stateColor}`}>
                            <span className="w-1.5 h-1.5 rounded-full bg-current" />
                            {isStale ? "STALE (RETAINED)" : sa.state}
                          </span>
                          {isStale && (
                            <div className="text-[10px] text-orange-600 dark:text-orange-400 mt-1 max-w-xs truncate">
                              {sa.staleness_reason || "Heartbeat timeout"}
                            </div>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-neutral-500">
                          {new Date(sa.last_event_at).toLocaleTimeString()}
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </Card>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: IMMUTABLE AUDIT TIMELINE                                          */}
      {/* ========================================================================= */}
      {activeTab === "timeline" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-bold font-mono text-neutral-800 dark:text-neutral-200 uppercase">
                Immutable Telemetry Event Stream
              </h2>
              <p className="text-xs text-neutral-500 mt-0.5">
                Append-only evidence log ingested from authorized telemetry sensors.
              </p>
            </div>

            {/* Filter by Event Kind and Gateway */}
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1.5">
                <label className="text-xs font-mono text-neutral-500">GATEWAY:</label>
                <select
                  value={filterGatewayId}
                  onChange={(e) => setFilterGatewayId(e.target.value)}
                  className="bg-white dark:bg-[#111113] border border-neutral-300 dark:border-neutral-700 text-xs font-mono px-2 py-1 rounded"
                >
                  <option value="">ALL GATEWAYS</option>
                  {gateways.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name} ({g.gateway_ip})
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex items-center gap-1.5">
                <label className="text-xs font-mono text-neutral-500">KIND:</label>
                <select
                  value={filterEventKind}
                  onChange={(e) => setFilterEventKind(e.target.value)}
                  className="bg-white dark:bg-[#111113] border border-neutral-300 dark:border-neutral-700 text-xs font-mono px-2 py-1 rounded"
                >
                  <option value="">ALL EVENTS</option>
                  <option value="GATEWAY_IKE_SA_ESTABLISHED">GATEWAY_IKE_SA_ESTABLISHED</option>
                  <option value="GATEWAY_IKE_SA_FAILED">GATEWAY_IKE_SA_FAILED</option>
                  <option value="GATEWAY_CHILD_SA_ESTABLISHED">GATEWAY_CHILD_SA_ESTABLISHED</option>
                  <option value="GATEWAY_CHILD_SA_REKEYED">GATEWAY_CHILD_SA_REKEYED</option>
                  <option value="GATEWAY_CHILD_SA_DELETED">GATEWAY_CHILD_SA_DELETED</option>
                  <option value="GATEWAY_HEARTBEAT">GATEWAY_HEARTBEAT</option>
                  <option value="CAPTURE_DROPS_RECORDED">CAPTURE_DROPS_RECORDED</option>
                  <option value="CAPTURE_FAILED">CAPTURE_FAILED</option>
                </select>
              </div>

              {(filterGatewayId || filterEventKind) && (
                <button
                  onClick={() => {
                    setFilterGatewayId("");
                    setFilterEventKind("");
                  }}
                  className="text-[11px] font-mono px-2 py-1 border border-neutral-300 dark:border-neutral-700 text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
                >
                  RESET FILTERS
                </button>
              )}
            </div>
          </div>

          <Card className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113] overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="font-mono text-xs">SOURCE TIME (UTC)</TableHead>
                  <TableHead className="font-mono text-xs">EVENT KIND</TableHead>
                  <TableHead className="font-mono text-xs">SCOPE</TableHead>
                  <TableHead className="font-mono text-xs">INITIATOR SPI / INTERFACE</TableHead>
                  <TableHead className="font-mono text-xs">PACKETS / DROPS</TableHead>
                  <TableHead className="font-mono text-xs">RAW REASON / DETAIL</TableHead>
                  <TableHead className="font-mono text-xs text-right">INSPECT</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {!timelineData || timelineData.items.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-10 text-neutral-400 font-mono text-xs space-y-1">
                      <div className="font-semibold text-neutral-700 dark:text-neutral-300">
                        No events recorded matching current filters in this interval.
                      </div>
                      <div className="text-[11px] text-neutral-500">
                        Sensors remain active and listening. This reflects an absence of state transitions in the query window, not a telemetry failure.
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  timelineData.items.map((item) => {
                    const isFailure = item.event_kind.includes("FAILED");
                    const isDrop = item.event_kind.includes("DROPS");
                    return (
                      <TableRow key={item.id} className={isFailure ? "bg-red-500/5" : ""}>
                        <TableCell className="font-mono text-[11px] text-neutral-500">
                          {new Date(item.source_timestamp).toISOString().replace("T", " ").substring(0, 19)}
                        </TableCell>
                        <TableCell className="font-mono text-xs font-semibold">
                          <span
                            className={
                              isFailure
                                ? "text-red-500"
                                : isDrop
                                ? "text-amber-500"
                                : "text-neutral-800 dark:text-neutral-200"
                            }
                          >
                            {item.event_kind}
                          </span>
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-neutral-400">
                          {item.authorized_scope}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {item.initiator_spi ? (
                            <CopyableValue value={item.initiator_spi} label={item.initiator_spi} />
                          ) : (
                            item.interface_name || "—"
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {item.packet_count !== null && item.packet_count !== undefined ? (
                            <div>Pkts: {item.packet_count}</div>
                          ) : null}
                          {item.drop_count !== null && item.drop_count !== undefined && item.drop_count > 0 ? (
                            <div className="text-amber-500 font-semibold">Drops: {item.drop_count}</div>
                          ) : null}
                          {item.packet_count === null && item.drop_count === null && "—"}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-neutral-600 dark:text-neutral-400 max-w-xs truncate">
                          {item.failure_reason || item.raw_source_status || item.cipher_suite || "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          <button
                            onClick={() => setSelectedEvent(item)}
                            className="p-1 hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </Card>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: AUTHORIZED GATEWAYS                                                */}
      {/* ========================================================================= */}
      {activeTab === "gateways" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold font-mono text-neutral-800 dark:text-neutral-200 uppercase">
                Authorized VPN Gateway Boundaries
              </h2>
              <p className="text-xs text-neutral-500 mt-0.5">
                Approved network boundaries with operator attestation and authorization references.
              </p>
            </div>
            <button
              onClick={() => setIsRegisterGwOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono bg-[#FF3D00] hover:bg-[#e03600] text-white rounded font-medium transition-colors"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              REGISTER GATEWAY
            </button>
          </div>

          <Card className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113] overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="font-mono text-xs">GATEWAY NAME</TableHead>
                  <TableHead className="font-mono text-xs">PRIMARY IP</TableHead>
                  <TableHead className="font-mono text-xs">AUTHORIZED SCOPE</TableHead>
                  <TableHead className="font-mono text-xs">OPERATOR</TableHead>
                  <TableHead className="font-mono text-xs">AUTHORIZATION REF</TableHead>
                  <TableHead className="font-mono text-xs">STATUS</TableHead>
                  <TableHead className="font-mono text-xs">REGISTERED AT</TableHead>
                  <TableHead className="font-mono text-xs text-right">ACTIONS</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {gateways.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-8 text-neutral-400 font-mono text-xs">
                      No authorized gateways configured. Click &quot;Register Gateway&quot; to authorize an IPsec boundary.
                    </TableCell>
                  </TableRow>
                ) : (
                  gateways.map((gw) => (
                    <TableRow
                      key={gw.id}
                      className="cursor-pointer hover:bg-neutral-50 dark:hover:bg-neutral-900/50"
                      onClick={() => setSelectedGatewayDetails(gw)}
                    >
                      <TableCell className="font-mono text-xs font-semibold">
                        <div className="flex items-center space-x-1.5">
                          <Server className="w-3.5 h-3.5 text-[#FF3D00]" />
                          <span>{gw.name}</span>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        <CopyableValue value={gw.gateway_ip} label={gw.gateway_ip} />
                      </TableCell>
                      <TableCell className="font-mono text-xs text-neutral-600 dark:text-neutral-400">
                        {gw.authorized_scope}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-neutral-500">
                        {gw.operator_id}
                      </TableCell>
                      <TableCell className="font-mono text-xs font-mono text-neutral-500">
                        {gw.authorization_reference}
                      </TableCell>
                      <TableCell>
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase font-semibold rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                          {gw.status}
                        </span>
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-neutral-500">
                        {new Date(gw.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedGatewayDetails(gw);
                          }}
                          className="inline-flex items-center space-x-1 px-2 py-1 text-[11px] font-mono border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-800 dark:text-neutral-200"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>INSPECT</span>
                        </button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </Card>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 5: SENSOR FLEET REGISTRY                                              */}
      {/* ========================================================================= */}
      {activeTab === "sensors" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold font-mono text-neutral-800 dark:text-neutral-200 uppercase">
                Registered Telemetry Sensors & Collectors
              </h2>
              <p className="text-xs text-neutral-500 mt-0.5">
                Sensor authentication credentials and bound scopes. Tokens are hashed with SHA-256 upon issuance.
              </p>
            </div>
            <button
              onClick={() => setIsRegisterSensorOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono bg-[#FF3D00] hover:bg-[#e03600] text-white rounded font-medium transition-colors"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              REGISTER SENSOR
            </button>
          </div>

          <Card className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113] overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="font-mono text-xs">SENSOR NAME</TableHead>
                  <TableHead className="font-mono text-xs">TYPE</TableHead>
                  <TableHead className="font-mono text-xs">TOKEN PREFIX</TableHead>
                  <TableHead className="font-mono text-xs">BOUND SCOPE</TableHead>
                  <TableHead className="font-mono text-xs">FRESHNESS WINDOW</TableHead>
                  <TableHead className="font-mono text-xs">STATUS</TableHead>
                  <TableHead className="font-mono text-xs text-right">ACTION</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sensors.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-neutral-400 font-mono text-xs">
                      No sensors registered yet. Click &quot;Register Sensor&quot; to issue a collector credential.
                    </TableCell>
                  </TableRow>
                ) : (
                  sensors.map((s) => (
                    <TableRow key={s.id}>
                      <TableCell className="font-mono text-xs font-semibold">
                        {s.sensor_name}
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-neutral-500">
                        {s.sensor_type}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-neutral-400">
                        {s.token_prefix}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-neutral-600 dark:text-neutral-400">
                        {s.authorized_scope}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {s.freshness_window_seconds}s
                      </TableCell>
                      <TableCell>
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase font-semibold rounded ${
                            s.status === "ACTIVE"
                              ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20"
                              : "bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20"
                          }`}
                        >
                          {s.status}
                        </span>
                      </TableCell>
                      <TableCell className="text-right">
                        {s.status === "ACTIVE" ? (
                          <button
                            onClick={() => revokeSensorMutation.mutate(s.id)}
                            className="px-2 py-1 text-[11px] font-mono text-red-600 hover:bg-red-500/10 rounded transition-colors"
                          >
                            REVOKE
                          </button>
                        ) : (
                          <span className="text-[11px] font-mono text-neutral-400">REVOKED</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </Card>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL: REGISTER GATEWAY                                                   */}
      {/* ========================================================================= */}
      {isRegisterGwOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-white dark:bg-[#111113] border border-neutral-300 dark:border-neutral-800 rounded-lg max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-3">
              <h3 className="text-sm font-bold font-mono uppercase text-neutral-900 dark:text-white">
                Register Authorized VPN Gateway
              </h3>
              <button
                onClick={() => setIsRegisterGwOpen(false)}
                className="text-neutral-400 hover:text-neutral-600 dark:hover:text-white"
                aria-label="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-neutral-500 mb-1">GATEWAY NAME</label>
                <input
                  type="text"
                  value={gwName}
                  onChange={(e) => setGwName(e.target.value)}
                  placeholder="e.g. DC-Gateway-Primary"
                  className="w-full px-3 py-2 bg-neutral-100 dark:bg-black border border-neutral-300 dark:border-neutral-800 rounded focus:border-[#FF3D00] outline-none"
                />
              </div>

              <div>
                <label className="block text-neutral-500 mb-1">PRIMARY IP ADDRESS</label>
                <input
                  type="text"
                  value={gwIp}
                  onChange={(e) => setGwIp(e.target.value)}
                  placeholder="e.g. 198.51.100.1"
                  className="w-full px-3 py-2 bg-neutral-100 dark:bg-black border border-neutral-300 dark:border-neutral-800 rounded focus:border-[#FF3D00] outline-none"
                />
              </div>

              <div>
                <label className="block text-neutral-500 mb-1">AUTHORIZED CIDR SCOPE</label>
                <input
                  type="text"
                  value={gwScope}
                  onChange={(e) => setGwScope(e.target.value)}
                  placeholder="e.g. 198.51.100.0/24"
                  className="w-full px-3 py-2 bg-neutral-100 dark:bg-black border border-neutral-300 dark:border-neutral-800 rounded focus:border-[#FF3D00] outline-none"
                />
              </div>

              <div>
                <label className="block text-neutral-500 mb-1">AUTHORIZATION REFERENCE</label>
                <input
                  type="text"
                  value={gwAuthRef}
                  onChange={(e) => setGwAuthRef(e.target.value)}
                  placeholder="e.g. CHG-2026-MON-01"
                  className="w-full px-3 py-2 bg-neutral-100 dark:bg-black border border-neutral-300 dark:border-neutral-800 rounded focus:border-[#FF3D00] outline-none"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-neutral-200 dark:border-neutral-800">
              <button
                onClick={() => setIsRegisterGwOpen(false)}
                className="px-4 py-2 text-xs font-mono border border-neutral-300 dark:border-neutral-700 rounded hover:bg-neutral-100 dark:hover:bg-neutral-800"
              >
                CANCEL
              </button>
              <button
                onClick={() =>
                  registerGatewayMutation.mutate({
                    name: gwName,
                    gateway_ip: gwIp,
                    authorized_scope: gwScope,
                    operator_id: gwOperator,
                    authorization_reference: gwAuthRef,
                  })
                }
                disabled={!gwName || !gwIp || !gwScope || registerGatewayMutation.isPending}
                className="px-4 py-2 text-xs font-mono bg-[#FF3D00] text-white rounded font-medium hover:bg-[#e03600] disabled:opacity-50"
              >
                {registerGatewayMutation.isPending ? "REGISTERING..." : "CONFIRM GATEWAY"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL: REGISTER SENSOR                                                    */}
      {/* ========================================================================= */}
      {isRegisterSensorOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-white dark:bg-[#111113] border border-neutral-300 dark:border-neutral-800 rounded-lg max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-3">
              <h3 className="text-sm font-bold font-mono uppercase text-neutral-900 dark:text-white">
                Register Telemetry Sensor
              </h3>
              <button
                onClick={() => setIsRegisterSensorOpen(false)}
                className="text-neutral-400 hover:text-neutral-600 dark:hover:text-white"
                aria-label="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-neutral-500 mb-1">SENSOR NAME</label>
                <input
                  type="text"
                  value={sensorName}
                  onChange={(e) => setSensorName(e.target.value)}
                  placeholder="e.g. collector-dc-swanctl"
                  className="w-full px-3 py-2 bg-neutral-100 dark:bg-black border border-neutral-300 dark:border-neutral-800 rounded focus:border-[#FF3D00] outline-none"
                />
              </div>

              <div>
                <label className="block text-neutral-500 mb-1">TARGET GATEWAY</label>
                <select
                  value={sensorGwId}
                  onChange={(e) => {
                    setSensorGwId(e.target.value);
                    const selected = gateways.find((g) => g.id === e.target.value);
                    if (selected) setSensorScope(selected.authorized_scope);
                  }}
                  className="w-full px-3 py-2 bg-neutral-100 dark:bg-black border border-neutral-300 dark:border-neutral-800 rounded focus:border-[#FF3D00] outline-none"
                >
                  <option value="">SELECT BOUND GATEWAY...</option>
                  {gateways.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name} ({g.gateway_ip})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-neutral-500 mb-1">SENSOR TYPE</label>
                <select
                  value={sensorType}
                  onChange={(e) => setSensorType(e.target.value as any)}
                  className="w-full px-3 py-2 bg-neutral-100 dark:bg-black border border-neutral-300 dark:border-neutral-800 rounded focus:border-[#FF3D00] outline-none"
                >
                  <option value="GATEWAY_COLLECTOR">GATEWAY_COLLECTOR (Daemon IKE/Child SAs)</option>
                  <option value="CAPTURE_SENSOR">CAPTURE_SENSOR (PCAP & Drop Probes)</option>
                </select>
              </div>

              <div>
                <label className="block text-neutral-500 mb-1">BOUND SCOPE</label>
                <input
                  type="text"
                  value={sensorScope}
                  onChange={(e) => setSensorScope(e.target.value)}
                  placeholder="Must match gateway scope exactly"
                  className="w-full px-3 py-2 bg-neutral-100 dark:bg-black border border-neutral-300 dark:border-neutral-800 rounded focus:border-[#FF3D00] outline-none"
                />
              </div>

              <div>
                <label className="block text-neutral-500 mb-1">FRESHNESS WINDOW (SECONDS)</label>
                <input
                  type="number"
                  value={sensorFreshness}
                  onChange={(e) => setSensorFreshness(Number(e.target.value))}
                  min={10}
                  max={86400}
                  className="w-full px-3 py-2 bg-neutral-100 dark:bg-black border border-neutral-300 dark:border-neutral-800 rounded focus:border-[#FF3D00] outline-none"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-neutral-200 dark:border-neutral-800">
              <button
                onClick={() => setIsRegisterSensorOpen(false)}
                className="px-4 py-2 text-xs font-mono border border-neutral-300 dark:border-neutral-700 rounded hover:bg-neutral-100 dark:hover:bg-neutral-800"
              >
                CANCEL
              </button>
              <button
                onClick={() =>
                  registerSensorMutation.mutate({
                    sensor_name: sensorName,
                    sensor_type: sensorType,
                    gateway_id: sensorGwId,
                    authorized_scope: sensorScope,
                    freshness_window_seconds: sensorFreshness,
                  })
                }
                disabled={!sensorName || !sensorGwId || !sensorScope || registerSensorMutation.isPending}
                className="px-4 py-2 text-xs font-mono bg-[#FF3D00] text-white rounded font-medium hover:bg-[#e03600] disabled:opacity-50"
              >
                {registerSensorMutation.isPending ? "REGISTERING..." : "ISSUE SENSOR TOKEN"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL: SENSOR TOKEN ISSUED (DISPLAYED ONCE)                               */}
      {/* ========================================================================= */}
      {issuedTokenModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-white dark:bg-[#111113] border border-amber-500 rounded-lg max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center gap-2 text-amber-500">
              <AlertTriangle className="w-5 h-5" />
              <h3 className="text-sm font-bold font-mono uppercase">
                Sensor Authentication Credential Issued
              </h3>
            </div>

            <p className="text-xs text-neutral-600 dark:text-neutral-300 font-mono">
              Save this authentication token now. For zero-trust security, this token is hashed with SHA-256 and will{" "}
              <strong className="text-amber-500">never be displayed again</strong>.
            </p>

            <div className="p-3 bg-neutral-100 dark:bg-black border border-neutral-300 dark:border-neutral-800 rounded font-mono text-xs break-all flex items-center justify-between gap-3">
              <span className="text-[#FF3D00] font-semibold">
                {showRawToken
                  ? issuedTokenModal.raw_token
                  : issuedTokenModal.raw_token.slice(0, 8) + "••••••••••••••••" + issuedTokenModal.raw_token.slice(-6)}
              </span>
              <div className="flex items-center space-x-1 shrink-0">
                <button
                  type="button"
                  onClick={() => setShowRawToken(!showRawToken)}
                  title={showRawToken ? "Hide token" : "Show token"}
                  className="p-1.5 hover:bg-neutral-200 dark:hover:bg-neutral-800 rounded text-neutral-500 hover:text-neutral-900 dark:hover:text-white transition-colors"
                >
                  {showRawToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(issuedTokenModal.raw_token);
                    setCopiedToken(true);
                    setTimeout(() => setCopiedToken(false), 3000);
                  }}
                  title="Copy full token"
                  className="p-1.5 hover:bg-neutral-200 dark:hover:bg-neutral-800 rounded text-neutral-500 hover:text-neutral-900 dark:hover:text-white transition-colors"
                >
                  {copiedToken ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div className="text-[11px] text-neutral-500 font-mono space-y-1">
              <div>Sensor: {issuedTokenModal.sensor_name}</div>
              <div>Scope: {issuedTokenModal.authorized_scope}</div>
              <div>Header: <code className="text-neutral-400">X-Sensor-Token: {showRawToken ? issuedTokenModal.raw_token : "••••••••••••••••"}</code></div>
            </div>

            <div className="flex justify-end pt-3 border-t border-neutral-200 dark:border-neutral-800">
              <button
                onClick={() => setIssuedTokenModal(null)}
                className="px-4 py-2 text-xs font-mono bg-[#FF3D00] text-white rounded font-medium hover:bg-[#e03600]"
              >
                I HAVE SECURELY SAVED THIS TOKEN
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* DRAWER: INSPECT EVENT DETAILS                                             */}
      {/* ========================================================================= */}
      {selectedEvent && (
        <InspectorDrawer
          isOpen={true}
          onClose={() => setSelectedEvent(null)}
          title="TELEMETRY EVENT INSPECTOR"
          subtitle={`Event ID: ${selectedEvent.event_id}`}
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="space-y-1">
              <div className="text-neutral-500">EVENT KIND</div>
              <div className="font-semibold text-neutral-900 dark:text-neutral-100">
                {selectedEvent.event_kind}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <div className="text-neutral-500">SCHEMA VERSION</div>
                <div>{selectedEvent.schema_version}</div>
              </div>
              <div>
                <div className="text-neutral-500">EVIDENCE GRADE</div>
                <div>{selectedEvent.evidence_grade}</div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <div className="text-neutral-500">SOURCE TIMESTAMP</div>
                <div>{selectedEvent.source_timestamp}</div>
              </div>
              <div>
                <div className="text-neutral-500">RECEIVED AT (SERVER)</div>
                <div>{selectedEvent.received_at}</div>
              </div>
            </div>

            <div className="space-y-1">
              <div className="text-neutral-500">CLOCK SKEW</div>
              <div>{selectedEvent.clock_skew_seconds.toFixed(3)} seconds</div>
            </div>

            {selectedEvent.initiator_spi && (
              <div className="space-y-1">
                <div className="text-neutral-500">INITIATOR SPI</div>
                <CopyableValue value={selectedEvent.initiator_spi} label={selectedEvent.initiator_spi} />
              </div>
            )}

            {selectedEvent.responder_spi && (
              <div className="space-y-1">
                <div className="text-neutral-500">RESPONDER SPI</div>
                <CopyableValue value={selectedEvent.responder_spi} label={selectedEvent.responder_spi} />
              </div>
            )}

            {selectedEvent.cipher_suite && (
              <div className="space-y-1">
                <div className="text-neutral-500">CIPHER SUITE</div>
                <div>{selectedEvent.cipher_suite}</div>
              </div>
            )}

            {selectedEvent.failure_reason && (
              <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-500 rounded">
                <div className="font-semibold mb-1">FAILURE REASON</div>
                <div>{selectedEvent.failure_reason}</div>
              </div>
            )}

            {selectedEvent.raw_source_status && (
              <div className="space-y-1">
                <div className="text-neutral-500">RAW SOURCE LOG / STATUS</div>
                <pre className="p-3 bg-neutral-100 dark:bg-black border border-neutral-300 dark:border-neutral-800 rounded text-[11px] overflow-x-auto whitespace-pre-wrap">
                  {selectedEvent.raw_source_status}
                </pre>
              </div>
            )}

            {/* Quick cross-flow links */}
            <div className="pt-2 border-t border-neutral-200 dark:border-neutral-800 space-y-1.5">
              <span className="text-[10px] text-neutral-400 uppercase font-bold block">Cross-Flow Forensics</span>
              <div className="flex gap-2">
                <Link
                  href="/inventory"
                  className="flex-1 flex items-center justify-center space-x-1 py-1.5 px-2 text-[11px] border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800"
                >
                  <FileKey2 className="w-3 h-3 text-blue-500" />
                  <span>Config Inventory</span>
                </Link>
                <Link
                  href="/analyses"
                  className="flex-1 flex items-center justify-center space-x-1 py-1.5 px-2 text-[11px] border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800"
                >
                  <Activity className="w-3 h-3 text-[#FF3D00]" />
                  <span>Forensic Analyses</span>
                </Link>
              </div>
            </div>
          </div>
        </InspectorDrawer>
      )}

      {/* ========================================================================= */}
      {/* DRAWER: INSPECT GATEWAY DETAILS & WORKFLOW TRANSITIONS                     */}
      {/* ========================================================================= */}
      {selectedGatewayDetails && (
        <InspectorDrawer
          isOpen={true}
          onClose={() => setSelectedGatewayDetails(null)}
          title={`AUTHORIZED GATEWAY: ${selectedGatewayDetails.name}`}
          subtitle={`IP: ${selectedGatewayDetails.gateway_ip}`}
          badge={
            <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase font-semibold rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
              {selectedGatewayDetails.status}
            </span>
          }
        >
          <div className="space-y-4 font-mono text-xs">
            {/* Properties */}
            <div className="grid grid-cols-2 gap-2 p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800">
              <div>
                <span className="text-neutral-500 text-[10px] block">PRIMARY IP</span>
                <CopyableValue value={selectedGatewayDetails.gateway_ip} label="IP" />
              </div>
              <div>
                <span className="text-neutral-500 text-[10px] block">OPERATOR ID</span>
                <span className="font-bold">{selectedGatewayDetails.operator_id}</span>
              </div>
              <div>
                <span className="text-neutral-500 text-[10px] block">AUTHORIZED SCOPE</span>
                <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                  {selectedGatewayDetails.authorized_scope}
                </span>
              </div>
              <div>
                <span className="text-neutral-500 text-[10px] block">AUTHORIZATION REF</span>
                <span>{selectedGatewayDetails.authorization_reference}</span>
              </div>
            </div>

            {/* Attached Sensors */}
            <div className="space-y-1.5">
              <span className="text-[10px] text-neutral-500 uppercase font-bold">Attached Telemetry Sensors</span>
              {sensors.filter((s) => s.gateway_id === selectedGatewayDetails.id).length === 0 ? (
                <div className="p-2.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-neutral-500 text-[11px]">
                  No dedicated sensors attached directly to this gateway boundary.
                </div>
              ) : (
                <div className="space-y-1">
                  {sensors
                    .filter((s) => s.gateway_id === selectedGatewayDetails.id)
                    .map((s) => {
                      const h = healthList.find((hl) => hl.sensor_id === s.id);
                      return (
                        <div
                          key={s.id}
                          className="p-2 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 flex items-center justify-between"
                        >
                          <div>
                            <div className="font-bold">{s.sensor_name}</div>
                            <div className="text-[10px] text-neutral-400">
                              {s.sensor_type} • Window: {s.freshness_window_seconds}s
                            </div>
                          </div>
                          <span
                            className={`text-[10px] px-1.5 py-0.5 border font-semibold ${
                              h?.current_health === "HEALTHY"
                                ? "border-emerald-500 text-emerald-600 bg-emerald-50 dark:bg-emerald-950/20"
                                : "border-amber-500 text-amber-600 bg-amber-50 dark:bg-amber-950/20"
                            }`}
                          >
                            {h?.current_health || "UNKNOWN"}
                          </span>
                        </div>
                      );
                    })}
                </div>
              )}
            </div>

            {/* Analyst Workflow Transitions */}
            <div className="space-y-2 pt-2 border-t border-neutral-200 dark:border-neutral-800">
              <span className="text-[10px] text-neutral-500 uppercase font-bold block">
                SOC Analyst Workflow Transitions
              </span>
              <button
                onClick={() => {
                  setFilterGatewayId(selectedGatewayDetails.id);
                  setActiveTab("timeline");
                  setSelectedGatewayDetails(null);
                }}
                className="w-full flex items-center justify-between px-3 py-2 bg-neutral-900 hover:bg-black dark:bg-white dark:hover:bg-neutral-200 text-white dark:text-neutral-900 text-xs font-bold transition-colors"
              >
                <div className="flex items-center space-x-2">
                  <Layers className="w-3.5 h-3.5" />
                  <span>Filter Event Timeline for {selectedGatewayDetails.name}</span>
                </div>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>

              <button
                onClick={() => {
                  setFilterGatewayId(selectedGatewayDetails.id);
                  setActiveTab("sa_states");
                  setSelectedGatewayDetails(null);
                }}
                className="w-full flex items-center justify-between px-3 py-2 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-xs font-bold transition-colors"
              >
                <div className="flex items-center space-x-2">
                  <GitBranch className="w-3.5 h-3.5" />
                  <span>View Projected SAs for {selectedGatewayDetails.name}</span>
                </div>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>

              <Link
                href={`/inventory?gateway_identity=${encodeURIComponent(selectedGatewayDetails.name)}`}
                className="w-full flex items-center justify-between px-3 py-2 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-xs font-bold transition-colors"
              >
                <div className="flex items-center space-x-2">
                  <FileKey2 className="w-3.5 h-3.5 text-blue-500" />
                  <span>Inspect Configuration & Cert Inventory</span>
                </div>
                <ExternalLink className="w-3.5 h-3.5" />
              </Link>

              <Link
                href={`/vulnerabilities?host_ip=${encodeURIComponent(selectedGatewayDetails.gateway_ip)}`}
                className="w-full flex items-center justify-between px-3 py-2 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-xs font-bold transition-colors"
              >
                <div className="flex items-center space-x-2">
                  <ShieldCheck className="w-3.5 h-3.5 text-indigo-500" />
                  <span>View Correlated External Vulnerabilities</span>
                </div>
                <ExternalLink className="w-3.5 h-3.5" />
              </Link>

              <Link
                href="/analyses"
                className="w-full flex items-center justify-between px-3 py-2 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-xs font-bold transition-colors"
              >
                <div className="flex items-center space-x-2">
                  <Activity className="w-3.5 h-3.5 text-[#FF3D00]" />
                  <span>Open Protocol & Forensics Analyses</span>
                </div>
                <ChevronRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>
        </InspectorDrawer>
      )}
    </div>
  );
}

export default function ContinuousMonitoringPage() {
  return (
    <Suspense
      fallback={
        <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
          Loading Continuous Monitoring workbench and telemetry status...
        </div>
      }
    >
      <MonitoringContent />
    </Suspense>
  );
}
