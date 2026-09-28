"use client";

import React, { useState, useEffect, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import {
  ConfigurationSnapshotDTO,
  ConfigurationDriftDTO,
  GatewayCertificateDTO,
  FieldDriftItemDTO,
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
  FileKey2,
  FileCode2,
  GitCompare,
  ShieldCheck,
  AlertTriangle,
  Clock,
  RefreshCw,
  PlusCircle,
  Copy,
  Check,
  XCircle,
  Lock,
  Layers,
  Eye,
  SlidersHorizontal,
  FileText,
  BadgeAlert,
  CheckCircle2,
  Radio,
  Activity,
  ExternalLink,
  ChevronRight,
} from "lucide-react";

function InventoryContent() {
  const queryClient = useQueryClient();
  const searchParams = useSearchParams();

  // Navigation tab state
  const [activeTab, setActiveTab] = useState<"snapshots" | "drift" | "certificates" | "import">("snapshots");

  // Filter states
  const [selectedGateway, setSelectedGateway] = useState<string>("");
  const [certValidityFilter, setCertValidityFilter] = useState<string>("");

  // Sync selectedGateway from URL query parameter if present
  useEffect(() => {
    const gwParam = searchParams.get("gateway_identity");
    if (gwParam) {
      setSelectedGateway(gwParam);
    }
  }, [searchParams]);

  // Drawer inspector states
  const [selectedSnapshot, setSelectedSnapshot] = useState<ConfigurationSnapshotDTO | null>(null);
  const [selectedDrift, setSelectedDrift] = useState<ConfigurationDriftDTO | null>(null);
  const [selectedCert, setSelectedCert] = useState<GatewayCertificateDTO | null>(null);

  // Drift comparison form state
  const [driftBaselineId, setDriftBaselineId] = useState<string>("");
  const [driftObservedId, setDriftObservedId] = useState<string>("");

  // Ingestion form state
  const [importType, setImportType] = useState<"config" | "cert">("config");
  const [gatewayIdentity, setGatewayIdentity] = useState("gw-strongswan-01");
  const [authorizedScope, setAuthorizedScope] = useState("198.51.100.0/24");
  const [sourceType, setSourceType] = useState<"CONFIGURED_FILE" | "LAB_CONTROLLED">("CONFIGURED_FILE");
  const [configText, setConfigText] = useState("");
  const [certPemText, setCertPemText] = useState("");
  const [trustStorePemText, setTrustStorePemText] = useState("");
  const [sourceAlias, setSourceAlias] = useState("gateway_swanctl.conf");
  const [operatorId, setOperatorId] = useState("operator-admin");
  const [authRef, setAuthRef] = useState("CHG-2026-INV-01");
  const [attestationConfirmed, setAttestationConfirmed] = useState(false);
  const [formMessage, setFormMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Queries
  const {
    data: snapshots = [],
    isLoading: isSnapshotsLoading,
    refetch: refetchSnapshots,
  } = useQuery({
    queryKey: ["inventory-snapshots", selectedGateway],
    queryFn: () =>
      api.inventory.listSnapshots({
        gateway_identity: selectedGateway || undefined,
        limit: 50,
      }),
  });

  const {
    data: driftHistory = [],
    isLoading: isDriftLoading,
    refetch: refetchDrift,
  } = useQuery({
    queryKey: ["inventory-drift-history", selectedGateway],
    queryFn: () =>
      api.inventory.getDriftHistory({
        gateway_identity: selectedGateway || undefined,
        limit: 50,
      }),
  });

  const {
    data: certificates = [],
    isLoading: isCertsLoading,
    refetch: refetchCerts,
  } = useQuery({
    queryKey: ["inventory-certificates", selectedGateway, certValidityFilter],
    queryFn: () =>
      api.inventory.listCertificates({
        gateway_identity: selectedGateway || undefined,
        validity_status: certValidityFilter || undefined,
        limit: 50,
      }),
  });

  // Mutations
  const importConfigMutation = useMutation({
    mutationFn: () => {
      if (!attestationConfirmed) {
        throw new Error("Operator attestation confirmation is required.");
      }
      if (!configText.trim()) {
        throw new Error("Configuration content cannot be empty. Please provide valid swanctl.conf syntax.");
      }
      return api.inventory.importConfiguration({
        gateway_identity: gatewayIdentity,
        authorized_scope: authorizedScope,
        source_type: sourceType,
        config_text: configText,
        collection_method: "OFFLINE_IMPORT",
        operator_id: operatorId,
        authorization_reference: authRef,
      });
    },
    onSuccess: (data) => {
      setFormMessage({
        type: "success",
        text: `Configuration snapshot imported successfully! ID: ${data.id} (Digest: ${data.canonical_digest.substring(0, 12)}...)`,
      });
      setConfigText("");
      queryClient.invalidateQueries({ queryKey: ["inventory-snapshots"] });
    },
    onError: (err: any) => {
      setFormMessage({
        type: "error",
        text: err?.message || "Failed to import configuration snapshot.",
      });
    },
  });

  const importCertMutation = useMutation({
    mutationFn: () => {
      if (!attestationConfirmed) {
        throw new Error("Operator attestation confirmation is required.");
      }
      return api.inventory.importCertificate({
        gateway_identity: gatewayIdentity,
        certificate_pem: certPemText,
        trust_store_pem: trustStorePemText || undefined,
        source_alias: sourceAlias,
        operator_id: operatorId,
        authorization_reference: authRef,
      });
    },
    onSuccess: (data) => {
      setFormMessage({
        type: "success",
        text: `Imported ${data.length} certificate(s) successfully!`,
      });
      setCertPemText("");
      setTrustStorePemText("");
      queryClient.invalidateQueries({ queryKey: ["inventory-certificates"] });
    },
    onError: (err: any) => {
      setFormMessage({
        type: "error",
        text: err?.message || "Failed to import certificate(s).",
      });
    },
  });

  const designateBaselineMutation = useMutation({
    mutationFn: (snapshotId: string) =>
      api.inventory.designateBaseline(snapshotId, {
        operator_id: operatorId,
        approval_reference: authRef,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["inventory-snapshots"] });
    },
  });

  const compareDriftMutation = useMutation({
    mutationFn: () => {
      if (!driftBaselineId || !driftObservedId) {
        throw new Error("Both baseline and observed snapshots must be selected.");
      }
      return api.inventory.compareDrift({
        baseline_snapshot_id: driftBaselineId,
        observed_snapshot_id: driftObservedId,
      });
    },
    onSuccess: (data) => {
      setSelectedDrift(data);
      queryClient.invalidateQueries({ queryKey: ["inventory-drift-history"] });
    },
    onError: (err: any) => {
      alert(`Drift comparison failed: ${err?.message || "Unknown error"}`);
    },
  });

  // Calculate summary counters (exclude e3b0c442 empty hashes from verified baseline count)
  const totalSnapshots = snapshots.length;
  const baselineCount = snapshots.filter((s) => s.is_baseline && !s.canonical_digest?.startsWith("e3b0c442")).length;
  const totalCerts = certificates.length;
  const expiringSoonCerts = certificates.filter((c) => c.validity_status === "EXPIRING_SOON").length;
  const expiredCerts = certificates.filter((c) => c.validity_status === "EXPIRED").length;

  return (
    <div className="space-y-6">
      {/* Top Banner & Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight font-heading text-neutral-900 dark:text-neutral-100">
              Configuration & Certificate Inventory
            </h1>
            <span className="text-[10px] bg-sky-100 dark:bg-sky-950/80 text-sky-800 dark:text-sky-400 border border-sky-300 dark:border-sky-800 font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider">
              strongSwan Baseline
            </span>
          </div>
          <p className="text-sm text-neutral-500 dark:text-neutral-400 mt-1">
            Authoritative baseline tracking, semantic configuration drift detection, and public X.509 certificate intelligence.
          </p>
        </div>

        {/* Global Action / Refresh */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              refetchSnapshots();
              refetchDrift();
              refetchCerts();
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-neutral-100 hover:bg-neutral-200 dark:bg-[#1F1F1F] dark:hover:bg-[#2A2A2A] text-neutral-700 dark:text-neutral-300 text-xs font-mono border border-neutral-300 dark:border-[#333] rounded transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
          <button
            onClick={() => setActiveTab("import")}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs font-mono font-medium rounded transition-colors shadow-sm"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            Import Snapshot / Cert
          </button>
        </div>
      </div>

      {/* Configuration Intent vs Monitored Runtime Telemetry Clarification */}
      <div className="p-3 bg-neutral-50 dark:bg-neutral-900/60 border border-neutral-200 dark:border-neutral-800 rounded text-xs font-mono text-neutral-600 dark:text-neutral-400 flex items-start gap-2.5">
        <FileCode2 className="w-4 h-4 text-sky-500 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-neutral-900 dark:text-neutral-100">Configured Intent Repository:</span> Parsed strongSwan (<code className="font-bold">swanctl.conf</code>) files represent static administrative intent and authorized baselines. For active sensor health, heartbeat telemetry, and established IPsec tunnels, navigate to{" "}
          <Link href="/monitoring" className="text-[#FF3D00] underline font-bold">
            Live Monitoring
          </Link>
          .
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 font-mono">
        <Card className="p-3 bg-white dark:bg-[#141416] border-neutral-300 dark:border-neutral-800 shadow-xs">
          <div className="text-[11px] text-neutral-500 uppercase tracking-wider">Total Snapshots</div>
          <div className="text-xl font-bold text-neutral-900 dark:text-neutral-100 mt-1">{totalSnapshots}</div>
          <div className="text-[10px] text-neutral-400 mt-0.5">Recorded configurations</div>
        </Card>

        <Card className="p-3 bg-white dark:bg-[#141416] border-neutral-300 dark:border-neutral-800 shadow-xs">
          <div className="text-[11px] text-neutral-500 uppercase tracking-wider">Active Baselines</div>
          <div className="text-xl font-bold text-emerald-600 dark:text-emerald-400 mt-1">{baselineCount}</div>
          <div className="text-[10px] text-neutral-400 mt-0.5">Approved baselines</div>
        </Card>

        <Card className="p-3 bg-white dark:bg-[#141416] border-neutral-300 dark:border-neutral-800 shadow-xs">
          <div className="text-[11px] text-neutral-500 uppercase tracking-wider">Total Certificates</div>
          <div className="text-xl font-bold text-neutral-900 dark:text-neutral-100 mt-1">{totalCerts}</div>
          <div className="text-[10px] text-neutral-400 mt-0.5">Public X.509 credentials</div>
        </Card>

        <Card className="p-3 bg-white dark:bg-[#141416] border-neutral-300 dark:border-neutral-800 shadow-xs">
          <div className="text-[11px] text-neutral-500 uppercase tracking-wider">Expiring Soon</div>
          <div className="text-xl font-bold text-amber-600 dark:text-amber-400 mt-1">{expiringSoonCerts}</div>
          <div className="text-[10px] text-neutral-400 mt-0.5">&lt; 30 days remaining</div>
        </Card>

        <Card className="p-3 bg-white dark:bg-[#141416] border-neutral-300 dark:border-neutral-800 shadow-xs">
          <div className="text-[11px] text-neutral-500 uppercase tracking-wider">Expired</div>
          <div className={`text-xl font-bold mt-1 ${expiredCerts > 0 ? "text-rose-600 dark:text-rose-400" : "text-neutral-400"}`}>
            {expiredCerts}
          </div>
          <div className="text-[10px] text-neutral-400 mt-0.5">Invalid validity end</div>
        </Card>
      </div>

      {/* Epistemic Invariant Callout */}
      <div className="bg-neutral-100 dark:bg-[#121212] border border-neutral-200 dark:border-neutral-800 p-3 rounded text-xs text-neutral-700 dark:text-neutral-300 flex items-start gap-2.5">
        <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-neutral-900 dark:text-neutral-200">Epistemic Truth Guard:</span> Parsed configuration is evidence of <span className="font-mono text-sky-600 dark:text-sky-400">CONFIGURED INTENT</span>. Active runtime status is <span className="font-mono text-emerald-600 dark:text-emerald-400">RUNTIME EVIDENCE</span>. All secrets (PSKs, private keys, passwords) are scrubbed and replaced with <span className="font-mono text-amber-600 dark:text-amber-400">[REDACTED_SECRET]</span> prior to storage. Private keys are strictly rejected at ingestion.
        </div>
      </div>

      {/* Tabs Header */}
      <div className="border-b border-[#2C2C2C] flex items-center gap-1 font-mono text-xs">
        <button
          onClick={() => setActiveTab("snapshots")}
          className={`px-4 py-2 border-b-2 font-medium transition-colors flex items-center gap-1.5 ${
            activeTab === "snapshots"
              ? "border-sky-500 text-sky-400 bg-sky-950/20"
              : "border-transparent text-neutral-400 hover:text-neutral-200"
          }`}
        >
          <FileCode2 className="w-3.5 h-3.5" />
          Snapshots & Baselines ({snapshots.length})
        </button>

        <button
          onClick={() => setActiveTab("drift")}
          className={`px-4 py-2 border-b-2 font-medium transition-colors flex items-center gap-1.5 ${
            activeTab === "drift"
              ? "border-sky-500 text-sky-400 bg-sky-950/20"
              : "border-transparent text-neutral-400 hover:text-neutral-200"
          }`}
        >
          <GitCompare className="w-3.5 h-3.5" />
          Configuration Drift ({driftHistory.length})
        </button>

        <button
          onClick={() => setActiveTab("certificates")}
          className={`px-4 py-2 border-b-2 font-medium transition-colors flex items-center gap-1.5 ${
            activeTab === "certificates"
              ? "border-sky-500 text-sky-400 bg-sky-950/20"
              : "border-transparent text-neutral-400 hover:text-neutral-200"
          }`}
        >
          <FileKey2 className="w-3.5 h-3.5" />
          Certificate Inventory ({certificates.length})
        </button>

        <button
          onClick={() => setActiveTab("import")}
          className={`px-4 py-2 border-b-2 font-medium transition-colors flex items-center gap-1.5 ${
            activeTab === "import"
              ? "border-sky-500 text-sky-400 bg-sky-950/20"
              : "border-transparent text-neutral-400 hover:text-neutral-200"
          }`}
        >
          <PlusCircle className="w-3.5 h-3.5" />
          Import Ingestion
        </button>
      </div>

      {/* TAB 1: SNAPSHOTS & BASELINES */}
      {activeTab === "snapshots" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs">
            <div className="flex items-center gap-2">
              <span className="text-neutral-400">Filter Gateway:</span>
              <input
                type="text"
                placeholder="All gateways..."
                value={selectedGateway}
                onChange={(e) => setSelectedGateway(e.target.value)}
                className="bg-[#191919] border border-[#333] px-2.5 py-1 text-neutral-200 rounded text-xs w-48"
              />
            </div>
            <div className="text-neutral-500">
              Showing {snapshots.length} snapshot(s)
            </div>
          </div>

          <Card className="bg-[#141414] border-[#2A2A2A] overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="border-b border-[#2A2A2A] bg-[#191919]">
                  <TableHead className="font-mono text-xs text-neutral-400">Gateway Identity</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400">Status / Baseline</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400">Source Type</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400">Digest (SHA-256)</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400">Connections</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400">Created At (UTC)</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isSnapshotsLoading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-neutral-500 font-mono text-xs">
                      Loading configuration snapshots...
                    </TableCell>
                  </TableRow>
                ) : snapshots.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-neutral-500 font-mono text-xs">
                      No configuration snapshots found. Import a strongSwan swanctl.conf file to begin.
                    </TableCell>
                  </TableRow>
                ) : (
                  snapshots.map((s) => {
                    const conns = s.normalized_ir?.connections || {};
                    const connCount = Object.keys(conns).length;
                    return (
                      <TableRow key={s.id} className="border-b border-[#222] hover:bg-[#1A1A1A]">
                        <TableCell className="font-mono text-xs font-semibold text-neutral-200">
                          {s.gateway_identity}
                          <div className="text-[10px] text-neutral-500 font-normal">
                            Scope: {s.authorized_scope}
                          </div>
                        </TableCell>

                        <TableCell>
                          {s.canonical_digest?.startsWith("e3b0c442") ? (
                            <span className="inline-flex items-center gap-1 bg-amber-950/80 text-amber-400 border border-amber-800 px-2 py-0.5 rounded text-[10px] font-mono font-bold" title="SHA-256 digest of empty content (e3b0c442). Not an approved configuration baseline.">
                              <AlertTriangle className="w-3 h-3 text-amber-500" />
                              UNVERIFIED / EMPTY BASELINE
                            </span>
                          ) : s.is_baseline ? (
                            <span className="inline-flex items-center gap-1 bg-emerald-950/80 text-emerald-400 border border-emerald-800 px-2 py-0.5 rounded text-[10px] font-mono font-bold">
                              <CheckCircle2 className="w-3 h-3" />
                              BASELINE v{s.baseline_version || 1}
                            </span>
                          ) : (
                            <span className="inline-flex items-center bg-neutral-900 text-neutral-400 border border-neutral-800 px-2 py-0.5 rounded text-[10px] font-mono">
                              SNAPSHOT
                            </span>
                          )}
                        </TableCell>

                        <TableCell className="font-mono text-xs">
                          <span className="text-sky-400 bg-sky-950/40 px-1.5 py-0.5 rounded text-[10px] border border-sky-900/50">
                            {s.source_type}
                          </span>
                        </TableCell>

                        <TableCell className="font-mono text-xs">
                          <CopyableValue value={s.canonical_digest} truncate={true} />
                          {s.canonical_digest?.startsWith("e3b0c442") && (
                            <div className="text-[9px] text-amber-400 font-mono mt-0.5">
                              (Empty Content Digest)
                            </div>
                          )}
                        </TableCell>

                        <TableCell className="font-mono text-xs text-neutral-300">
                          {connCount} connection(s)
                          {s.unsupported_directives?.length > 0 && (
                            <span className="ml-1 text-[10px] text-amber-400">
                              ({s.unsupported_directives.length} unmodeled)
                            </span>
                          )}
                        </TableCell>

                        <TableCell className="font-mono text-xs text-neutral-400">
                          {new Date(s.created_at).toLocaleString()}
                        </TableCell>

                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => setSelectedSnapshot(s)}
                              className="px-2 py-1 bg-[#222] hover:bg-[#333] text-neutral-300 text-xs font-mono rounded flex items-center gap-1"
                            >
                              <Eye className="w-3 h-3" />
                              View IR
                            </button>

                            {!s.is_baseline && (
                              <button
                                onClick={() => designateBaselineMutation.mutate(s.id)}
                                disabled={designateBaselineMutation.isPending}
                                className="px-2 py-1 bg-emerald-950/80 hover:bg-emerald-900 text-emerald-400 border border-emerald-800 text-xs font-mono rounded"
                                title="Promote to authoritative baseline"
                              >
                                Set Baseline
                              </button>
                            )}
                          </div>
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

      {/* TAB 2: CONFIGURATION DRIFT */}
      {activeTab === "drift" && (
        <div className="space-y-4">
          {/* Drift Compare Launcher */}
          <Card className="p-4 bg-[#161616] border-[#2A2A2A]">
            <h3 className="text-sm font-bold font-mono text-neutral-200 mb-3 flex items-center gap-2">
              <GitCompare className="w-4 h-4 text-sky-400" />
              Compare Snapshots for Semantic Configuration Drift
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
              <div>
                <label className="block text-neutral-400 mb-1">Baseline Snapshot:</label>
                <select
                  value={driftBaselineId}
                  onChange={(e) => setDriftBaselineId(e.target.value)}
                  className="w-full bg-[#1F1F1F] border border-[#333] text-neutral-200 p-1.5 rounded"
                >
                  <option value="">Select Baseline...</option>
                  {snapshots.map((s) => {
                    const isEmptyDigest = s.canonical_digest?.startsWith("e3b0c442");
                    return (
                      <option key={s.id} value={s.id} disabled={isEmptyDigest}>
                        {isEmptyDigest
                          ? "[UNVERIFIED / EMPTY BASELINE] "
                          : s.is_baseline
                          ? "[BASELINE] "
                          : ""}
                        {s.gateway_identity} ({new Date(s.created_at).toLocaleDateString()}) - {s.canonical_digest.substring(0, 8)}
                      </option>
                    );
                  })}
                </select>
              </div>

              <div>
                <label className="block text-neutral-400 mb-1">Observed Snapshot:</label>
                <select
                  value={driftObservedId}
                  onChange={(e) => setDriftObservedId(e.target.value)}
                  className="w-full bg-[#1F1F1F] border border-[#333] text-neutral-200 p-1.5 rounded"
                >
                  <option value="">Select Observed...</option>
                  {snapshots.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.gateway_identity} ({new Date(s.created_at).toLocaleDateString()}) - {s.canonical_digest.substring(0, 8)}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex items-end">
                <button
                  onClick={() => compareDriftMutation.mutate()}
                  disabled={!driftBaselineId || !driftObservedId || compareDriftMutation.isPending}
                  className="w-full py-1.5 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-mono text-xs font-medium rounded transition-colors"
                >
                  {compareDriftMutation.isPending ? "Comparing..." : "Evaluate Configuration Drift"}
                </button>
              </div>
            </div>
          </Card>

          {/* Active Drift Comparison View */}
          {selectedDrift && (
            <Card className="p-4 bg-white dark:bg-[#141414] border border-sky-300 dark:border-sky-900/60 space-y-3">
              <div className="flex items-center justify-between border-b border-neutral-200 dark:border-[#2A2A2A] pb-3">
                <div>
                  <h4 className="text-sm font-bold font-mono text-neutral-900 dark:text-neutral-100 flex items-center gap-2">
                    <span>Drift Report: {selectedDrift.gateway_identity}</span>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                        selectedDrift.comparison_status === "MATCHED"
                          ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                          : selectedDrift.comparison_status === "DRIFT_DETECTED"
                          ? "bg-amber-950 text-amber-400 border border-amber-800"
                          : "bg-neutral-800 text-neutral-400"
                      }`}
                    >
                      {selectedDrift.comparison_status}
                    </span>
                  </h4>
                  <div className="text-xs text-neutral-400 font-mono mt-0.5">
                    Evaluated at {new Date(selectedDrift.created_at).toLocaleString()}
                  </div>
                </div>

                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="text-emerald-400">Matched: {selectedDrift.drift_summary.matched_count}</span>
                  <span className="text-amber-400">Changed: {selectedDrift.drift_summary.changed_count}</span>
                  <span className="text-rose-400">Missing: {selectedDrift.drift_summary.missing_count}</span>
                  <span className="text-sky-400">New: {selectedDrift.drift_summary.new_count}</span>
                  <button
                    onClick={() => setSelectedDrift(null)}
                    className="ml-2 text-neutral-500 hover:text-neutral-300"
                  >
                    Close
                  </button>
                </div>
              </div>

              {/* Field Drift Table */}
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="border-b border-[#2A2A2A] bg-[#191919]">
                      <TableHead className="font-mono text-xs text-neutral-400">Field Path</TableHead>
                      <TableHead className="font-mono text-xs text-neutral-400">Status</TableHead>
                      <TableHead className="font-mono text-xs text-neutral-400">Baseline Value</TableHead>
                      <TableHead className="font-mono text-xs text-neutral-400">Observed Value</TableHead>
                      <TableHead className="font-mono text-xs text-neutral-400">Description</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {selectedDrift.field_drifts.map((fd, i) => (
                      <TableRow key={i} className="border-b border-[#222] font-mono text-xs">
                        <TableCell className="font-semibold text-neutral-200">{fd.field_path}</TableCell>
                        <TableCell>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              fd.status === "MATCHED"
                                ? "bg-emerald-950/60 text-emerald-400 border border-emerald-900"
                                : fd.status === "CHANGED"
                                ? "bg-amber-950/60 text-amber-400 border border-amber-900"
                                : fd.status === "MISSING_IN_OBSERVED"
                                ? "bg-rose-950/60 text-rose-400 border border-rose-900"
                                : fd.status === "NEW_IN_OBSERVED"
                                ? "bg-sky-950/60 text-sky-400 border border-sky-900"
                                : "bg-neutral-900 text-neutral-400 border border-neutral-800"
                            }`}
                          >
                            {fd.status}
                          </span>
                        </TableCell>
                        <TableCell className="text-neutral-300">
                          {fd.baseline_value !== null ? String(fd.baseline_value) : <span className="text-neutral-600">None</span>}
                        </TableCell>
                        <TableCell className="text-neutral-300">
                          {fd.observed_value !== null ? String(fd.observed_value) : <span className="text-neutral-600">None</span>}
                        </TableCell>
                        <TableCell className="text-neutral-400">{fd.description}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </Card>
          )}

          {/* Drift History Table */}
          <Card className="bg-[#141414] border-[#2A2A2A] overflow-hidden">
            <div className="p-3 border-b border-[#2A2A2A] font-mono text-xs font-bold text-neutral-300">
              Drift Evaluation History
            </div>
            <Table>
              <TableHeader>
                <TableRow className="border-b border-[#2A2A2A] bg-[#191919]">
                  <TableHead className="font-mono text-xs text-neutral-400">Gateway</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400">Comparison Status</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400">Drift Breakdown</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400">Evaluated At</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isDriftLoading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-6 text-neutral-500 font-mono text-xs">
                      Loading drift records...
                    </TableCell>
                  </TableRow>
                ) : driftHistory.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-6 text-neutral-500 font-mono text-xs">
                      No drift records recorded yet. Compare two snapshots above.
                    </TableCell>
                  </TableRow>
                ) : (
                  driftHistory.map((d) => (
                    <TableRow key={d.id} className="border-b border-[#222] hover:bg-[#1A1A1A]">
                      <TableCell className="font-mono text-xs font-semibold text-neutral-200">
                        {d.gateway_identity}
                      </TableCell>
                      <TableCell>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                            d.comparison_status === "MATCHED"
                              ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                              : d.comparison_status === "DRIFT_DETECTED"
                              ? "bg-amber-950 text-amber-400 border border-amber-800"
                              : "bg-neutral-800 text-neutral-400"
                          }`}
                        >
                          {d.comparison_status}
                        </span>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-neutral-400">
                        {d.drift_summary.changed_count} changed, {d.drift_summary.missing_count} missing, {d.drift_summary.new_count} new ({d.drift_summary.matched_count} matched)
                      </TableCell>
                      <TableCell className="font-mono text-xs text-neutral-400">
                        {new Date(d.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <button
                          onClick={() => setSelectedDrift(d)}
                          className="px-2 py-1 bg-[#222] hover:bg-[#333] text-neutral-300 text-xs font-mono rounded"
                        >
                          View Diff
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

      {/* TAB 3: CERTIFICATE INVENTORY */}
      {activeTab === "certificates" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs">
            <div className="flex items-center gap-2">
              <span className="text-neutral-400">Validity Status:</span>
              <select
                value={certValidityFilter}
                onChange={(e) => setCertValidityFilter(e.target.value)}
                className="bg-[#191919] border border-[#333] px-2.5 py-1 text-neutral-200 rounded text-xs"
              >
                <option value="">All Statuses</option>
                <option value="VALID">VALID</option>
                <option value="EXPIRING_SOON">EXPIRING_SOON</option>
                <option value="EXPIRED">EXPIRED</option>
                <option value="NOT_YET_VALID">NOT_YET_VALID</option>
              </select>
            </div>
            <div className="text-neutral-500 font-mono text-xs">
              Showing {certificates.length} certificate(s)
            </div>
          </div>

          <Card className="bg-[#141414] border-[#2A2A2A] overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="border-b border-[#2A2A2A] bg-[#191919]">
                  <TableHead className="font-mono text-xs text-neutral-400">Subject DN / Fingerprint</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400">Validity Status</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400">Days Remaining</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400">Key & Signature</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400">strongSwan Connection</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400">Chain Validation</TableHead>
                  <TableHead className="font-mono text-xs text-neutral-400 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isCertsLoading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-neutral-500 font-mono text-xs">
                      Loading certificate inventory...
                    </TableCell>
                  </TableRow>
                ) : certificates.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-neutral-500 font-mono text-xs">
                      No certificates recorded. Import an X.509 PEM certificate to begin.
                    </TableCell>
                  </TableRow>
                ) : (
                  certificates.map((cert) => {
                    const isDemoSeedCert =
                      cert.id?.replace(/-/g, "").toLowerCase() === "7a2dc9ca442f4ce49b358a0acb4758e0" ||
                      cert.subject_dn?.includes("CN=vpn-gw-alpha.corp.internal");
                    return (
                    <TableRow key={cert.id} className="border-b border-[#222] hover:bg-[#1A1A1A]">
                      <TableCell className="font-mono text-xs font-semibold text-neutral-200 max-w-xs">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="truncate" title={cert.subject_dn}>{cert.subject_dn}</span>
                          {isDemoSeedCert && (
                            <span
                              className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-800"
                              title="Seeded test fixture for demonstration purposes"
                            >
                              [DEMO / SEED DATA]
                            </span>
                          )}
                        </div>
                        <div className="text-[10px] text-neutral-500 font-normal">
                          SHA-256: {cert.sha256_fingerprint.substring(0, 16)}...
                        </div>
                      </TableCell>

                      <TableCell>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                            cert.validity_status === "VALID"
                              ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                              : cert.validity_status === "EXPIRING_SOON"
                              ? "bg-amber-950 text-amber-400 border border-amber-800"
                              : "bg-rose-950 text-rose-400 border border-rose-800"
                          }`}
                        >
                          {cert.validity_status}
                        </span>
                      </TableCell>

                      <TableCell className="font-mono text-xs">
                        <span
                          className={
                            cert.days_until_expiry < 0
                              ? "text-rose-400 font-bold"
                              : cert.days_until_expiry <= 30
                              ? "text-amber-400 font-bold"
                              : "text-neutral-300"
                          }
                        >
                          {cert.days_until_expiry < 0
                            ? `Expired ${Math.abs(cert.days_until_expiry)}d ago`
                            : `${cert.days_until_expiry} days`}
                        </span>
                      </TableCell>

                      <TableCell className="font-mono text-xs text-neutral-300">
                        {cert.public_key_algorithm} ({cert.public_key_bits} bits)
                        <div className="text-[10px] text-neutral-500">{cert.signature_algorithm}</div>
                      </TableCell>

                      <TableCell className="font-mono text-xs">
                        {cert.associated_connection ? (
                          <span className="text-emerald-400 bg-emerald-950/40 px-1.5 py-0.5 rounded border border-emerald-900/50 text-[10px]">
                            {cert.associated_connection}
                          </span>
                        ) : (
                          <span className="text-neutral-500 text-[10px]">{cert.identity_association_status}</span>
                        )}
                      </TableCell>

                      <TableCell className="font-mono text-xs">
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded border ${
                            cert.chain_validation_status === "VALIDATED"
                              ? "bg-emerald-950/60 text-emerald-400 border-emerald-800"
                              : cert.chain_validation_status === "FAILED"
                              ? "bg-rose-950/60 text-rose-400 border-rose-800"
                              : "bg-neutral-900 text-neutral-400 border-neutral-800"
                          }`}
                        >
                          {cert.chain_validation_status}
                        </span>
                      </TableCell>

                      <TableCell className="text-right">
                        <button
                          onClick={() => setSelectedCert(cert)}
                          className="px-2 py-1 bg-[#222] hover:bg-[#333] text-neutral-300 text-xs font-mono rounded"
                        >
                          Inspect
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

      {/* TAB 4: IMPORT INGESTION WORKBENCH */}
      {activeTab === "import" && (
        <div className="space-y-4 max-w-4xl">
          <Card className="p-4 bg-[#161616] border-[#2A2A2A] space-y-4 font-mono text-xs">
            <div className="flex items-center gap-4 border-b border-[#2A2A2A] pb-3">
              <span className="text-neutral-300 font-bold">Import Target:</span>
              <label className="flex items-center gap-1.5 text-neutral-200 cursor-pointer">
                <input
                  type="radio"
                  name="importType"
                  checked={importType === "config"}
                  onChange={() => setImportType("config")}
                />
                strongSwan Configuration (swanctl.conf)
              </label>
              <label className="flex items-center gap-1.5 text-neutral-200 cursor-pointer">
                <input
                  type="radio"
                  name="importType"
                  checked={importType === "cert"}
                  onChange={() => setImportType("cert")}
                />
                X.509 Public Certificate (PEM)
              </label>
            </div>

            {/* Scope & Operator Details */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-neutral-400 mb-1">Gateway Identity (FQDN / ID):</label>
                <input
                  type="text"
                  value={gatewayIdentity}
                  onChange={(e) => setGatewayIdentity(e.target.value)}
                  className="w-full bg-[#1A1A1A] border border-[#333] p-1.5 text-neutral-200 rounded"
                />
              </div>

              <div>
                <label className="block text-neutral-400 mb-1">Authorized Scope (CIDR):</label>
                <input
                  type="text"
                  value={authorizedScope}
                  onChange={(e) => setAuthorizedScope(e.target.value)}
                  className="w-full bg-[#1A1A1A] border border-[#333] p-1.5 text-neutral-200 rounded"
                />
              </div>

              <div>
                <label className="block text-neutral-400 mb-1">Operator ID:</label>
                <input
                  type="text"
                  value={operatorId}
                  onChange={(e) => setOperatorId(e.target.value)}
                  className="w-full bg-[#1A1A1A] border border-[#333] p-1.5 text-neutral-200 rounded"
                />
              </div>

              <div>
                <label className="block text-neutral-400 mb-1">Authorization Reference:</label>
                <input
                  type="text"
                  value={authRef}
                  onChange={(e) => setAuthRef(e.target.value)}
                  className="w-full bg-[#1A1A1A] border border-[#333] p-1.5 text-neutral-200 rounded"
                />
              </div>
            </div>

            {/* Config Import Form */}
            {importType === "config" && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <label className="block text-neutral-400">
                    swanctl.conf Text Payload (Max 1MB, parsed safely in-memory):
                  </label>
                  <button
                    type="button"
                    onClick={() => {
                      setConfigText(`connections {
    gw-prod-tunnel {
        version = 2
        local_addrs = 192.0.2.1
        remote_addrs = 198.51.100.1
        proposals = aes256gcm16-prfsha256-ecp256
        encap = yes
        local {
            auth = pubkey
            certs = gw-prod.crt
            id = gw-prod.agency.gov
        }
        remote {
            auth = pubkey
            id = peer.partner.gov
        }
        children {
            net-prod {
                mode = tunnel
                local_ts = 10.10.0.0/16
                remote_ts = 10.20.0.0/16
                esp_proposals = aes256gcm16-ecp256
                start_action = start
            }
        }
    }
}
secrets {
    rsa-priv {
        file = /etc/swanctl/private/priv.key
        secret = "secret-production-token-1234"
    }
}`);
                    }}
                    className="text-[10px] text-sky-400 hover:underline"
                  >
                    Load Sample swanctl.conf
                  </button>
                </div>
                <textarea
                  rows={10}
                  value={configText}
                  onChange={(e) => setConfigText(e.target.value)}
                  placeholder="Paste strongSwan swanctl.conf content here..."
                  className="w-full bg-[#121212] border border-[#333] p-2 text-neutral-200 font-mono text-xs rounded"
                />
              </div>
            )}

            {/* Certificate Import Form */}
            {importType === "cert" && (
              <div className="space-y-3">
                <div>
                  <label className="block text-neutral-400 mb-1">
                    Public X.509 Certificate (PEM Format):
                  </label>
                  <textarea
                    rows={6}
                    value={certPemText}
                    onChange={(e) => setCertPemText(e.target.value)}
                    placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                    className="w-full bg-[#121212] border border-[#333] p-2 text-neutral-200 font-mono text-xs rounded"
                  />
                </div>

                <div>
                  <label className="block text-neutral-400 mb-1">
                    Optional CA Trust Store (PEM Format) for Chain Validation:
                  </label>
                  <textarea
                    rows={4}
                    value={trustStorePemText}
                    onChange={(e) => setTrustStorePemText(e.target.value)}
                    placeholder="Optional root CA certificates for chain evaluation..."
                    className="w-full bg-[#121212] border border-[#333] p-2 text-neutral-200 font-mono text-xs rounded"
                  />
                </div>
              </div>
            )}

            {/* Private Key Safety Notice */}
            <div className="bg-amber-950/40 border border-amber-900/60 p-2.5 rounded text-[11px] text-amber-200 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <strong>Security Boundary Notice:</strong> Never upload private keys. The parser enforces an active rejection boundary against private key headers. Any secrets in <code>swanctl.conf</code> are automatically redacted and never persisted or logged.
              </div>
            </div>

            {/* Operator Attestation */}
            <label className="flex items-center gap-2 cursor-pointer pt-2">
              <input
                type="checkbox"
                checked={attestationConfirmed}
                onChange={(e) => setAttestationConfirmed(e.target.checked)}
                className="rounded border-[#333]"
              />
              <span className="text-neutral-300">
                I attest that this configuration/certificate artifact belongs to authorized gateway <code>{gatewayIdentity}</code> within scope <code>{authorizedScope}</code>.
              </span>
            </label>

            {formMessage && (
              <div
                className={`p-2.5 rounded text-xs ${
                  formMessage.type === "success"
                    ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                    : "bg-rose-950 text-rose-300 border border-rose-800"
                }`}
              >
                {formMessage.text}
              </div>
            )}

            <button
              onClick={() => {
                setFormMessage(null);
                if (importType === "config") {
                  importConfigMutation.mutate();
                } else {
                  importCertMutation.mutate();
                }
              }}
              disabled={
                !attestationConfirmed ||
                (importType === "config" && !configText.trim()) ||
                (importType === "cert" && !certPemText.trim()) ||
                importConfigMutation.isPending ||
                importCertMutation.isPending
              }
              className="px-4 py-2 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-mono text-xs font-bold rounded transition-colors"
            >
              {importConfigMutation.isPending || importCertMutation.isPending
                ? "Ingesting..."
                : importType === "config"
                ? "Ingest & Normalize Configuration"
                : "Ingest & Validate Certificate"}
            </button>
          </Card>
        </div>
      )}

      {/* INSPECTOR DRAWER: SNAPSHOT IR */}
      {selectedSnapshot && (
        <InspectorDrawer
          isOpen={true}
          onClose={() => setSelectedSnapshot(null)}
          title={`Snapshot IR: ${selectedSnapshot.gateway_identity}`}
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="bg-[#181818] p-3 rounded border border-[#2A2A2A] space-y-1">
              <div><strong className="text-neutral-400">Snapshot ID:</strong> {selectedSnapshot.id}</div>
              <div><strong className="text-neutral-400">Canonical SHA-256:</strong> {selectedSnapshot.canonical_digest}</div>
              <div><strong className="text-neutral-400">Baseline State:</strong> {selectedSnapshot.is_baseline ? `Authoritative Baseline v${selectedSnapshot.baseline_version}` : "Observed Snapshot"}</div>
              <div><strong className="text-neutral-400">Parser Version:</strong> {selectedSnapshot.parser_version}</div>
              <div><strong className="text-neutral-400">Source Type:</strong> {selectedSnapshot.source_type}</div>
              <div><strong className="text-neutral-400">Approved By:</strong> {selectedSnapshot.approved_by || "None"} ({selectedSnapshot.approval_reference || "N/A"})</div>
            </div>

            {selectedSnapshot.unsupported_directives?.length > 0 && (
              <div>
                <h4 className="font-bold text-amber-400 mb-1">Unsupported / Unmodeled Directives:</h4>
                <div className="bg-[#1A1412] border border-amber-900/60 p-2 rounded max-h-40 overflow-y-auto">
                  {selectedSnapshot.unsupported_directives.map((u, i) => (
                    <div key={i} className="text-neutral-300">
                      <code>{u.path}</code>: {String(u.value)}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div>
              <h4 className="font-bold text-neutral-300 mb-1">Normalized Configuration IR (Public Fields):</h4>
              <pre className="bg-[#111] p-3 rounded border border-[#222] text-neutral-300 overflow-x-auto text-[11px] max-h-96">
                {JSON.stringify(selectedSnapshot.normalized_ir, null, 2)}
              </pre>
            </div>

            {/* SOC Analyst Workflow Transitions */}
            <div className="pt-2 border-t border-[#2A2A2A] space-y-1.5">
              <span className="text-[10px] text-neutral-400 uppercase font-bold block">
                SOC Analyst Workflow Transitions
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <Link
                  href={`/monitoring?tab=fleet&gateway=${encodeURIComponent(selectedSnapshot.gateway_identity)}`}
                  className="flex items-center justify-center space-x-1.5 py-1.5 px-2 text-[11px] font-mono border border-neutral-700 bg-[#1F1F1F] hover:bg-[#2A2A2A] text-neutral-200 transition-colors"
                >
                  <Radio className="w-3.5 h-3.5 text-[#FF3D00]" />
                  <span>Telemetry</span>
                </Link>
                <Link
                  href={`/monitoring?tab=timeline&gateway=${encodeURIComponent(selectedSnapshot.gateway_identity)}`}
                  className="flex items-center justify-center space-x-1.5 py-1.5 px-2 text-[11px] font-mono border border-neutral-700 bg-[#1F1F1F] hover:bg-[#2A2A2A] text-neutral-200 transition-colors"
                >
                  <Layers className="w-3.5 h-3.5 text-blue-400" />
                  <span>Events</span>
                </Link>
                <Link
                  href="/analyses"
                  className="flex items-center justify-center space-x-1.5 py-1.5 px-2 text-[11px] font-mono border border-neutral-700 bg-[#1F1F1F] hover:bg-[#2A2A2A] text-neutral-200 transition-colors"
                >
                  <Activity className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Analyses</span>
                </Link>
              </div>
            </div>
          </div>
        </InspectorDrawer>
      )}

      {/* INSPECTOR DRAWER: CERTIFICATE DETAILS */}
      {selectedCert && (
        <InspectorDrawer
          isOpen={true}
          onClose={() => setSelectedCert(null)}
          title={`Certificate: ${selectedCert.subject_dn}`}
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="bg-[#181818] p-3 rounded border border-[#2A2A2A] space-y-1">
              {(selectedCert.id?.replace(/-/g, "").toLowerCase() === "7a2dc9ca442f4ce49b358a0acb4758e0" ||
                selectedCert.subject_dn?.includes("CN=vpn-gw-alpha.corp.internal")) && (
                <div className="mb-2">
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-800">
                    [DEMO / SEED DATA]
                  </span>
                </div>
              )}
              <div><strong className="text-neutral-400">Fingerprint (SHA-256):</strong> {selectedCert.sha256_fingerprint}</div>
              <div><strong className="text-neutral-400">Serial Number:</strong> {selectedCert.serial_number}</div>
              <div><strong className="text-neutral-400">Validity:</strong> {selectedCert.validity_status} ({selectedCert.days_until_expiry} days remaining)</div>
              <div><strong className="text-neutral-400">Valid Window:</strong> {new Date(selectedCert.not_valid_before).toUTCString()} to {new Date(selectedCert.not_valid_after).toUTCString()}</div>
              <div><strong className="text-neutral-400">Key Info:</strong> {selectedCert.public_key_algorithm} {selectedCert.public_key_bits} bits</div>
              <div><strong className="text-neutral-400">Signature Alg:</strong> {selectedCert.signature_algorithm}</div>
              <div><strong className="text-neutral-400">Is CA:</strong> {selectedCert.is_ca ? "YES" : "NO"}</div>
              <div><strong className="text-neutral-400">Connection Mapping:</strong> {selectedCert.associated_connection || "Unassociated"} ({selectedCert.identity_association_status})</div>
              <div><strong className="text-neutral-400">Chain Validation:</strong> {selectedCert.chain_validation_status}</div>
              <div><strong className="text-neutral-400">Revocation Status:</strong> {selectedCert.revocation_status}</div>
            </div>

            {selectedCert.subject_alt_names && Object.keys(selectedCert.subject_alt_names).length > 0 && (
              <div>
                <h4 className="font-bold text-neutral-300 mb-1">Subject Alternative Names (SANs):</h4>
                <div className="bg-[#141414] border border-[#2A2A2A] p-2.5 rounded space-y-1">
                  {Object.entries(selectedCert.subject_alt_names).map(([type, values]) => (
                    <div key={type} className="text-neutral-300">
                      <strong className="text-neutral-400 uppercase text-[10px]">{type}:</strong> {values.join(", ")}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div>
              <h4 className="font-bold text-neutral-300 mb-1">Issuer DN:</h4>
              <div className="bg-[#141414] border border-[#2A2A2A] p-2 rounded text-neutral-400 break-all">
                {selectedCert.issuer_dn}
              </div>
            </div>
          </div>
        </InspectorDrawer>
      )}
    </div>
  );
}

export default function InventoryPage() {
  return (
    <Suspense
      fallback={
        <div className="py-20 text-center font-mono text-xs text-neutral-500 animate-pulse">
          Loading Configuration & Certificate Inventory catalog...
        </div>
      }
    >
      <InventoryContent />
    </Suspense>
  );
}
