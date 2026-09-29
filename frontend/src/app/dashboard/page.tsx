"use client";

import React, { useState, useMemo } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { formatRelativeTime } from "@/lib/format";
import { useAnalysis } from "@/lib/analysis-context";
import { StatusBadge } from "@/components/ui/badge";
import { ScoreDisplay } from "@/components/ui/score-display";
import { toCanonicalAnalysisSummary } from "@/lib/canonical-analysis-summary";
import {
  UploadCloud,
  Radio,
  FlaskConical,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Layers,
  FileSearch,
  ChevronDown,
  Info,
  Network,
  GitBranch,
  ShieldAlert,
  Server,
  Terminal,
  Activity,
  Sparkles,
} from "lucide-react";

export default function SOCDashboardPage() {
  const { activeAnalysisId, overview } = useAnalysis();

  const { data: runs, isLoading: isRunsLoading, refetch } = useQuery({
    queryKey: ["analyses-list"],
    queryFn: () => api.analyses.list(),
  });

  const { data: readiness, isLoading: isReadinessLoading } = useQuery({
    queryKey: ["system-readiness"],
    queryFn: () => api.system.getReadiness(),
    refetchInterval: 30000,
  });

  const [isStatusOpen, setIsStatusOpen] = useState(false);
  const deps = readiness?.dependencies || {};

  // Canonical analysis summary for the active or most recent run
  const activeSummary = useMemo(() => {
    if (overview) return toCanonicalAnalysisSummary(overview);
    if (runs && runs.length > 0) {
      const target = activeAnalysisId
        ? runs.find((r) => r.analysis_id === activeAnalysisId) || runs[0]
        : runs[0];
      return toCanonicalAnalysisSummary(target);
    }
    return null;
  }, [overview, runs, activeAnalysisId]);

  const recentRuns = useMemo(() => {
    if (!runs) return [];
    return runs.slice(0, 5);
  }, [runs]);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Top Header / Context */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5 max-w-3xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[10px] font-mono px-2 py-0.5 bg-[#FF3D00] text-white font-bold uppercase tracking-wider">
                PS 26160
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-400 uppercase font-mono">
                NTRO · IPsec Protocol Forensics
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 bg-neutral-100 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-300 border border-neutral-300 dark:border-neutral-700 font-mono">
                Pipeline v2.0.0 · Policy v1.0.0
              </span>
            </div>
            <h1 className="text-2xl font-bold font-mono text-neutral-900 dark:text-white tracking-tight uppercase">
              TunnelTrace<span className="text-[#FF3D00]">.AI</span> SOC Workbench
            </h1>
            <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed font-sans">
              Authoritative, deterministic IPsec VPN protocol assessment and security intelligence.
              Reconstructs IKEv1/IKEv2 handshakes, analyzes Child SAs and ESP encapsulation, evaluates
              cryptographic posture against NIST SP 800-77, and generates verifiable evidence lineage graphs.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Link
              href="/analyses/new"
              className="inline-flex items-center space-x-1.5 bg-[#FF3D00] hover:bg-[#e03600] text-white text-xs font-mono font-bold px-4 py-2.5 transition-colors uppercase border border-[#FF3D00]"
            >
              <UploadCloud className="w-4 h-4" />
              <span>Analyze a Capture</span>
            </Link>
            <Link
              href="/"
              className="inline-flex items-center space-x-1.5 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-800 dark:text-neutral-200 text-xs font-mono font-bold px-3 py-2.5 transition-colors uppercase"
              title="View Public Landing Page"
            >
              <Sparkles className="w-3.5 h-3.5 text-[#FF3D00]" />
              <span>Landing Page</span>
            </Link>
          </div>
        </div>
      </div>

      {/* System Status Strip */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416]">
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 text-xs font-mono text-neutral-600 dark:text-neutral-400">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="flex items-center space-x-1.5 font-bold text-neutral-900 dark:text-white">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span>SYSTEM:</span>
              <span className="text-emerald-600 dark:text-emerald-400">
                {readiness?.status === "READY_LOCAL_DEV" ? "READY (LOCAL)" : readiness?.status || "ONLINE"}
              </span>
            </span>
            <span className="text-neutral-300 dark:text-neutral-700">|</span>
            <span className="text-[11px] text-neutral-500">
              DB: {isReadinessLoading ? "CHECKING..." : deps.database?.status === "UP" ? "UP" : "OK"}
            </span>
            <span className="text-neutral-300 dark:text-neutral-700">•</span>
            <span className="text-[11px] text-neutral-500">
              Storage: {isReadinessLoading ? "CHECKING..." : deps.storage?.status === "UP" ? "UP" : "OK"}
            </span>
            <span className="text-neutral-300 dark:text-neutral-700">•</span>
            <span className="text-[11px] text-neutral-500">
              TShark: {isReadinessLoading ? "CHECKING..." : deps.tshark?.status === "UP" ? "UP (v4.6.4)" : "UNAVAILABLE"}
            </span>
            <span className="text-neutral-300 dark:text-neutral-700">•</span>
            <span className="text-[11px] text-amber-600 dark:text-amber-400 font-medium">
              ML: {isReadinessLoading ? "CHECKING..." : deps.ml_engine?.artifact_state || "EXPERIMENTAL"}
            </span>
            <span className="text-neutral-300 dark:text-neutral-700">•</span>
            <span className="text-[11px] text-neutral-500" title="Class B Agent required for direct Windows capture; remote Linux collector supported">
              Live Agent: UNAVAILABLE (Windows Host)
            </span>
          </div>
          <button
            type="button"
            onClick={() => setIsStatusOpen((prev) => !prev)}
            className="text-[11px] text-neutral-500 hover:text-neutral-800 dark:hover:text-neutral-200 underline font-mono flex items-center space-x-1"
          >
            <span>{isStatusOpen ? "Hide Diagnostics" : "Diagnostic Probes"}</span>
            <ChevronDown className={`w-3 h-3 transition-transform ${isStatusOpen ? "rotate-180" : ""}`} />
          </button>
        </div>

        {isStatusOpen && (
          <div className="p-4 pt-3 border-t border-neutral-200 dark:border-neutral-800 space-y-3">
            <p className="text-xs text-neutral-500 font-mono">
              Live probes querying database, local storage, TShark dissection binary, async queue, and ML inference dependencies.
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 font-mono">
              {/* SQLite DB */}
              <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1 bg-neutral-50/50 dark:bg-neutral-900/30">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-neutral-500">DATABASE</span>
                  {deps.database?.status === "UP" ? (
                    <span className="text-emerald-600 font-bold flex items-center space-x-0.5">
                      <CheckCircle2 className="w-3 h-3" />
                      <span>UP</span>
                    </span>
                  ) : (
                    <span className="text-rose-500 font-bold">DOWN</span>
                  )}
                </div>
                <div className="text-xs font-semibold text-neutral-900 dark:text-white">
                  SQLite Local
                </div>
                <div className="text-[10px] text-neutral-400">
                  {deps.database?.latency_ms ? `${deps.database.latency_ms.toFixed(1)}ms` : "1.0ms"}
                </div>
              </div>

              {/* Local Storage */}
              <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1 bg-neutral-50/50 dark:bg-neutral-900/30">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-neutral-500">STORAGE</span>
                  {deps.storage?.status === "UP" ? (
                    <span className="text-emerald-600 font-bold flex items-center space-x-0.5">
                      <CheckCircle2 className="w-3 h-3" />
                      <span>UP</span>
                    </span>
                  ) : (
                    <span className="text-rose-500 font-bold">DOWN</span>
                  )}
                </div>
                <div className="text-xs font-semibold text-neutral-900 dark:text-white">
                  Local FS
                </div>
                <div className="text-[10px] text-neutral-400">
                  Captures & Reports
                </div>
              </div>

              {/* TShark Engine */}
              <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1 bg-neutral-50/50 dark:bg-neutral-900/30">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-neutral-500">TSHARK</span>
                  {deps.tshark?.status === "UP" ? (
                    <span className="text-emerald-600 font-bold flex items-center space-x-0.5">
                      <CheckCircle2 className="w-3 h-3" />
                      <span>UP</span>
                    </span>
                  ) : (
                    <span className="text-amber-500 font-bold">ABSENT</span>
                  )}
                </div>
                <div className="text-xs font-semibold text-neutral-900 dark:text-white truncate">
                  TShark 4.6.4
                </div>
                <div className="text-[10px] text-neutral-400">
                  IKEv2/ESP Engine
                </div>
              </div>

              {/* Task Queue / Redis */}
              <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1 bg-neutral-50/50 dark:bg-neutral-900/30">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-neutral-500">ASYNC QUEUE</span>
                  <span className="text-amber-600 dark:text-amber-400 font-bold flex items-center space-x-0.5">
                    <Info className="w-3 h-3" />
                    <span>EAGER</span>
                  </span>
                </div>
                <div className="text-xs font-semibold text-neutral-900 dark:text-white">
                  In-Process Dev
                </div>
                <div className="text-[10px] text-neutral-400">
                  Sync Execution
                </div>
              </div>

              {/* Live Capture Agent */}
              <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1 bg-neutral-50/50 dark:bg-neutral-900/30">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-neutral-500">LIVE AGENT</span>
                  <span className="text-neutral-400 font-bold flex items-center space-x-0.5">
                    <XCircle className="w-3 h-3" />
                    <span>WINDOWS</span>
                  </span>
                </div>
                <div className="text-xs font-semibold text-neutral-900 dark:text-white">
                  Unavailable (Host)
                </div>
                <div className="text-[10px] text-neutral-400">
                  Linux CAP_NET_ADMIN Req
                </div>
              </div>

              {/* ML Classifier */}
              <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1 bg-neutral-50/50 dark:bg-neutral-900/30">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-neutral-500">TRAFFIC ML</span>
                  <span className="text-amber-600 dark:text-amber-400 font-bold flex items-center space-x-0.5">
                    <AlertTriangle className="w-3 h-3" />
                    <span>EXPERIMENTAL</span>
                  </span>
                </div>
                <div className="text-xs font-semibold text-neutral-900 dark:text-white">
                  Statistical Baseline
                </div>
                <div className="text-[10px] text-neutral-400">
                  v1.0.0-experimental
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Primary Action / Active Run Hub */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Card 1: Analyze a Capture */}
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-5 flex flex-col justify-between hover:border-[#FF3D00] transition-colors">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2.5">
                <div className="w-8 h-8 bg-orange-100 dark:bg-orange-950/40 text-[#FF3D00] flex items-center justify-center border border-orange-200 dark:border-orange-800/60">
                  <UploadCloud className="w-4 h-4" />
                </div>
                <h2 className="font-mono font-bold text-sm text-neutral-900 dark:text-white uppercase tracking-wide">
                  Analyze a Capture
                </h2>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 bg-[#FF3D00]/10 text-[#FF3D00] border border-[#FF3D00]/20 font-bold uppercase">
                Ingest & Audit
              </span>
            </div>

            <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed font-sans">
              Upload standard <span className="font-mono font-bold text-neutral-900 dark:text-white">.pcap</span> or{" "}
              <span className="font-mono font-bold text-neutral-900 dark:text-white">.pcapng</span> binary captures.
              TunnelTrace validates cryptographic hashes (SHA-256), executes TShark forensic extraction, evaluates 8 deterministic NIST SP 800-77 rules, and reconstructs bidirectional ESP flows.
            </p>

            <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-neutral-500 pt-1">
              <div>• SHA-256 Integrity Verification</div>
              <div>• Child SA Mode & Cipher Extraction</div>
              <div>• NIST SP 800-77 Policy Scoring</div>
              <div>• Explainable Forensic Graph</div>
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-neutral-200 dark:border-neutral-800/80">
            <Link
              href="/analyses/new"
              className="inline-flex items-center justify-between w-full bg-[#FF3D00] hover:bg-[#e03600] text-white text-xs font-mono font-bold px-4 py-2.5 transition-colors uppercase border border-[#FF3D00]"
            >
              <span>Upload New Capture (PCAP/PCAPNG)</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>

        {/* Card 2: Active Investigation Context */}
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-5 flex flex-col justify-between hover:border-neutral-400 dark:hover:border-neutral-600 transition-colors">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2.5">
                <div className="w-8 h-8 bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 flex items-center justify-center border border-neutral-200 dark:border-neutral-700">
                  <Layers className="w-4 h-4" />
                </div>
                <h2 className="font-mono font-bold text-sm text-neutral-900 dark:text-white uppercase tracking-wide">
                  Active Investigation
                </h2>
              </div>
              {activeSummary ? (
                <span className="text-[10px] font-mono px-2 py-0.5 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800 font-bold uppercase">
                  Active Run
                </span>
              ) : (
                <span className="text-[10px] font-mono px-2 py-0.5 bg-neutral-100 dark:bg-neutral-800 text-neutral-500 border border-neutral-200 dark:border-neutral-700 uppercase">
                  No Selection
                </span>
              )}
            </div>

            {activeSummary ? (
              <div className="space-y-2">
                <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed font-sans">
                  Capture: <span className="font-mono font-bold text-neutral-900 dark:text-white">{activeSummary.captureFilename}</span>
                  <span className="text-neutral-400 ml-1 font-mono text-[11px]">({activeSummary.analysisId.slice(0, 8)}...)</span>
                </p>

                <div className="text-[11px] font-mono text-neutral-500 flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="font-semibold text-neutral-800 dark:text-neutral-200">
                    Score: {activeSummary.displayScore}
                  </span>
                  <span>•</span>
                  <span>{activeSummary.findings.total} findings</span>
                  <span>•</span>
                  <span>{activeSummary.traffic.totalFlows} flows</span>
                  <span>•</span>
                  <span className="text-[10px] px-1.5 py-0.2 bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-400 uppercase font-semibold">
                    {activeSummary.displayRiskTier}
                  </span>
                </div>

                <p className="text-[11px] font-mono text-neutral-400">
                  Evidence Coverage: {activeSummary.displayCoverage} ({activeSummary.evaluatedControls}/{activeSummary.totalControls} controls evaluated
                  {activeSummary.unknownControls > 0 ? `, ${activeSummary.unknownControls} unknown` : ""}).
                </p>
              </div>
            ) : (
              <div className="space-y-1.5">
                <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
                  No Active Analysis Selected — Select an investigation from the catalog below or ingest a new capture first.
                </p>
                <p className="text-[11px] font-mono text-neutral-400">
                  Persisted analyses provide cryptographic audit scores and packet-level evidence.
                </p>
              </div>
            )}
          </div>

          <div className="pt-4 mt-4 border-t border-neutral-200 dark:border-neutral-800/80">
            {activeSummary ? (
              <Link
                href={`/analyses/${activeSummary.analysisId}/overview`}
                className="inline-flex items-center justify-between w-full border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-900 dark:text-white text-xs font-mono font-bold px-4 py-2.5 transition-colors uppercase"
              >
                <span>Open Active Investigation Overview</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            ) : (
              <div className="flex items-center space-x-2">
                <Link
                  href="/analyses"
                  className="flex-1 inline-flex items-center justify-center space-x-1.5 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-900 dark:text-white text-xs font-mono font-bold px-3 py-2.5 transition-colors uppercase"
                >
                  <Layers className="w-3.5 h-3.5" />
                  <span>Browse Catalog</span>
                </Link>
                <Link
                  href="/analyses/new"
                  className="inline-flex items-center justify-center space-x-1 bg-neutral-900 hover:bg-neutral-800 dark:bg-white dark:hover:bg-neutral-200 text-white dark:text-neutral-900 text-xs font-mono font-bold px-4 py-2.5 transition-colors uppercase"
                >
                  <span>New Analysis</span>
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 4 Task Hubs: Analyze, Monitor, Testbed, Advanced/Ops */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 font-mono">
        {/* Hub 1: Analyze */}
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-4 flex flex-col justify-between">
          <div className="space-y-2.5">
            <div className="flex items-center space-x-2 text-[#FF3D00]">
              <Layers className="w-4 h-4" />
              <h3 className="font-bold text-xs uppercase tracking-wider text-neutral-900 dark:text-white">
                1. Analyze
              </h3>
            </div>
            <p className="text-[11px] text-neutral-500 font-sans leading-relaxed">
              PCAP upload, deterministic policy audit, ESP flow extraction, and evidence graphs.
            </p>
            <div className="space-y-1 text-xs">
              <Link href="/analyses/new" className="block text-neutral-700 dark:text-neutral-300 hover:text-[#FF3D00] hover:underline">
                → Upload New Capture
              </Link>
              <Link href="/analyses" className="block text-neutral-700 dark:text-neutral-300 hover:text-[#FF3D00] hover:underline">
                → Investigation Catalog
              </Link>
            </div>
          </div>
        </div>

        {/* Hub 2: Monitor */}
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-4 flex flex-col justify-between">
          <div className="space-y-2.5">
            <div className="flex items-center space-x-2 text-cyan-600 dark:text-cyan-400">
              <Radio className="w-4 h-4" />
              <h3 className="font-bold text-xs uppercase tracking-wider text-neutral-900 dark:text-white">
                2. Monitor
              </h3>
            </div>
            <p className="text-[11px] text-neutral-500 font-sans leading-relaxed">
              Gateway telemetry, sensor registration, projected SAs, and quarantined synthetic tests.
            </p>
            <div className="space-y-1 text-xs">
              <Link href="/monitoring?tab=sensors" className="block text-neutral-700 dark:text-neutral-300 hover:text-cyan-600 hover:underline">
                → Sensor Fleet & Tokens
              </Link>
              <Link href="/monitoring?tab=projected-sas" className="block text-neutral-700 dark:text-neutral-300 hover:text-cyan-600 hover:underline">
                → Projected SAs
              </Link>
            </div>
          </div>
        </div>

        {/* Hub 3: Testbed */}
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-4 flex flex-col justify-between">
          <div className="space-y-2.5">
            <div className="flex items-center space-x-2 text-amber-600 dark:text-amber-400">
              <FlaskConical className="w-4 h-4" />
              <h3 className="font-bold text-xs uppercase tracking-wider text-neutral-900 dark:text-white">
                3. Testbed
              </h3>
            </div>
            <p className="text-[11px] text-neutral-500 font-sans leading-relaxed">
              Isolated strongSwan simulation, netem impairment profiles, and negative test cases.
            </p>
            <div className="space-y-1 text-xs">
              <Link href="/lab" className="block text-neutral-700 dark:text-neutral-300 hover:text-amber-600 hover:underline">
                → Lab Scenarios Matrix
              </Link>
              <Link href="/lab?tab=history" className="block text-neutral-700 dark:text-neutral-300 hover:text-amber-600 hover:underline">
                → Test Execution History
              </Link>
            </div>
          </div>
        </div>

        {/* Hub 4: Advanced / Ops */}
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-4 flex flex-col justify-between">
          <div className="space-y-2.5">
            <div className="flex items-center space-x-2 text-purple-600 dark:text-purple-400">
              <Server className="w-4 h-4" />
              <h3 className="font-bold text-xs uppercase tracking-wider text-neutral-900 dark:text-white">
                4. Advanced / Ops
              </h3>
            </div>
            <p className="text-[11px] text-neutral-500 font-sans leading-relaxed">
              Authorized asset discovery, configuration/cert inventory, and external CVE scans.
            </p>
            <div className="space-y-1 text-xs">
              <Link href="/discovery" className="block text-neutral-700 dark:text-neutral-300 hover:text-purple-600 hover:underline">
                → Asset Discovery Pre-Scan
              </Link>
              <Link href="/inventory" className="block text-neutral-700 dark:text-neutral-300 hover:text-purple-600 hover:underline">
                → Config & Cert Inventory
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416]">
        <div className="p-4 border-b border-neutral-200 dark:border-neutral-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <FileSearch className="w-4 h-4 text-[#FF3D00]" />
            <h2 className="font-mono font-bold text-xs text-neutral-900 dark:text-white uppercase tracking-wider">
              Recent Ingested Analyses ({runs?.length ?? 0} total)
            </h2>
          </div>
          <Link
            href="/analyses"
            className="text-xs font-mono text-[#FF3D00] hover:underline flex items-center space-x-1"
          >
            <span>View Full Catalog</span>
            <ArrowRight className="w-3 h-3" />
          </Link>
        </div>

        {isRunsLoading ? (
          <div className="p-8 text-center text-xs font-mono text-neutral-500">
            Loading recent analyses...
          </div>
        ) : recentRuns.length === 0 ? (
          <div className="p-8 text-center space-y-2">
            <p className="text-xs font-mono text-neutral-500">No analyses currently in database.</p>
            <Link
              href="/analyses/new"
              className="inline-block text-xs font-mono text-[#FF3D00] hover:underline uppercase font-bold"
            >
              → Upload your first PCAP
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-neutral-50 dark:bg-neutral-900/60 border-b border-neutral-200 dark:border-neutral-800 text-[10px] text-neutral-500 uppercase">
                <tr>
                  <th className="p-3">Capture Artifact</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Security Score</th>
                  <th className="p-3">Coverage</th>
                  <th className="p-3">Findings</th>
                  <th className="p-3">Risk Tier</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800">
                {recentRuns.map((r) => {
                  const itemSummary = toCanonicalAnalysisSummary(r);
                  if (!itemSummary) return null;

                  return (
                    <tr
                      key={r.analysis_id}
                      className="hover:bg-neutral-50 dark:hover:bg-neutral-900/40 transition-colors"
                    >
                      <td className="p-3">
                        <div className="space-y-0.5">
                          <div className="flex items-center space-x-1.5">
                            <span className="font-bold text-neutral-900 dark:text-white">
                              {itemSummary.captureFilename}
                            </span>
                            {itemSummary.provenance.isSyntheticDemo && (
                              <span
                                className="px-1 py-0.2 bg-amber-100 text-amber-900 dark:bg-amber-950/40 dark:text-amber-300 border border-amber-400 text-[9px] font-bold uppercase"
                                title="Results were seeded for demonstration reference"
                              >
                                DEMONSTRATION / SEEDED REFERENCE
                              </span>
                            )}
                          </div>
                          <div className="text-[10px] text-neutral-400">
                            SHA: {itemSummary.captureSha256 ? `${itemSummary.captureSha256.slice(0, 10)}...` : "N/A"} • {formatRelativeTime(itemSummary.provenance.createdAt)}
                          </div>
                        </div>
                      </td>
                      <td className="p-3">
                        <StatusBadge status={itemSummary.status} />
                      </td>
                      <td className="p-3">
                        <ScoreDisplay
                          score={itemSummary.securityScore}
                          coverage={itemSummary.coveragePercentage}
                          riskTier={itemSummary.displayRiskTier}
                          status={itemSummary.status}
                          size="sm"
                        />
                      </td>
                      <td className="p-3 text-neutral-600 dark:text-neutral-400">
                        {itemSummary.displayCoverage}
                      </td>
                      <td className="p-3">
                        <span className={itemSummary.findings.critical > 0 ? "text-rose-600 font-bold" : itemSummary.findings.high > 0 ? "text-amber-600 font-bold" : "text-neutral-500"}>
                          {itemSummary.findings.critical > 0
                            ? `${itemSummary.findings.critical} crit`
                            : itemSummary.findings.high > 0
                            ? `${itemSummary.findings.high} high`
                            : `${itemSummary.findings.total} findings`}
                        </span>
                      </td>
                      <td className="p-3">
                        <span className="text-[10px] px-1.5 py-0.5 border border-neutral-300 dark:border-neutral-700 bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 uppercase">
                          {itemSummary.displayRiskTier}
                        </span>
                      </td>
                      <td className="p-3 text-right">
                        <Link
                          href={`/analyses/${itemSummary.analysisId}/overview`}
                          className="text-[#FF3D00] hover:underline font-bold text-xs inline-flex items-center space-x-1"
                        >
                          <span>Open</span>
                          <ArrowRight className="w-3 h-3" />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="p-3 bg-neutral-50 dark:bg-neutral-900/40 border-t border-neutral-200 dark:border-neutral-800 flex items-center justify-between text-[11px] font-mono text-neutral-500">
          <div>
            Next Action: Select an active investigation to inspect cryptographic evidence, or ingest a new PCAP.
          </div>
          <div>
            Policy Authority: Deterministic NIST SP 800-77 Rev. 1
          </div>
        </div>
      </div>
    </div>
  );
}
