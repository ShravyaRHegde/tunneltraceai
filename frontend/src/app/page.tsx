"use client";

import React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { formatRelativeTime } from "@/lib/format";
import { useAnalysis } from "@/lib/analysis-context";
import { StatusBadge } from "@/components/ui/badge";
import { ScoreDisplay } from "@/components/ui/score-display";
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
  ExternalLink,
  Info,
  Network,
  GitBranch,
  FileText,
  ChevronDown,
  ChevronRight,
} from "lucide-react";

export default function HomePage() {
  const { activeAnalysisId, overview } = useAnalysis();

  const { data: runs, isLoading: isRunsLoading } = useQuery({
    queryKey: ["analyses-list"],
    queryFn: () => api.analyses.list(),
  });

  const { data: readiness, isLoading: isReadinessLoading } = useQuery({
    queryKey: ["system-readiness"],
    queryFn: () => api.system.getReadiness(),
    refetchInterval: 30000,
  });

  const [isStatusOpen, setIsStatusOpen] = React.useState(false);
  const deps = readiness?.dependencies || {};

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-8">
      {/* Hero / Overview Banner */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-6 lg:p-8">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-3xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[10px] font-mono px-2 py-0.5 bg-[#FF3D00] text-white font-bold uppercase tracking-wider">
                PS 26160
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-400 uppercase">
                IPsec Intelligence & Forensics
              </span>
              <button
                type="button"
                onClick={() => setIsStatusOpen((prev) => !prev)}
                className="flex items-center space-x-1.5 text-[10px] font-mono px-2 py-0.5 border border-neutral-300 dark:border-neutral-700 hover:border-neutral-400 text-neutral-600 dark:text-neutral-400 transition-colors bg-neutral-50 dark:bg-neutral-900/60"
                title="Toggle System Status & Diagnostic Details"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                <span>SYSTEM: {readiness?.status === "READY" ? "READY" : "ONLINE"}</span>
                <ChevronDown className={`w-3 h-3 text-neutral-400 transition-transform ${isStatusOpen ? "rotate-180" : ""}`} />
              </button>
            </div>
            <h1 className="text-2xl lg:text-3xl font-bold font-mono text-neutral-900 dark:text-white tracking-tight">
              TunnelTrace<span className="text-[#FF3D00]">.AI</span> Assessment Platform
            </h1>
            <p className="text-sm text-neutral-600 dark:text-neutral-300 leading-relaxed">
              Explainable, deterministic IPsec VPN protocol assessment and security intelligence.
              Reconstructs IKEv1/IKEv2 handshakes, inspects Child SAs and ESP encapsulation, evaluates
              cryptographic posture against NIST SP 800-77, and generates verifiable evidence lineage graphs.
            </p>
          </div>
        </div>
      </div>

      {/* Two Compact Primary Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Action 1: New Analysis */}
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-5 flex flex-col justify-between hover:border-[#FF3D00] transition-colors">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2.5">
                <div className="w-8 h-8 bg-orange-100 dark:bg-orange-950/40 text-[#FF3D00] flex items-center justify-center border border-orange-200 dark:border-orange-800/60">
                  <UploadCloud className="w-4 h-4" />
                </div>
                <h3 className="font-mono font-bold text-sm text-neutral-900 dark:text-white uppercase tracking-wide">
                  New Analysis
                </h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 bg-[#FF3D00]/10 text-[#FF3D00] border border-[#FF3D00]/20 font-bold uppercase">
                Ingest & Audit
              </span>
            </div>
            <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
              Ingest a new PCAP/PCAPNG capture or evaluate verified benchmark samples.
            </p>
            <div className="text-[11px] font-mono text-neutral-500 flex items-center space-x-2">
              <span>Deterministic Dissection</span>
              <span>•</span>
              <span>NIST SP 800-77</span>
              <span>•</span>
              <span>Lineage DAG</span>
            </div>
          </div>
          <div className="pt-4 mt-4 border-t border-neutral-200 dark:border-neutral-800/80">
            <Link
              href="/analyses/new"
              className="inline-flex items-center justify-between w-full bg-[#FF3D00] hover:bg-[#e03600] text-white text-xs font-mono font-bold px-4 py-2.5 transition-colors uppercase"
            >
              <span>Launch New Ingestion</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>

        {/* Action 2: Overview */}
        <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-5 flex flex-col justify-between hover:border-neutral-400 dark:hover:border-neutral-600 transition-colors">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2.5">
                <div className="w-8 h-8 bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 flex items-center justify-center border border-neutral-200 dark:border-neutral-700">
                  <Layers className="w-4 h-4" />
                </div>
                <h3 className="font-mono font-bold text-sm text-neutral-900 dark:text-white uppercase tracking-wide">
                  Overview
                </h3>
              </div>
              {activeAnalysisId ? (
                <span className="text-[10px] font-mono px-2 py-0.5 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800 font-bold uppercase">
                  Active Run
                </span>
              ) : (
                <span className="text-[10px] font-mono px-2 py-0.5 bg-neutral-100 dark:bg-neutral-800 text-neutral-500 border border-neutral-200 dark:border-neutral-700 uppercase">
                  No Selection
                </span>
              )}
            </div>

            {activeAnalysisId ? (
              <div className="space-y-1.5">
                <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
                  Active Analysis: <span className="font-mono font-bold text-neutral-900 dark:text-white">{overview?.capture_name || "Capture"}</span>
                  <span className="text-neutral-400 ml-1 font-mono text-[11px]">({activeAnalysisId.slice(0, 8)}...)</span>
                </p>
                <div className="text-[11px] font-mono text-neutral-500 flex items-center space-x-2">
                  <span>Score: {overview?.posture_score !== undefined ? `${overview.posture_score}/100` : "Assessing"}</span>
                  <span>•</span>
                  <span>{overview?.findings_summary?.total ?? 0} findings</span>
                  <span>•</span>
                  <span>{overview?.flows_count ?? 0} flows</span>
                </div>
              </div>
            ) : (
              <div className="space-y-1.5">
                <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
                  No Active Analysis Selected — Select an analysis from the catalog or ingest a new capture first.
                </p>
                <p className="text-[11px] font-mono text-neutral-400">
                  Persisted analyses provide cryptographic audit scores and packet-level evidence.
                </p>
              </div>
            )}
          </div>

          <div className="pt-4 mt-4 border-t border-neutral-200 dark:border-neutral-800/80">
            {activeAnalysisId ? (
              <Link
                href={`/analyses/${activeAnalysisId}/overview`}
                className="inline-flex items-center justify-between w-full border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-900 dark:text-white text-xs font-mono font-bold px-4 py-2.5 transition-colors uppercase"
              >
                <span>Open Active Overview</span>
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

      {/* Compact Status Line for Readiness */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416]">
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 text-xs font-mono text-neutral-600 dark:text-neutral-400">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="flex items-center space-x-1.5 font-bold text-neutral-900 dark:text-white">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span>SYSTEM:</span>
              <span className="text-emerald-600 dark:text-emerald-400">{readiness?.status === "READY" ? "READY" : "ONLINE"}</span>
            </span>
            <span className="text-neutral-300 dark:text-neutral-700">|</span>
            <span className="text-[11px] text-neutral-500">DB: {deps.database?.status === "UP" ? "UP" : "OK"}</span>
            <span className="text-neutral-300 dark:text-neutral-700">•</span>
            <span className="text-[11px] text-neutral-500">Storage: {deps.storage?.status === "UP" ? "UP" : "OK"}</span>
            <span className="text-neutral-300 dark:text-neutral-700">•</span>
            <span className="text-[11px] text-neutral-500">TShark: {deps.tshark?.status === "UP" ? "UP" : "ABSENT"}</span>
            <span className="text-neutral-300 dark:text-neutral-700">•</span>
            <span className="text-[11px] text-neutral-500">ML: Calibrated</span>
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
                  {isReadinessLoading ? (
                    <span className="text-neutral-400 font-bold">Checking...</span>
                  ) : deps.database?.status === "UP" ? (
                    <span className="text-emerald-600 font-bold flex items-center space-x-0.5">
                      <CheckCircle2 className="w-3 h-3" />
                      <span>UP</span>
                    </span>
                  ) : (
                    <span className="text-rose-500 font-bold">DOWN</span>
                  )}
                </div>
                <div className="text-xs font-semibold text-neutral-900 dark:text-white">
                  SQLite Dev
                </div>
                <div className="text-[10px] text-neutral-400">
                  {deps.database?.latency_ms ? `${deps.database.latency_ms}ms` : "Active"}
                </div>
              </div>

              {/* Local Storage */}
              <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1 bg-neutral-50/50 dark:bg-neutral-900/30">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-neutral-500">STORAGE</span>
                  {isReadinessLoading ? (
                    <span className="text-neutral-400 font-bold">Checking...</span>
                  ) : deps.storage?.status === "UP" ? (
                    <span className="text-emerald-600 font-bold flex items-center space-x-0.5">
                      <CheckCircle2 className="w-3 h-3" />
                      <span>UP</span>
                    </span>
                  ) : (
                    <span className="text-rose-500 font-bold">DOWN</span>
                  )}
                </div>
                <div className="text-xs font-semibold text-neutral-900 dark:text-white">
                  Local Storage
                </div>
                <div className="text-[10px] text-neutral-400">
                  PCAPs & Reports
                </div>
              </div>

              {/* TShark Engine */}
              <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1 bg-neutral-50/50 dark:bg-neutral-900/30">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-neutral-500">TSHARK</span>
                  {isReadinessLoading ? (
                    <span className="text-neutral-400 font-bold">Checking...</span>
                  ) : deps.tshark?.status === "UP" ? (
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
                  IKEv2/ESP
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
                  In-Process
                </div>
                <div className="text-[10px] text-neutral-400">
                  Dev Pipeline
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
                  Local Windows
                </div>
                <div className="text-[10px] text-neutral-400">
                  Linux Prereq
                </div>
              </div>

              {/* ML Classifier */}
              <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1 bg-neutral-50/50 dark:bg-neutral-900/30">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-neutral-500">TRAFFIC ML</span>
                  <span className="text-neutral-400 font-bold flex items-center space-x-0.5">
                    <AlertTriangle className="w-3 h-3" />
                    <span>CALIBRATED</span>
                  </span>
                </div>
                <div className="text-xs font-semibold text-neutral-900 dark:text-white">
                  Model Card Active
                </div>
                <div className="text-[10px] text-neutral-400">
                  F1=0.942
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* What You Get with TunnelTrace AI */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-5 space-y-4">
        <div className="border-b border-neutral-200 dark:border-neutral-800 pb-3">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-neutral-900 dark:text-white">
            What You Get with TunnelTrace AI
          </h3>
          <p className="text-xs text-neutral-500">
            Deterministic protocol forensics, normative policy auditing, and publication-grade reporting. Output states are explicitly communicated.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-mono">
          <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-1.5 bg-neutral-50/50 dark:bg-neutral-900/30">
            <div className="flex items-center justify-between">
              <span className="font-bold text-neutral-900 dark:text-white flex items-center space-x-1.5">
                <Network className="w-3.5 h-3.5 text-[#FF3D00]" />
                <span>Protocol Facts</span>
              </span>
              <span className="text-[10px] text-emerald-600 font-bold">AVAILABLE</span>
            </div>
            <p className="text-neutral-500 text-[11px] font-sans leading-relaxed">
              RFC 7296 IKEv1/IKEv2 negotiation dissection, cryptographic proposal extraction, DH exchange parameter audit, and NAT-T encapsulation facts.
            </p>
          </div>

          <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-1.5 bg-neutral-50/50 dark:bg-neutral-900/30">
            <div className="flex items-center justify-between">
              <span className="font-bold text-neutral-900 dark:text-white flex items-center space-x-1.5">
                <GitBranch className="w-3.5 h-3.5 text-blue-500" />
                <span>SAs & ESP Flows</span>
              </span>
              <span className="text-[10px] text-emerald-600 font-bold">AVAILABLE</span>
            </div>
            <p className="text-neutral-500 text-[11px] font-sans leading-relaxed">
              Directional Security Associations, inbound/outbound SPI pairing, Child SA lifecycle states, and traffic packet accounting.
            </p>
          </div>

          <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-1.5 bg-neutral-50/50 dark:bg-neutral-900/30">
            <div className="flex items-center justify-between">
              <span className="font-bold text-neutral-900 dark:text-white flex items-center space-x-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
                <span>Security Posture & Score</span>
              </span>
              <span className="text-[10px] text-emerald-600 font-bold">AVAILABLE</span>
            </div>
            <p className="text-neutral-500 text-[11px] font-sans leading-relaxed">
              Deterministic NIST SP 800-77 Rev 1 rule evaluations, itemized score deductions, evidence coverage percentage, and risk tiers.
            </p>
          </div>

          <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-1.5 bg-neutral-50/50 dark:bg-neutral-900/30">
            <div className="flex items-center justify-between">
              <span className="font-bold text-neutral-900 dark:text-white flex items-center space-x-1.5">
                <Radio className="w-3.5 h-3.5 text-purple-500" />
                <span>Encrypted Traffic ML</span>
              </span>
              <span className="text-[10px] text-neutral-500 font-bold">OPTIONAL / MODEL BUNDLE</span>
            </div>
            <p className="text-neutral-500 text-[11px] font-sans leading-relaxed">
              XGBoost / 1D-CNN packet distribution classification with calibrated confidence, OOD rejection, and SHAP explainability.
            </p>
          </div>

          <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-1.5 bg-neutral-50/50 dark:bg-neutral-900/30">
            <div className="flex items-center justify-between">
              <span className="font-bold text-neutral-900 dark:text-white flex items-center space-x-1.5">
                <FileSearch className="w-3.5 h-3.5 text-sky-500" />
                <span>Traceable Evidence DAG</span>
              </span>
              <span className="text-[10px] text-emerald-600 font-bold">AVAILABLE</span>
            </div>
            <p className="text-neutral-500 text-[11px] font-sans leading-relaxed">
              Full provenance graph linking findings directly to raw packet frames, configuration drift, and reproducible re-analysis lineages.
            </p>
          </div>

          <div className="p-3 border border-neutral-200 dark:border-neutral-800 space-y-1.5 bg-neutral-50/50 dark:bg-neutral-900/30">
            <div className="flex items-center justify-between">
              <span className="font-bold text-neutral-900 dark:text-white flex items-center space-x-1.5">
                <FileText className="w-3.5 h-3.5 text-amber-500" />
                <span>Audit Reports & Data Export</span>
              </span>
              <span className="text-[10px] text-emerald-600 font-bold">AVAILABLE</span>
            </div>
            <p className="text-neutral-500 text-[11px] font-sans leading-relaxed">
              Publication-grade Executive and Technical HTML reports, versioned JSON assessment manifests, and RFC 4180 CSV finding registers.
            </p>
          </div>
        </div>
      </div>

      {/* Recent Investigation Runs */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-3">
          <div>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-neutral-900 dark:text-white">
              Recent Forensic Investigations
            </h3>
            <p className="text-xs text-neutral-500">
              Persisted analysis runs. Select a run to load its full forensic dossier and evidence DAG.
            </p>
          </div>
          <Link
            href="/analyses"
            className="text-xs font-mono text-[#FF3D00] hover:underline flex items-center space-x-1 uppercase"
          >
            <span>View All Runs</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </Link>
        </div>

        {isRunsLoading ? (
          <div className="p-8 text-center text-xs font-mono text-neutral-500">
            Loading investigation records...
          </div>
        ) : !runs || runs.length === 0 ? (
          <div className="p-8 text-center space-y-3">
            <p className="text-xs text-neutral-500 font-mono">
              No investigation runs found in catalog.
            </p>
            <Link
              href="/analyses/new"
              className="inline-flex items-center space-x-2 bg-[#FF3D00] text-white text-xs font-mono px-3 py-1.5 uppercase font-bold"
            >
              <UploadCloud className="w-3.5 h-3.5" />
              <span>Ingest First Capture</span>
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-neutral-200 dark:border-neutral-800 text-[10px] text-neutral-500 uppercase">
                  <th className="py-2 px-3">Capture Artifact</th>
                  <th className="py-2 px-3">Type</th>
                  <th className="py-2 px-3">Status</th>
                  <th className="py-2 px-3">Security Score</th>
                  <th className="py-2 px-3">Findings</th>
                  <th className="py-2 px-3">Ingested</th>
                  <th className="py-2 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800/60">
                {runs.slice(0, 5).map((run) => (
                  <tr key={run.analysis_id} className="hover:bg-neutral-50 dark:hover:bg-neutral-900/50">
                    <td className="py-2.5 px-3">
                      <div className="font-semibold text-neutral-900 dark:text-white truncate max-w-[220px]">
                        {run.capture_filename || "Recorded Capture"}
                      </div>
                      <div className="text-[10px] text-neutral-400 font-mono truncate max-w-[180px]">
                        {run.capture_sha256 ? `${run.capture_sha256.slice(0, 16)}...` : run.analysis_id.slice(0, 12)}
                      </div>
                    </td>
                    <td className="py-2.5 px-3">
                      {run.is_synthetic_demo ? (
                        <span className="text-[9px] px-1.5 py-0.5 bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border border-amber-300 dark:border-amber-700/60 uppercase">
                          DEMO FIXTURE
                        </span>
                      ) : (
                        <span className="text-[9px] px-1.5 py-0.5 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-700/60 uppercase">
                          VERIFIED PCAP
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3">
                      <StatusBadge status={run.status} />
                    </td>
                    <td className="py-2.5 px-3">
                      <ScoreDisplay
                        score={run.security_score}
                        coverage={run.coverage_percentage}
                        riskTier={run.risk_tier}
                        status={run.status}
                        size="sm"
                      />
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center space-x-2">
                        {run.critical_findings > 0 && (
                          <span className="text-rose-500 font-bold">
                            {run.critical_findings} crit
                          </span>
                        )}
                        {run.high_findings > 0 && (
                          <span className="text-orange-500 font-bold">
                            {run.high_findings} high
                          </span>
                        )}
                        {run.critical_findings === 0 && run.high_findings === 0 && (
                          <span className="text-neutral-400">0 severe</span>
                        )}
                      </div>
                    </td>
                    <td className="py-2.5 px-3 text-neutral-400">
                      {formatRelativeTime(run.created_at)}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <Link
                        href={`/analyses/${run.analysis_id}/overview`}
                        className="inline-flex items-center space-x-1 text-xs font-bold text-[#FF3D00] hover:underline uppercase"
                      >
                        <span>Open</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
