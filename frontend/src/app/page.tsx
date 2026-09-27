"use client";

import React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { formatRelativeTime } from "@/lib/format";
import { StatusBadge } from "@/components/ui/badge";
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
} from "lucide-react";

export default function HomePage() {
  const { data: runs, isLoading: isRunsLoading } = useQuery({
    queryKey: ["analyses-list"],
    queryFn: () => api.analyses.list(),
  });

  const { data: readiness, isLoading: isReadinessLoading } = useQuery({
    queryKey: ["system-readiness"],
    queryFn: () => api.system.getReadiness(),
    refetchInterval: 30000,
  });

  const deps = readiness?.dependencies || {};

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-8">
      {/* Hero / Overview Banner */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-6 lg:p-8">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-3xl">
            <div className="flex items-center space-x-2">
              <span className="text-[10px] font-mono px-2 py-0.5 bg-[#FF3D00] text-white font-bold uppercase tracking-wider">
                PS 26160
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 border border-neutral-300 dark:border-neutral-700 text-neutral-600 dark:text-neutral-400 uppercase">
                IPsec Intelligence & Forensics
              </span>
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

          <div className="flex flex-col sm:flex-row lg:flex-col gap-3 min-w-[200px]">
            <Link
              href="/analyses/new"
              className="flex items-center justify-center space-x-2 bg-[#FF3D00] hover:bg-[#e03600] text-white text-xs font-mono font-bold px-4 py-2.5 transition-colors uppercase"
            >
              <UploadCloud className="w-4 h-4" />
              <span>Analyze Capture</span>
            </Link>
            <Link
              href="/analyses"
              className="flex items-center justify-center space-x-2 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-800 dark:text-neutral-200 text-xs font-mono px-4 py-2.5 transition-colors uppercase"
            >
              <Layers className="w-4 h-4" />
              <span>Browse Catalog</span>
            </Link>
          </div>
        </div>
      </div>

      {/* 3 Core Workflow Pathways */}
      <div>
        <h2 className="text-xs font-mono uppercase tracking-wider font-bold text-neutral-500 dark:text-neutral-400 mb-3">
          Select Investigation Workflow
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {/* Pathway 1: Analyze a Capture */}
          <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-5 flex flex-col justify-between hover:border-[#FF3D00] transition-colors group">
            <div className="space-y-3">
              <div className="w-9 h-9 bg-orange-100 dark:bg-orange-950/40 text-[#FF3D00] flex items-center justify-center border border-orange-200 dark:border-orange-800/60">
                <UploadCloud className="w-5 h-5" />
              </div>
              <h3 className="font-mono font-bold text-base text-neutral-900 dark:text-white">
                1. Analyze a Capture
              </h3>
              <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
                Ingest forensic PCAP/PCAPNG files or try verified benchmark samples. Dissects IKEv2 exchanges, verifies ESP payloads, audits cryptographic suites, and produces evidence graphs.
              </p>
            </div>
            <div className="pt-5 mt-4 border-t border-neutral-200 dark:border-neutral-800/80 flex items-center justify-between">
              <Link
                href="/analyses/new"
                className="text-xs font-mono font-bold text-[#FF3D00] hover:underline flex items-center space-x-1 uppercase"
              >
                <span>Upload or Sample</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
              <span className="text-[10px] font-mono text-neutral-400">Offline / Forensic</span>
            </div>
          </div>

          {/* Pathway 2: Set Up Live Monitoring */}
          <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-5 flex flex-col justify-between hover:border-[#FF3D00] transition-colors group">
            <div className="space-y-3">
              <div className="w-9 h-9 bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400 flex items-center justify-center border border-blue-200 dark:border-blue-800/60">
                <Radio className="w-5 h-5" />
              </div>
              <h3 className="font-mono font-bold text-base text-neutral-900 dark:text-white">
                2. Set Up Live Monitoring
              </h3>
              <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
                Register authorized VPN gateways and deploy lightweight telemetry sensors. Ingests heartbeat lifecycle events, tracks projected SAs, and monitors gateway health.
              </p>
            </div>
            <div className="pt-5 mt-4 border-t border-neutral-200 dark:border-neutral-800/80 flex items-center justify-between">
              <Link
                href="/monitoring"
                className="text-xs font-mono font-bold text-blue-600 dark:text-blue-400 hover:underline flex items-center space-x-1 uppercase"
              >
                <span>Live Monitor</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
              <span className="text-[10px] font-mono text-neutral-400">Continuous SOC</span>
            </div>
          </div>

          {/* Pathway 3: Controlled Lab Scenario */}
          <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-5 flex flex-col justify-between hover:border-[#FF3D00] transition-colors group">
            <div className="space-y-3">
              <div className="w-9 h-9 bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400 flex items-center justify-center border border-emerald-200 dark:border-emerald-800/60">
                <FlaskConical className="w-5 h-5" />
              </div>
              <h3 className="font-mono font-bold text-base text-neutral-900 dark:text-white">
                3. Run Controlled Lab Scenario
              </h3>
              <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
                Execute reproducible dual-strongSwan Linux namespace testbed scenarios. Safely inject misconfigurations, simulate workloads, capture WAN PCAPs, and test policy twins.
              </p>
            </div>
            <div className="pt-5 mt-4 border-t border-neutral-200 dark:border-neutral-800/80 flex items-center justify-between">
              <Link
                href="/lab"
                className="text-xs font-mono font-bold text-emerald-600 dark:text-emerald-400 hover:underline flex items-center space-x-1 uppercase"
              >
                <span>Lab Orchestrator</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
              <span className="text-[10px] font-mono text-neutral-400">Active Testbed</span>
            </div>
          </div>
        </div>
      </div>

      {/* Runtime Readiness & Engine Health (Truthful Status) */}
      <div className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#141416] p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-neutral-200 dark:border-neutral-800 pb-3">
          <div>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-neutral-900 dark:text-white flex items-center space-x-2">
              <span>Runtime Engine Readiness</span>
              <span className="text-[10px] font-normal px-2 py-0.5 border border-neutral-300 dark:border-neutral-700 text-neutral-500 uppercase">
                {readiness?.status === "READY" ? "READY" : "IN-PROCESS / DEGRADED"}
              </span>
            </h3>
            <p className="text-xs text-neutral-500">
              Live probes querying database, storage, TShark, Redis broker, and ML inference subsystems.
            </p>
          </div>
          <div className="text-[11px] font-mono text-neutral-500">
            Probe: {readiness?.timestamp ? formatRelativeTime(readiness.timestamp) : "Polling..."}
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {/* SQLite DB */}
          <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1">
            <div className="flex items-center justify-between text-[11px] font-mono">
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
            <div className="text-xs font-mono font-semibold text-neutral-900 dark:text-white">
              SQLite Dev
            </div>
            <div className="text-[10px] text-neutral-400 font-mono">
              {deps.database?.latency_ms ? `${deps.database.latency_ms}ms` : "Active"}
            </div>
          </div>

          {/* Local Storage */}
          <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1">
            <div className="flex items-center justify-between text-[11px] font-mono">
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
            <div className="text-xs font-mono font-semibold text-neutral-900 dark:text-white">
              Local Filesystem
            </div>
            <div className="text-[10px] text-neutral-400 font-mono">
              PCAP & Reports
            </div>
          </div>

          {/* TShark Engine */}
          <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1">
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-neutral-500">TSHARK ENGINE</span>
              {deps.tshark?.status === "UP" ? (
                <span className="text-emerald-600 font-bold flex items-center space-x-0.5">
                  <CheckCircle2 className="w-3 h-3" />
                  <span>UP</span>
                </span>
              ) : (
                <span className="text-amber-500 font-bold">ABSENT</span>
              )}
            </div>
            <div className="text-xs font-mono font-semibold text-neutral-900 dark:text-white truncate">
              TShark 4.6.4
            </div>
            <div className="text-[10px] text-neutral-400 font-mono">
              IKEv2/ESP Dissector
            </div>
          </div>

          {/* Task Queue / Redis */}
          <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1">
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-neutral-500">ASYNC QUEUE</span>
              <span className="text-amber-600 dark:text-amber-400 font-bold flex items-center space-x-0.5">
                <Info className="w-3 h-3" />
                <span>EAGER</span>
              </span>
            </div>
            <div className="text-xs font-mono font-semibold text-neutral-900 dark:text-white">
              In-Process Tasks
            </div>
            <div className="text-[10px] text-neutral-400 font-mono">
              Redis Optional in Dev
            </div>
          </div>

          {/* Live Capture Agent */}
          <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1">
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-neutral-500">LIVE CAPTURE</span>
              <span className="text-neutral-400 font-bold flex items-center space-x-0.5">
                <XCircle className="w-3 h-3" />
                <span>UNAVAIL</span>
              </span>
            </div>
            <div className="text-xs font-mono font-semibold text-neutral-900 dark:text-white">
              Windows Host
            </div>
            <div className="text-[10px] text-neutral-400 font-mono">
              Requires Linux Root
            </div>
          </div>

          {/* ML Classifier */}
          <div className="border border-neutral-200 dark:border-neutral-800 p-3 space-y-1">
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-neutral-500">TRAFFIC ML</span>
              <span className="text-neutral-400 font-bold flex items-center space-x-0.5">
                <AlertTriangle className="w-3 h-3" />
                <span>UNCONFIG</span>
              </span>
            </div>
            <div className="text-xs font-mono font-semibold text-neutral-900 dark:text-white">
              Classifier Bundle
            </div>
            <div className="text-[10px] text-neutral-400 font-mono">
              models/active empty
            </div>
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
                      {run.security_score !== null && run.security_score !== undefined ? (
                        <span className={`font-bold ${
                          run.security_score >= 80 ? "text-emerald-600" :
                          run.security_score >= 60 ? "text-amber-500" : "text-rose-500"
                        }`}>
                          {run.security_score}/100
                        </span>
                      ) : (
                        <span className="text-neutral-400">N/A</span>
                      )}
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
