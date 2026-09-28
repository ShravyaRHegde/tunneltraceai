"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import {
  DiscoveryJobCreateRequestDTO,
  DiscoveryJobDTO,
  DiscoveryStatusDTO,
} from "@/lib/api/types";
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
import {
  Globe,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  Clock,
  Hash,
  HelpCircle,
  FileText,
  Terminal,
  Ban,
  Layers,
} from "lucide-react";

export default function DiscoveryPage() {
  const queryClient = useQueryClient();

  // Form State
  const [jobName, setJobName] = useState("Authorized VPN Discovery");
  const [operatorId, setOperatorId] = useState("operator-admin");
  const [authRef, setAuthRef] = useState("CHG-2026-0924");
  const [authAttestation, setAuthAttestation] = useState(
    "I attest that written authorization has been granted for active IPsec discovery on these approved targets."
  );
  const [hasConfirmedAttestation, setHasConfirmedAttestation] = useState(false);
  const [profile, setProfile] = useState("IKE_SERVICE_DISCOVERY");
  const [targetsText, setTargetsText] = useState("127.0.0.1");
  const [exclusionsText, setExclusionsText] = useState("");
  const [portsText, setPortsText] = useState("");
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  // Queries
  const { data: statusData, isLoading: isStatusLoading } = useQuery<DiscoveryStatusDTO>({
    queryKey: ["discovery-status"],
    queryFn: () => api.discovery.getStatus(),
  });

  const { data: jobs, isLoading: isJobsLoading, refetch: refetchJobs } = useQuery<DiscoveryJobDTO[]>({
    queryKey: ["discovery-jobs"],
    queryFn: () => api.discovery.listJobs(),
  });

  const activeJob = jobs?.find((j) => j.id === (selectedJobId || jobs[0]?.id));

  // Mutations
  const createJobMutation = useMutation({
    mutationFn: (req: DiscoveryJobCreateRequestDTO) => api.discovery.createJob(req),
    onSuccess: (newJob) => {
      queryClient.invalidateQueries({ queryKey: ["discovery-jobs"] });
      setSelectedJobId(newJob.id);
      setShowConfirmModal(false);
      setFormError(null);
    },
    onError: (err: any) => {
      setFormError(err.message || "Failed to submit discovery job.");
      setShowConfirmModal(false);
    },
  });

  const cancelJobMutation = useMutation({
    mutationFn: (jobId: string) => api.discovery.cancelJob(jobId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["discovery-jobs"] });
    },
  });

  // Target Parsing Preview
  const parsedTargets = targetsText
    .split(/[\n,]+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  const parsedExclusions = exclusionsText
    .split(/[\n,]+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  const parsedPorts = portsText
    .split(/[\n,]+/)
    .map((p) => parseInt(p.trim(), 10))
    .filter((p) => !isNaN(p) && p >= 1 && p <= 65535);

  const handleOpenConfirmation = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (parsedTargets.length === 0) {
      setFormError("At least one target IP, CIDR, or hostname is required.");
      return;
    }

    if (statusData && parsedTargets.length > statusData.max_targets) {
      setFormError(
        `Target count (${parsedTargets.length}) exceeds hard limit of ${statusData.max_targets}.`
      );
      return;
    }

    if (!hasConfirmedAttestation || authAttestation.trim().length < 10) {
      setFormError("You must explicitly verify and attest authorization before scanning.");
      return;
    }

    setShowConfirmModal(true);
  };

  const handleExecuteScan = () => {
    createJobMutation.mutate({
      job_name: jobName,
      operator_id: operatorId,
      authorization_reference: authRef,
      authorization_attestation: authAttestation,
      profile: profile,
      requested_targets: parsedTargets,
      exclusions: parsedExclusions.length > 0 ? parsedExclusions : undefined,
      permitted_ports: parsedPorts.length > 0 ? parsedPorts : undefined,
      simulate_demo: !statusData?.nmap_available,
    });
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <Globe className="w-5 h-5 text-[#FF3D00]" />
            <h1 className="text-xl font-bold tracking-tight text-neutral-900 dark:text-white uppercase font-mono">
              Authorized Asset Discovery
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-neutral-200 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-300">
              Stage 2
            </span>
          </div>
          <p className="text-xs text-neutral-500 mt-1 max-w-2xl leading-relaxed">
            <strong className="text-neutral-700 dark:text-neutral-300">Purpose & Governance:</strong> Bounded active UDP/TCP discovery for authorized VPN gateways. Requires written change authorization; queries local Nmap (or deterministic simulation fallback) and outputs raw port observation records without speculative vulnerability claims.
          </p>
        </div>

        {/* Nmap Engine Status Indicator */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5 px-3 py-1 rounded bg-neutral-100 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-xs">
            <span
              className={`w-2 h-2 rounded-full ${
                statusData?.nmap_available ? "bg-emerald-500 animate-pulse" : "bg-amber-500"
              }`}
            />
            <span className="font-mono text-neutral-700 dark:text-neutral-300">
              {isStatusLoading
                ? "CHECKING TOOL..."
                : statusData?.nmap_available
                ? `NMAP ${statusData.nmap_version || "READY"}`
                : "NMAP NOT INSTALLED (SIMULATION ONLY)"}
            </span>
          </div>
          <Link
            href="/vulnerabilities"
            className="flex items-center space-x-1.5 px-3 py-1 rounded bg-indigo-950/40 hover:bg-indigo-900/40 border border-indigo-500/30 text-indigo-300 text-xs font-mono transition-colors"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-indigo-400" />
            <span>VULNERABILITY REPORTS</span>
          </Link>
          <button
            onClick={() => refetchJobs()}
            className="p-1.5 rounded text-neutral-500 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-100 dark:hover:bg-neutral-800"
            title="Refresh jobs"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Safety & Ambiguity Callout Banner */}
      <div className="p-4 rounded-lg bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-900/40 text-xs text-blue-900 dark:text-blue-300 flex items-start space-x-3">
        <HelpCircle className="w-4 h-4 text-blue-500 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-blue-950 dark:text-blue-200">
            Observational Evidence vs. Vulnerability Verdicts
          </div>
          <p className="text-blue-800 dark:text-blue-300/90 leading-relaxed">
            Nmap discovery outputs scanner observations, not vulnerability claims or proof of VPN security.
            UDP service states such as <code className="font-mono font-bold">open|filtered</code> occur when
            no response packet is returned (e.g. firewalls or non-responsive IKE responders). They remain
            explicitly ambiguous and are never converted into false certainty.
          </p>
        </div>
      </div>

      {/* Two-Column Grid: Form & Results */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Scope & Launch Form */}
        <div className="lg:col-span-5 space-y-6">
          <Card className="p-5 space-y-5">
            <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-3">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-[#FF3D00]" />
                <h2 className="text-sm font-bold uppercase font-mono text-neutral-900 dark:text-white">
                  Job Scope & Authorization
                </h2>
              </div>
              <span className="text-[10px] font-mono text-neutral-400">UNPRIVILEGED</span>
            </div>

            {formError && (
              <div className="p-3 rounded bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-xs text-red-600 dark:text-red-400 flex items-start space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{formError}</span>
              </div>
            )}

            <form onSubmit={handleOpenConfirmation} className="space-y-4 text-xs">
              {/* Job Name */}
              <div className="space-y-1">
                <label className="font-mono text-neutral-600 dark:text-neutral-400 font-medium">
                  JOB NAME / ENGAGEMENT TITLE
                </label>
                <input
                  type="text"
                  value={jobName}
                  onChange={(e) => setJobName(e.target.value)}
                  className="w-full px-3 py-1.5 rounded border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-900 text-neutral-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF3D00]"
                  required
                />
              </div>

              {/* Scan Profile Selection */}
              <div className="space-y-1">
                <label className="font-mono text-neutral-600 dark:text-neutral-400 font-medium">
                  BOUNDED SCAN PROFILE
                </label>
                <select
                  value={profile}
                  onChange={(e) => setProfile(e.target.value)}
                  className="w-full px-3 py-1.5 rounded border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-900 text-neutral-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF3D00]"
                >
                  <option value="IKE_SERVICE_DISCOVERY">
                    IKE Service Discovery (UDP 500, 4500)
                  </option>
                  <option value="VPN_MANAGEMENT_DISCOVERY">
                    VPN Management Portals (TCP 22, 80, 443, 8443)
                  </option>
                  <option value="CUSTOM_BOUNDED">
                    Custom Bounded Scan (Operator-Specified Ports)
                  </option>
                </select>
                <p className="text-[11px] text-neutral-500">
                  {profile === "IKE_SERVICE_DISCOVERY" && "Low-impact UDP probe targeting standard IPsec and NAT-T ports."}
                  {profile === "VPN_MANAGEMENT_DISCOVERY" && "Safe TCP connect probes for authorized HTTPS, SSH, and management."}
                  {profile === "CUSTOM_BOUNDED" && "Strictly capped custom port probe (max 16 ports)."}
                </p>
              </div>

              {/* Operator ID & Authorization Ref */}
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="font-mono text-neutral-600 dark:text-neutral-400 font-medium">
                    OPERATOR ID
                  </label>
                  <input
                    type="text"
                    value={operatorId}
                    onChange={(e) => setOperatorId(e.target.value)}
                    className="w-full px-3 py-1.5 rounded border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-900 text-neutral-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF3D00]"
                    required
                  />
                </div>
                <div className="space-y-1">
                  <label className="font-mono text-neutral-600 dark:text-neutral-400 font-medium">
                    AUTH REFERENCE / TICKET
                  </label>
                  <input
                    type="text"
                    value={authRef}
                    onChange={(e) => setAuthRef(e.target.value)}
                    placeholder="e.g. CHG-2026-0924"
                    className="w-full px-3 py-1.5 rounded border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-900 text-neutral-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF3D00]"
                    required
                  />
                </div>
              </div>

              {/* Targets */}
              <div className="space-y-1.5">
                <div className="flex justify-between items-center">
                  <label className="font-mono text-neutral-600 dark:text-neutral-400 font-medium">
                    APPROVED TARGETS (IPs, CIDRs, or HOSTNAMES)
                  </label>
                  <span className="text-[10px] font-mono text-neutral-500">
                    Max: {statusData?.max_targets || 8}
                  </span>
                </div>

                {/* Quick Presets for Demo & Video */}
                <div className="flex items-center gap-1.5 flex-wrap pb-1">
                  <span className="text-[10px] font-mono text-neutral-500 uppercase">Quick Presets:</span>
                  <button
                    type="button"
                    onClick={() => {
                      setTargetsText("127.0.0.1");
                      setProfile("IKE_SERVICE_DISCOVERY");
                      setJobName("Local IKE Responder Discovery");
                      setHasConfirmedAttestation(true);
                    }}
                    className="px-2 py-0.5 text-[10px] font-mono rounded bg-neutral-100 hover:bg-neutral-200 dark:bg-neutral-800 dark:hover:bg-neutral-700 text-neutral-800 dark:text-neutral-200 border border-neutral-300 dark:border-neutral-700 transition-colors"
                  >
                    Loopback (127.0.0.1)
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setTargetsText("198.51.100.1, 198.51.100.2");
                      setProfile("VPN_MANAGEMENT_DISCOVERY");
                      setJobName("Lab Gateway Management Audit");
                      setHasConfirmedAttestation(true);
                    }}
                    className="px-2 py-0.5 text-[10px] font-mono rounded bg-neutral-100 hover:bg-neutral-200 dark:bg-neutral-800 dark:hover:bg-neutral-700 text-neutral-800 dark:text-neutral-200 border border-neutral-300 dark:border-neutral-700 transition-colors"
                  >
                    Lab Gateway (198.51.100.x)
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setTargetsText("10.0.1.1, 10.0.1.254");
                      setProfile("IKE_SERVICE_DISCOVERY");
                      setJobName("Enterprise Core IPsec Audit");
                      setHasConfirmedAttestation(true);
                    }}
                    className="px-2 py-0.5 text-[10px] font-mono rounded bg-neutral-100 hover:bg-neutral-200 dark:bg-neutral-800 dark:hover:bg-neutral-700 text-neutral-800 dark:text-neutral-200 border border-neutral-300 dark:border-neutral-700 transition-colors"
                  >
                    Core Network (10.0.1.x)
                  </button>
                </div>

                <textarea
                  rows={2}
                  value={targetsText}
                  onChange={(e) => setTargetsText(e.target.value)}
                  placeholder="127.0.0.1, 10.0.0.1"
                  className="w-full px-3 py-1.5 font-mono text-xs rounded border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-900 text-neutral-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF3D00]"
                  required
                />
              </div>

              {/* Exclusions & Ports */}
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="font-mono text-neutral-600 dark:text-neutral-400 font-medium">
                    EXCLUSIONS (OPTIONAL)
                  </label>
                  <input
                    type="text"
                    value={exclusionsText}
                    onChange={(e) => setExclusionsText(e.target.value)}
                    placeholder="10.0.0.254"
                    className="w-full px-3 py-1.5 font-mono text-xs rounded border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-900 text-neutral-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF3D00]"
                  />
                </div>
                <div className="space-y-1">
                  <label className="font-mono text-neutral-600 dark:text-neutral-400 font-medium">
                    PORTS (OPTIONAL)
                  </label>
                  <input
                    type="text"
                    value={portsText}
                    onChange={(e) => setPortsText(e.target.value)}
                    placeholder="Default from profile"
                    className="w-full px-3 py-1.5 font-mono text-xs rounded border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-900 text-neutral-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-[#FF3D00]"
                  />
                </div>
              </div>

              {/* Explicit Legal Attestation */}
              <div className="p-3 rounded bg-neutral-100 dark:bg-neutral-900/60 border border-neutral-200 dark:border-neutral-800 space-y-2">
                <label className="flex items-start space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={hasConfirmedAttestation}
                    onChange={(e) => setHasConfirmedAttestation(e.target.checked)}
                    className="mt-0.5 rounded border-neutral-400 text-[#FF3D00] focus:ring-[#FF3D00]"
                  />
                  <span className="text-[11px] text-neutral-800 dark:text-neutral-200 font-medium leading-tight">
                    I explicitly attest that testing of these targets has been formally authorized by their legal owner.
                  </span>
                </label>
                <textarea
                  rows={2}
                  value={authAttestation}
                  onChange={(e) => setAuthAttestation(e.target.value)}
                  className="w-full px-2 py-1 text-[11px] rounded border border-neutral-300 dark:border-neutral-700 bg-white dark:bg-neutral-950 text-neutral-700 dark:text-neutral-300"
                />
              </div>

              {/* Nmap Availability Guidance */}
              {!statusData?.nmap_available && (
                <div className="p-2.5 bg-amber-50 dark:bg-amber-950/30 border border-amber-300 dark:border-amber-800 rounded text-[11px] font-mono text-amber-900 dark:text-amber-200 space-y-1">
                  <div className="font-bold flex items-center space-x-1">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 shrink-0" />
                    <span>Nmap executable not found on host PATH</span>
                  </div>
                  <p className="text-[10px] text-amber-800 dark:text-amber-300 leading-tight">
                    Launching will run in <strong>Simulated Demo Mode</strong> to safely test Stage 2 service discovery, 
                    XML parsing, and port mapping for IKE (500/udp) and NAT-T (4500/udp).
                  </p>
                </div>
              )}

              {/* Submit Review Button */}
              <button
                type="submit"
                disabled={!hasConfirmedAttestation || createJobMutation.isPending}
                className="w-full py-2 px-4 rounded bg-[#FF3D00] hover:bg-[#E63700] text-white font-mono font-semibold text-xs transition-colors flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>
                  {createJobMutation.isPending
                    ? "SUBMITTING SCAN..."
                    : statusData?.nmap_available
                    ? "REVIEW & LAUNCH DISCOVERY SCAN"
                    : "REVIEW & LAUNCH DEMO SCAN"}
                </span>
              </button>
            </form>
          </Card>

          {/* Job History List */}
          <Card className="p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-2">
              <span className="font-mono text-xs font-bold text-neutral-700 dark:text-neutral-300 uppercase">
                Recent Discovery Jobs
              </span>
              <span className="text-[10px] font-mono text-neutral-400">
                {jobs?.length || 0} JOBS
              </span>
            </div>

            {isJobsLoading ? (
              <div className="py-8 text-center text-xs text-neutral-400 font-mono">
                LOADING HISTORY...
              </div>
            ) : !jobs || jobs.length === 0 ? (
              <div className="py-8 text-center text-xs text-neutral-400 font-mono">
                NO DISCOVERY JOBS RECORDED YET.
              </div>
            ) : (
              <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                {jobs.map((job) => (
                  <button
                    key={job.id}
                    onClick={() => setSelectedJobId(job.id)}
                    className={`w-full text-left p-2.5 rounded border text-xs transition-all flex items-center justify-between ${
                      (selectedJobId || jobs[0]?.id) === job.id
                        ? "border-[#FF3D00] bg-neutral-100 dark:bg-neutral-900"
                        : "border-neutral-200 dark:border-neutral-800/60 hover:bg-neutral-50 dark:hover:bg-neutral-900/40"
                    }`}
                  >
                    <div className="truncate pr-2">
                      <div className="font-medium text-neutral-900 dark:text-white truncate">
                        {job.job_name}
                      </div>
                      <div className="text-[10px] text-neutral-500 font-mono">
                        {job.profile} • {new Date(job.created_at).toLocaleTimeString()}
                      </div>
                    </div>
                    <div className="shrink-0 flex items-center space-x-2">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[9px] font-mono uppercase ${
                          job.status === "COMPLETED"
                            ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-400"
                            : job.status === "COMPLETED_WITH_AMBIGUITY"
                            ? "bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-400"
                            : job.status === "TOOL_UNAVAILABLE"
                            ? "bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-400"
                            : "bg-red-100 text-red-800 dark:bg-red-950/60 dark:text-red-400"
                        }`}
                      >
                        {job.status}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </Card>
        </div>

        {/* Right Column: Active Job Results & Normalized Evidence */}
        <div className="lg:col-span-7 space-y-6">
          {activeJob ? (
            <div className="space-y-6">
              {/* Job Header Card */}
              <Card className="p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-neutral-200 dark:border-neutral-800 pb-3">
                  <div>
                    <div className="flex items-center space-x-2">
                      <h2 className="text-base font-bold text-neutral-900 dark:text-white font-mono">
                        {activeJob.job_name}
                      </h2>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold ${
                          activeJob.status === "COMPLETED"
                            ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300"
                            : activeJob.status === "COMPLETED_WITH_AMBIGUITY"
                            ? "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300"
                            : activeJob.status === "TOOL_UNAVAILABLE"
                            ? "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300"
                            : "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300"
                        }`}
                      >
                        {activeJob.status}
                      </span>
                    </div>
                    <div className="text-xs text-neutral-500 font-mono mt-1">
                      ID: {activeJob.id}
                    </div>
                  </div>

                  {["QUEUED", "RUNNING", "VALIDATING"].includes(activeJob.status) && (
                    <button
                      onClick={() => cancelJobMutation.mutate(activeJob.id)}
                      disabled={cancelJobMutation.isPending}
                      className="px-3 py-1.5 rounded bg-red-600 hover:bg-red-700 text-white font-mono text-xs flex items-center space-x-1"
                    >
                      <Ban className="w-3.5 h-3.5" />
                      <span>CANCEL SCAN</span>
                    </button>
                  )}
                </div>

                {/* Status Diagnostic Message */}
                {activeJob.status === "TOOL_UNAVAILABLE" && (
                  <div className="p-3 rounded bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-900/40 text-xs text-amber-800 dark:text-amber-300 space-y-1">
                    <div className="font-bold flex items-center space-x-1">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span>TOOL UNAVAILABLE ON THIS SYSTEM</span>
                    </div>
                    <p className="text-[11px] text-amber-700 dark:text-amber-300/80">
                      {activeJob.failure_reason ||
                        "Nmap executable was not found on PATH or configured NMAP_PATH. In local test mode, scanner integrations safely report tool absence rather than pretending execution succeeded."}
                    </p>
                  </div>
                )}

                {activeJob.status === "COMPLETED_WITH_AMBIGUITY" && (
                  <div className="p-3 rounded bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-900/40 text-xs text-blue-800 dark:text-blue-300 space-y-1">
                    <div className="font-bold flex items-center space-x-1">
                      <HelpCircle className="w-3.5 h-3.5" />
                      <span>AMBIGUOUS PORT STATES OBSERVED</span>
                    </div>
                    <p className="text-[11px] text-blue-700 dark:text-blue-300/80">
                      UDP probes against ports 500/4500 received no response, yielding <code className="font-mono font-bold">open|filtered</code>.
                      This is standard network behavior for non-responding or protected IPsec endpoints and is preserved honestly.
                    </p>
                  </div>
                )}

                {/* Metrics Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                  <div className="p-2.5 rounded bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800">
                    <div className="text-[10px] text-neutral-500 uppercase">TARGET COUNT</div>
                    <div className="text-base font-bold text-neutral-900 dark:text-white mt-0.5">
                      {activeJob.target_count}
                    </div>
                  </div>
                  <div className="p-2.5 rounded bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800">
                    <div className="text-[10px] text-neutral-500 uppercase">HOSTS UP</div>
                    <div className={`text-base font-bold mt-0.5 ${activeJob.status === "TOOL_UNAVAILABLE" ? "text-amber-600 dark:text-amber-400 text-xs" : "text-neutral-900 dark:text-white"}`}>
                      {activeJob.status === "TOOL_UNAVAILABLE" ? "UNAVAILABLE (NOT RUN)" : activeJob.hosts_up_count}
                    </div>
                  </div>
                  <div className="p-2.5 rounded bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800">
                    <div className="text-[10px] text-neutral-500 uppercase">SERVICES OBSERVED</div>
                    <div className={`text-base font-bold mt-0.5 ${activeJob.status === "TOOL_UNAVAILABLE" ? "text-amber-600 dark:text-amber-400 text-xs" : "text-neutral-900 dark:text-white"}`}>
                      {activeJob.status === "TOOL_UNAVAILABLE" ? "UNAVAILABLE (NOT RUN)" : activeJob.services_discovered_count}
                    </div>
                  </div>
                  <div className="p-2.5 rounded bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800">
                    <div className="text-[10px] text-neutral-500 uppercase">NMAP VERSION</div>
                    <div className="text-base font-bold text-neutral-900 dark:text-white mt-0.5 truncate">
                      {activeJob.tool_version || "N/A"}
                    </div>
                  </div>
                </div>

                {/* Provenance Details */}
                <div className="border-t border-neutral-200 dark:border-neutral-800 pt-3 text-xs space-y-1 font-mono text-neutral-600 dark:text-neutral-400">
                  <div className="flex justify-between">
                    <span>OPERATOR:</span>
                    <span className="text-neutral-900 dark:text-neutral-200 font-semibold">
                      {activeJob.operator_id}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>AUTH REFERENCE:</span>
                    <span className="text-neutral-900 dark:text-neutral-200">
                      {activeJob.authorization_reference}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>CANONICAL TARGETS:</span>
                    <span className="text-neutral-900 dark:text-neutral-200 truncate max-w-xs">
                      {activeJob.canonical_targets.join(", ")}
                    </span>
                  </div>
                  {activeJob.raw_output_sha256 && (
                    <div className="flex justify-between items-center">
                      <span>XML SHA-256:</span>
                      <span className="text-neutral-900 dark:text-neutral-200 truncate max-w-xs">
                        {activeJob.raw_output_sha256}
                      </span>
                    </div>
                  )}
                </div>
              </Card>

              {/* Discovered Hosts & Services Evidence Table */}
              <Card className="p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-neutral-200 dark:border-neutral-800 pb-3">
                  <div className="flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-[#FF3D00]" />
                    <h3 className="text-sm font-bold uppercase font-mono text-neutral-900 dark:text-white">
                      Normalized Scanner Observations
                    </h3>
                  </div>
                  <span className="text-[10px] font-mono text-neutral-500">
                    ZERO FABRICATION POLICY
                  </span>
                </div>

                {activeJob.hosts.length === 0 ? (
                  <div className="py-12 text-center text-xs text-neutral-400 font-mono">
                    {activeJob.status === "TOOL_UNAVAILABLE"
                      ? "NO SCAN OBSERVATIONS (NMAP UNAVAILABLE ON HOST)"
                      : "NO HOST OBSERVATIONS RECORDED FOR THIS RUN"}
                  </div>
                ) : (
                  <div className="space-y-4">
                    {activeJob.hosts.map((host) => (
                      <div
                        key={host.id}
                        className="rounded border border-neutral-200 dark:border-neutral-800 overflow-hidden"
                      >
                        {/* Host Header */}
                        <div className="px-4 py-2.5 bg-neutral-50 dark:bg-neutral-900/80 border-b border-neutral-200 dark:border-neutral-800 flex items-center justify-between text-xs font-mono">
                          <div className="flex items-center space-x-2">
                            <span
                              className={`w-2 h-2 rounded-full ${
                                host.state === "UP" ? "bg-emerald-500" : "bg-red-500"
                              }`}
                            />
                            <span className="font-bold text-neutral-900 dark:text-white">
                              {host.ip_address}
                            </span>
                            <span className="text-neutral-400">({host.ip_version})</span>
                            {host.hostnames && host.hostnames.length > 0 && (
                              <span className="text-neutral-500">
                                [{host.hostnames.join(", ")}]
                              </span>
                            )}
                          </div>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              host.state === "UP"
                                ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300"
                                : "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300"
                            }`}
                          >
                            STATE: {host.state}
                          </span>
                        </div>

                        {/* Services Table */}
                        {host.services.length === 0 ? (
                          <div className="p-4 text-center text-xs text-neutral-400 font-mono">
                            NO OPEN/OBSERVED SERVICES FOUND ON THIS HOST
                          </div>
                        ) : (
                          <div className="overflow-x-auto">
                            <table className="w-full text-left text-xs font-mono">
                              <thead className="bg-neutral-100 dark:bg-neutral-950 text-neutral-500 text-[10px] uppercase border-b border-neutral-200 dark:border-neutral-800">
                                <tr>
                                  <th className="px-3 py-2">PORT</th>
                                  <th className="px-3 py-2">PROTO</th>
                                  <th className="px-3 py-2">OBSERVED STATE</th>
                                  <th className="px-3 py-2">REASON</th>
                                  <th className="px-3 py-2">SERVICE / BANNER</th>
                                  <th className="px-3 py-2">PRODUCT / VERSION</th>
                                  <th className="px-3 py-2">CONF</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-neutral-200 dark:divide-neutral-800 text-neutral-800 dark:text-neutral-200">
                                {host.services.map((svc) => (
                                  <tr key={svc.id} className="hover:bg-neutral-50 dark:hover:bg-neutral-900/40">
                                    <td className="px-3 py-2 font-bold text-neutral-900 dark:text-white">
                                      {svc.port}
                                    </td>
                                    <td className="px-3 py-2">{svc.protocol}</td>
                                    <td className="px-3 py-2">
                                      <span
                                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                          svc.state === "OPEN"
                                            ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300"
                                            : svc.state === "OPEN_OR_FILTERED"
                                            ? "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300"
                                            : svc.state === "FILTERED"
                                            ? "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300"
                                            : "bg-neutral-200 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-400"
                                        }`}
                                      >
                                        {svc.state}
                                      </span>
                                    </td>
                                    <td className="px-3 py-2 text-neutral-500">
                                      {svc.state_reason || "unknown"}
                                    </td>
                                    <td className="px-3 py-2 font-semibold">
                                      {svc.service_name || "unknown"}
                                    </td>
                                    <td className="px-3 py-2 text-neutral-400">
                                      {[svc.product, svc.version].filter(Boolean).join(" ") || "—"}
                                    </td>
                                    <td className="px-3 py-2 text-neutral-400">
                                      {svc.confidence !== null ? `${svc.confidence}` : "—"}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>
          ) : (
            <Card className="p-12 text-center text-xs text-neutral-400 font-mono space-y-2">
              <Globe className="w-8 h-8 mx-auto text-neutral-300 dark:text-neutral-700" />
              <div>SELECT A DISCOVERY JOB OR LAUNCH A NEW AUTHORIZED ASSESSMENT</div>
            </Card>
          )}
        </div>
      </div>

      {/* Confirmation Modal */}
      {showConfirmModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg rounded-lg bg-white dark:bg-neutral-900 border border-neutral-300 dark:border-neutral-700 p-6 space-y-4 shadow-xl text-xs">
            <div className="flex items-center space-x-2 text-neutral-900 dark:text-white border-b border-neutral-200 dark:border-neutral-800 pb-3">
              <ShieldAlert className="w-5 h-5 text-[#FF3D00]" />
              <h3 className="text-base font-bold font-mono uppercase">
                Confirm Authorized Scope Execution
              </h3>
            </div>

            <div className="space-y-3 font-mono">
              <div className="p-3 rounded bg-neutral-100 dark:bg-neutral-950 border border-neutral-200 dark:border-neutral-800 space-y-1.5">
                <div className="flex justify-between">
                  <span className="text-neutral-500">PROFILE:</span>
                  <span className="font-bold text-neutral-900 dark:text-white">{profile}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-neutral-500">OPERATOR:</span>
                  <span className="text-neutral-900 dark:text-white">{operatorId}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-neutral-500">AUTH REF:</span>
                  <span className="text-neutral-900 dark:text-white">{authRef}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-neutral-500">EXPANDED TARGETS:</span>
                  <span className="font-bold text-neutral-900 dark:text-white">
                    {parsedTargets.join(", ")}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-neutral-500">RATE LIMIT:</span>
                  <span className="text-neutral-900 dark:text-white">
                    {statusData?.rate_limit_pps || 100} pps (Low Impact)
                  </span>
                </div>
              </div>

              <p className="text-[11px] text-neutral-600 dark:text-neutral-400 font-sans leading-relaxed">
                By confirming, you attest that you hold explicit legal authorization to discover network services on
                these targets. All actions and output digests are permanently recorded in the audit trail.
              </p>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                type="button"
                onClick={() => setShowConfirmModal(false)}
                className="px-4 py-2 rounded border border-neutral-300 dark:border-neutral-700 font-mono hover:bg-neutral-100 dark:hover:bg-neutral-800 text-neutral-700 dark:text-neutral-300"
              >
                CANCEL
              </button>
              <button
                type="button"
                onClick={handleExecuteScan}
                disabled={createJobMutation.isPending}
                className="px-4 py-2 rounded bg-[#FF3D00] hover:bg-[#E63700] text-white font-mono font-bold flex items-center space-x-1.5 shadow"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>CONFIRM & LAUNCH</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
