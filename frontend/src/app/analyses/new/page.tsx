"use client";

import React, { useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { useQuery, useMutation } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import { Card } from "@/components/ui/card";
import { SampleCaptureDTO } from "@/lib/api/types";
import {
  UploadCloud,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Play,
  Square,
  Shield,
  ArrowRight,
  FlaskConical,
  Info,
  Layers,
  Sparkles,
  ExternalLink,
} from "lucide-react";

export default function NewAnalysisPage() {
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Tab: "upload" vs "samples" vs "live"
  const [activeTab, setActiveTab] = useState<"upload" | "samples" | "live">("upload");

  // Upload State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);

  // Live Capture State
  const [selectedInterface, setSelectedInterface] = useState<string>("");
  const [captureDuration, setCaptureDuration] = useState<number>(30);
  const [liveSessionId, setLiveSessionId] = useState<string | null>(null);
  const [liveError, setLiveError] = useState<string | null>(null);

  // Fetch verified repository sample captures
  const { data: samples, isLoading: isSamplesLoading } = useQuery({
    queryKey: ["capture-samples"],
    queryFn: () => api.captures.getSamples(),
  });

  // Fetch authorized live capture interfaces
  const { data: interfaces, isLoading: isInterfacesLoading } = useQuery({
    queryKey: ["live-interfaces"],
    queryFn: () => api.captures.listInterfaces(),
    enabled: activeTab === "live",
  });

  // Ingest Sample Mutation
  const [ingestingSampleId, setIngestingSampleId] = useState<string | null>(null);
  const ingestSampleMutation = useMutation({
    mutationFn: async (sampleId: string) => {
      setIngestingSampleId(sampleId);
      const capture = await api.captures.ingestSample(sampleId);
      const analysis = await api.analyses.create(capture.capture_id);
      return analysis;
    },
    onSuccess: (analysis) => {
      router.push(`/analyses/${analysis.analysis_id}/overview`);
    },
    onError: (err: any) => {
      setIngestingSampleId(null);
      setUploadError(err.message || "Failed to ingest sample capture fixture");
    },
  });

  // Upload Mutation
  const uploadMutation = useMutation({
    mutationFn: async (file: File) => {
      setUploadError(null);
      setUploadProgress(20);
      const capture = await api.captures.upload(file);
      setUploadProgress(70);
      const analysis = await api.analyses.create(capture.capture_id);
      setUploadProgress(100);
      return { capture, analysis };
    },
    onSuccess: (data) => {
      router.push(`/analyses/${data.analysis.analysis_id}/overview`);
    },
    onError: (err: any) => {
      setUploadProgress(null);
      if (err?.status === 405) {
        setUploadError(
          "HTTP 405 Method Not Allowed: The multipart ingestion endpoint is misconfigured on the server. Ensure backend mounts POST /api/v1/captures."
        );
      } else {
        setUploadError(err.message || "Failed to upload and initiate analysis");
      }
    },
  });

  const handleFileSelect = (file: File) => {
    const ext = file.name.split(".").pop()?.toLowerCase();
    if (ext !== "pcap" && ext !== "pcapng") {
      setUploadError("Invalid file type. Supported formats: standard libpcap (.pcap) and pcapng (.pcapng).");
      return;
    }
    const maxBytes = 250 * 1024 * 1024;
    if (file.size > maxBytes) {
      setUploadError(`File size (${(file.size / (1024 * 1024)).toFixed(2)} MB) exceeds configured limit of 250 MB.`);
      return;
    }
    setSelectedFile(file);
    setUploadError(null);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleStartUpload = () => {
    if (!selectedFile) return;
    uploadMutation.mutate(selectedFile);
  };

  const handleStartLiveCapture = async () => {
    if (!selectedInterface) {
      setLiveError("Please select an authorized network interface.");
      return;
    }
    setLiveError(null);
    try {
      const res = await api.captures.startLive({
        interface_id: selectedInterface,
        duration_sec: captureDuration,
      });
      setLiveSessionId(res.session_id);
    } catch (err: any) {
      setLiveError(err.message || "Failed to start live capture.");
    }
  };

  const handleStopLiveCapture = async () => {
    if (!liveSessionId) return;
    try {
      const res = await api.captures.stopLive(liveSessionId);
      if (res.capture_id) {
        const analysis = await api.analyses.create(res.capture_id);
        router.push(`/analyses/${analysis.analysis_id}/overview`);
      }
    } catch (err: any) {
      setLiveError(err.message || "Failed to stop live capture session.");
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Page Header */}
      <div className="border-b border-neutral-300 dark:border-neutral-800 pb-4">
        <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-900 dark:text-white uppercase flex items-center space-x-2">
          <UploadCloud className="w-5 h-5 text-[#FF3D00]" />
          <span>Ingest Network Evidence & Initiate Analysis</span>
        </h1>
        <p className="text-xs text-neutral-500 mt-1">
          Upload forensic packet captures (.pcap, .pcapng), try authentic repository test fixtures, or configure authorized live interface capture.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-neutral-300 dark:border-neutral-800">
        <button
          onClick={() => setActiveTab("upload")}
          className={`px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider border-b-2 transition-colors ${
            activeTab === "upload"
              ? "border-[#FF3D00] text-neutral-900 dark:text-white bg-white dark:bg-[#141416]"
              : "border-transparent text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
          }`}
        >
          PCAP / PCAPNG Upload
        </button>
        <button
          onClick={() => setActiveTab("samples")}
          className={`px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider border-b-2 transition-colors flex items-center space-x-1.5 ${
            activeTab === "samples"
              ? "border-[#FF3D00] text-neutral-900 dark:text-white bg-white dark:bg-[#141416]"
              : "border-transparent text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
          }`}
        >
          <Sparkles className="w-3.5 h-3.5 text-[#FF3D00]" />
          <span>Try Sample Captures</span>
        </button>
        <button
          onClick={() => setActiveTab("live")}
          className={`px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider border-b-2 transition-colors ${
            activeTab === "live"
              ? "border-[#FF3D00] text-neutral-900 dark:text-white bg-white dark:bg-[#141416]"
              : "border-transparent text-neutral-500 hover:text-neutral-900 dark:hover:text-white"
          }`}
        >
          Authorized Live Capture
        </button>
      </div>

      {/* Tab 1: Upload */}
      {activeTab === "upload" && (
        <div className="space-y-6">
          <Card title="Forensic Evidence Ingestion">
            <div
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed p-10 text-center cursor-pointer transition-colors ${
                selectedFile
                  ? "border-[#FF3D00] bg-orange-50/20 dark:bg-orange-950/10"
                  : "border-neutral-300 dark:border-neutral-700 hover:border-neutral-400 dark:hover:border-neutral-600 bg-neutral-50/50 dark:bg-neutral-900/30"
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileSelect(e.target.files[0]);
                  }
                }}
              />

              <div className="space-y-3">
                <div className="w-12 h-12 mx-auto bg-neutral-100 dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 flex items-center justify-center">
                  <UploadCloud className="w-6 h-6 text-[#FF3D00]" />
                </div>

                <div className="space-y-1">
                  <p className="text-sm font-semibold text-neutral-900 dark:text-white">
                    {selectedFile
                      ? selectedFile.name
                      : "Click to select or drag & drop capture file"}
                  </p>
                  <p className="text-xs font-mono text-neutral-500">
                    Supports libpcap (.pcap) and pcapng (.pcapng) formats. Packet headers are validated server-side. Configured safety limit: 250 MiB.
                  </p>
                </div>

                {selectedFile && (
                  <div className="inline-flex items-center space-x-2 px-3 py-1 bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-700 text-xs font-mono">
                    <FileCode className="w-4 h-4 text-neutral-500" />
                    <span>{(selectedFile.size / (1024 * 1024)).toFixed(2)} MB</span>
                    <span className="text-emerald-600 font-bold">READY</span>
                  </div>
                )}
              </div>
            </div>

            {/* Error Message */}
            {uploadError && (
              <div className="mt-4 p-3 bg-rose-50 dark:bg-rose-950/20 border border-rose-400 dark:border-rose-800 text-rose-700 dark:text-rose-400 text-xs flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{uploadError}</span>
              </div>
            )}

            {/* Upload Progress Bar */}
            {uploadProgress !== null && (
              <div className="mt-4 space-y-1.5">
                <div className="flex justify-between text-xs font-mono text-neutral-500">
                  <span>UPLOADING & INITIALIZING ANALYSIS PIPELINE</span>
                  <span>{uploadProgress}%</span>
                </div>
                <div className="w-full bg-neutral-200 dark:bg-neutral-800 h-2">
                  <div
                    className="bg-[#FF3D00] h-2 transition-all duration-300"
                    style={{ width: `${uploadProgress}%` }}
                  />
                </div>
              </div>
            )}

            {/* Actions */}
            <div className="mt-6 flex flex-col sm:flex-row items-center justify-between gap-3 pt-4 border-t border-neutral-200 dark:border-neutral-800">
              <button
                type="button"
                onClick={() => setActiveTab("samples")}
                className="text-xs font-mono text-[#FF3D00] hover:underline flex items-center space-x-1"
              >
                <span>Don&apos;t have a capture? Try safe benchmark samples</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>

              <button
                disabled={!selectedFile || uploadMutation.isPending}
                onClick={handleStartUpload}
                className={`flex items-center space-x-2 px-6 py-2.5 text-xs font-mono font-bold uppercase tracking-wider transition-colors ${
                  !selectedFile || uploadMutation.isPending
                    ? "bg-neutral-200 dark:bg-neutral-800 text-neutral-400 cursor-not-allowed border border-neutral-300 dark:border-neutral-700"
                    : "bg-[#FF3D00] hover:bg-[#e03600] text-white border border-[#FF3D00]"
                }`}
              >
                <span>{uploadMutation.isPending ? "PROCESSING..." : "START INGESTION"}</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </Card>

          {/* Privacy & Provenance Notice */}
          <div className="p-4 border border-neutral-300 dark:border-neutral-800 bg-neutral-50/50 dark:bg-neutral-900/30 text-xs text-neutral-600 dark:text-neutral-400 space-y-2">
            <div className="flex items-center space-x-2 text-neutral-900 dark:text-white font-bold font-mono">
              <Shield className="w-4 h-4 text-[#FF3D00]" />
              <span>UPLOAD AUTHORIZATION & LOCAL PROCESSING GUARANTEE</span>
            </div>
            <p>
              Upload only network packet captures you are legally authorized to inspect. Files may contain sensitive network topology, gateway addresses, and cryptographic exchange metadata. Uploaded captures are validated, hashed (SHA-256) server-side upon arrival, and processed locally without streaming packet payloads to third parties or cloud telemetry.
            </p>
          </div>
        </div>
      )}

      {/* Tab 2: Sample Captures */}
      {activeTab === "samples" && (
        <div className="space-y-6">
          <Card title="Verified Repository Sample Captures">
            <div className="space-y-4">
              <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
                These authentic network captures are sourced directly from TunnelTrace AI&apos;s dual-strongSwan Linux namespace benchmark testbed. Ingesting a sample registers a persistent capture and executes full analysis pipeline reconstruction, protocol facts extraction, and deterministic policy scoring.
              </p>

              {isSamplesLoading ? (
                <div className="p-8 text-center text-xs font-mono text-neutral-400">
                  Loading available benchmark fixtures...
                </div>
              ) : !samples || samples.length === 0 ? (
                <div className="p-6 text-center text-xs font-mono text-neutral-400 border border-neutral-200 dark:border-neutral-800">
                  No sample fixtures found in repository tests/fixtures/captures.
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-4">
                  {samples.map((sample: SampleCaptureDTO) => (
                    <div
                      key={sample.sample_id}
                      className="border border-neutral-300 dark:border-neutral-800 bg-white dark:bg-[#111113] p-5 space-y-3 hover:border-neutral-400 transition-colors"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="space-y-1">
                          <div className="flex items-center space-x-2">
                            <span className="text-[10px] font-mono px-2 py-0.5 bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 uppercase font-semibold">
                              {sample.format}
                            </span>
                            <h3 className="font-mono font-bold text-sm text-neutral-900 dark:text-white">
                              {sample.title}
                            </h3>
                          </div>
                          <p className="text-xs text-neutral-500 font-mono">
                            File: {sample.filename} • Packets: {sample.packet_count}
                          </p>
                        </div>

                        <button
                          disabled={ingestingSampleId === sample.sample_id}
                          onClick={() => ingestSampleMutation.mutate(sample.sample_id)}
                          className="shrink-0 flex items-center space-x-1.5 px-4 py-2 bg-[#FF3D00] hover:bg-[#e03600] text-white text-xs font-mono font-bold uppercase tracking-wider transition-colors disabled:opacity-50"
                        >
                          <Play className="w-3.5 h-3.5" />
                          <span>
                            {ingestingSampleId === sample.sample_id ? "INGESTING..." : "INGEST SAMPLE"}
                          </span>
                        </button>
                      </div>

                      <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
                        {sample.description}
                      </p>

                      <div className="pt-2 border-t border-neutral-200 dark:border-neutral-800/80 flex flex-col sm:flex-row sm:items-center justify-between text-[10px] font-mono text-neutral-500 gap-2">
                        <div className="truncate max-w-md">
                          <span>SHA-256: </span>
                          <span className="font-bold">{sample.sha256}</span>
                        </div>
                        <div className="text-neutral-400">
                          Provenance: {sample.provenance}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Card>
        </div>
      )}

      {/* Tab 3: Live Capture */}
      {activeTab === "live" && (
        <div className="space-y-6">
          <Card title="Authorized Live Network Interface Capture">
            <div className="space-y-4">
              {/* Host Platform Reality Notice */}
              <div className="p-4 bg-amber-50 dark:bg-amber-950/20 border border-amber-300 dark:border-amber-800 text-xs font-mono space-y-2 text-amber-800 dark:text-amber-300">
                <div className="flex items-center space-x-2 font-bold">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-amber-600 dark:text-amber-400" />
                  <span>PREFLIGHT: HOST CAPTURE ENVIRONMENT REQUIREMENTS</span>
                </div>
                <p className="leading-relaxed">
                  Direct raw socket packet capture requires an authorized local capture daemon with Linux <code className="bg-amber-100 dark:bg-amber-900/60 px-1 py-0.5 font-bold">CAP_NET_ADMIN</code> / root permissions. On Windows development hosts, raw socket sniffing is restricted by the operating system kernel.
                </p>
                <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px]">
                  <span className="font-bold">Recommended action:</span>
                  <button
                    onClick={() => setActiveTab("samples")}
                    className="underline font-bold hover:text-[#FF3D00]"
                  >
                    Use repository test captures (.pcapng)
                  </button>
                  <span>or</span>
                  <button
                    onClick={() => setActiveTab("upload")}
                    className="underline font-bold hover:text-[#FF3D00]"
                  >
                    Upload an authorized capture file
                  </button>
                </div>
              </div>

              {/* Distinction between Live Monitoring and Live Packet Capture */}
              <div className="p-3 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-xs space-y-1">
                <div className="flex items-center space-x-2 font-mono font-bold text-neutral-800 dark:text-neutral-200">
                  <Info className="w-4 h-4 text-blue-500 shrink-0" />
                  <span>NOTE: LIVE MONITORING VS DIRECT PACKET CAPTURE</span>
                </div>
                <p className="text-neutral-500 leading-relaxed">
                  <strong>Live Monitoring</strong> consumes telemetry events (IKE SA lifecycles, heartbeats) from deployed gateway collectors and operates independently of host raw sockets. To monitor remote VPN gateways, visit{" "}
                  <button
                    onClick={() => router.push("/monitoring")}
                    className="text-[#FF3D00] underline font-mono"
                  >
                    Live Monitor
                  </button>
                  .
                </p>
              </div>

              {/* Preflight State Machine Indicator */}
              <div className="p-4 border border-neutral-200 dark:border-neutral-800 bg-neutral-50/50 dark:bg-neutral-900/50 font-mono text-xs space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold text-neutral-400">Preflight Gate</span>
                  <span
                    className={`px-2 py-0.5 text-[10px] font-bold uppercase border ${
                      isInterfacesLoading
                        ? "bg-neutral-100 text-neutral-700 border-neutral-300 dark:bg-neutral-800 dark:text-neutral-300"
                        : interfaces && interfaces.length > 0
                        ? "bg-emerald-100 text-emerald-900 border-emerald-500 dark:bg-emerald-950/40 dark:text-emerald-300"
                        : "bg-amber-100 text-amber-900 border-amber-500 dark:bg-amber-950/40 dark:text-amber-300"
                    }`}
                  >
                    {isInterfacesLoading
                      ? "CHECKING CAPTURE AGENT"
                      : interfaces && interfaces.length > 0
                      ? "READY — CHOOSE INTERFACE"
                      : "UNAVAILABLE ON THIS HOST (WINDOWS NODE)"}
                  </span>
                </div>
                {isInterfacesLoading ? (
                  <p className="text-neutral-500 text-[11px] animate-pulse">
                    Probing Class B privileged capture daemon and enumerating authorized interfaces...
                  </p>
                ) : interfaces && interfaces.length > 0 ? (
                  <p className="text-emerald-700 dark:text-emerald-400 text-[11px]">
                    Privileged capture agent responded. {interfaces.length} authorized network interface(s) available for scoped capture.
                  </p>
                ) : (
                  <div className="space-y-2">
                    <p className="text-amber-800 dark:text-amber-300 text-[11px] leading-relaxed">
                      Direct raw packet capture requires a configured Class B Linux capture agent with <code className="font-bold">CAP_NET_ADMIN</code> / root socket privileges. 
                      No live capture daemon is present on this Windows development workstation. Please analyze an ingested capture using repository test samples or file upload.
                    </p>
                    <div className="flex flex-wrap items-center gap-3 pt-1">
                      <button
                        type="button"
                        onClick={() => setActiveTab("samples")}
                        className="px-3.5 py-1.5 bg-[#FF3D00] hover:bg-[#e03600] text-white font-bold text-xs flex items-center space-x-1 transition-colors"
                      >
                        <Play className="w-3 h-3" />
                        <span>INGEST SAFE BENCHMARK SAMPLE</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => setActiveTab("upload")}
                        className="px-3.5 py-1.5 bg-white dark:bg-neutral-800 hover:bg-neutral-100 dark:hover:bg-neutral-700 text-neutral-900 dark:text-white border border-neutral-300 dark:border-neutral-700 font-bold text-xs transition-colors"
                      >
                        <span>UPLOAD AUTHORIZED PCAP / PCAPNG</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Interface Selection & Controls (Only rendered when agent and interfaces are genuinely ready) */}
              {interfaces && interfaces.length > 0 && (
                <div className="space-y-4 pt-2">
                  <label className="block text-xs font-mono font-bold uppercase tracking-wider text-neutral-700 dark:text-neutral-300">
                    Select Capture Interface
                  </label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {interfaces.map((iface) => (
                      <div
                        key={iface.interface_id}
                        onClick={() => setSelectedInterface(iface.interface_id)}
                        className={`p-3 border cursor-pointer transition-colors ${
                          selectedInterface === iface.interface_id
                            ? "border-[#FF3D00] bg-orange-50/10 dark:bg-orange-950/20"
                            : "border-neutral-300 dark:border-neutral-800 hover:border-neutral-400"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-xs text-neutral-900 dark:text-white">
                            {iface.display_name}
                          </span>
                          <span className="text-[10px] font-mono px-1 border border-neutral-300 dark:border-neutral-700">
                            {iface.type}
                          </span>
                        </div>
                        <div className="mt-1 flex items-center justify-between text-[11px] text-neutral-500 font-mono">
                          <span>State: {iface.operstate}</span>
                          <span>{iface.lab_owned ? "LAB TESTBED" : "HOST"}</span>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="pt-2">
                    <label className="block text-xs font-mono font-bold uppercase tracking-wider text-neutral-700 dark:text-neutral-300 mb-1">
                      Capture Duration (Seconds)
                    </label>
                    <input
                      type="number"
                      min={5}
                      max={300}
                      value={captureDuration}
                      onChange={(e) => setCaptureDuration(Number(e.target.value))}
                      className="w-32 px-3 py-1.5 text-xs bg-white dark:bg-[#141416] border border-neutral-300 dark:border-neutral-800 font-mono text-neutral-900 dark:text-white focus:outline-none focus:border-[#FF3D00]"
                    />
                  </div>

                  {/* Live Session Controls */}
                  <div className="pt-2 flex items-center space-x-3">
                    {!liveSessionId ? (
                      <button
                        disabled={!selectedInterface}
                        onClick={handleStartLiveCapture}
                        className={`flex items-center space-x-2 px-5 py-2 text-xs font-mono font-bold uppercase tracking-wider ${
                          !selectedInterface
                            ? "bg-neutral-200 dark:bg-neutral-800 text-neutral-400 cursor-not-allowed border border-neutral-300 dark:border-neutral-700"
                            : "bg-[#FF3D00] hover:bg-[#e03600] text-white border border-[#FF3D00]"
                        }`}
                        title={!selectedInterface ? "Choose an authorized interface above to enable capture" : undefined}
                      >
                        <Play className="w-3.5 h-3.5" />
                        <span>START LIVE CAPTURE</span>
                      </button>
                    ) : (
                      <button
                        onClick={handleStopLiveCapture}
                        className="flex items-center space-x-2 px-5 py-2 text-xs font-mono font-bold uppercase tracking-wider bg-rose-600 hover:bg-rose-700 text-white border border-rose-700 animate-pulse"
                      >
                        <Square className="w-3.5 h-3.5" />
                        <span>STOP CAPTURE &amp; ANALYZE</span>
                      </button>
                    )}
                    {!selectedInterface && (
                      <span className="text-[11px] text-neutral-400 font-mono">
                        Select an interface above to enable capture
                      </span>
                    )}
                  </div>
                </div>
              )}

              {liveError && (
                <div className="p-3 bg-rose-50 dark:bg-rose-950/20 border border-rose-400 dark:border-rose-800 text-rose-700 dark:text-rose-400 text-xs flex items-center space-x-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{liveError}</span>
                </div>
              )}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
