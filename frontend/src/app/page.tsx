"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  ShieldAlert,
  Copy,
  Check,
  FileInput,
  Fingerprint,
  ListChecks,
  LayoutDashboard,
  Sparkles,
} from "lucide-react";
import { api } from "@/lib/api/client";
import { formatRelativeTime } from "@/lib/format";
import { StatusBadge } from "@/components/ui/badge";
import { ScoreDisplay } from "@/components/ui/score-display";
import { EmptyState } from "@/components/ui/empty-state";
import { ButtonLink } from "@/components/ui/button";
import { LandingHeader } from "@/components/home/landing-header";
import { InvestigationGraph, InvestigationPath } from "@/components/home/investigation-path";

function ServiceLine({ label, value, error }: { label: string; value?: string; error?: boolean }) {
  const normalized = (value || "CHECKING").toUpperCase();
  const ready = ["UP", "READY", "CONNECTED", "ACTIVE", "HEALTHY", "READY_LOCAL_DEV"].includes(normalized);
  const down = ["DOWN", "FAILED", "ERROR", "UNAVAILABLE"].includes(normalized);
  return (
    <div className="flex items-center justify-between gap-3 border-t border-line py-3">
      <span className="text-sm text-ink-2">{label}</span>
      <span
        className={`flex items-center gap-2 font-mono text-[.65rem] uppercase tracking-[.06em] ${
          error || down ? "text-critical" : ready ? "text-positive" : "text-ink-3"
        }`}
      >
        <i
          className={`h-1.5 w-1.5 rounded-full ${
            error || down ? "bg-critical" : ready ? "bg-positive" : "bg-ink-3"
          }`}
        />
        {value || "Checking"}
      </span>
    </div>
  );
}

function CaptureFilter() {
  const [copied, setCopied] = useState(false);
  const filter = "udp port 500 or udp port 4500 or esp";

  async function copyFilter() {
    try {
      await navigator.clipboard.writeText(filter);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="hero-command mt-8 p-5 sm:p-6">
      <div className="flex items-center justify-between gap-4">
        <div className="micro-label text-white/70">Capture filter · IPsec</div>
        <button
          type="button"
          onClick={copyFilter}
          className="inline-flex min-h-9 items-center gap-2 border border-white/50 px-3 text-xs font-bold uppercase tracking-wider transition-colors hover:bg-white hover:text-[#1f3d8f] cursor-pointer"
          aria-label="Copy IPsec capture filter"
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <code className="mt-4 block break-words text-xs leading-6 sm:text-sm">{filter}</code>
      <p className="mt-3 text-xs text-white/75">
        Use in Wireshark or tshark to isolate IKE and ESP traffic.
      </p>
    </div>
  );
}

export default function HomePage() {
  const {
    data: runs,
    isLoading,
    isError,
    refetch,
  } = useQuery({
    queryKey: ["analyses-list"],
    queryFn: () => api.analyses.list(),
  });

  const {
    data: readiness,
    isLoading: readinessLoading,
    isError: readinessError,
  } = useQuery({
    queryKey: ["system-readiness"],
    queryFn: () => api.system.getReadiness(),
    refetchInterval: 30000,
  });

  const recent = runs?.slice(0, 6) ?? [];
  const latest = recent[0];
  const deps = readiness?.dependencies;

  return (
    <div className="site-shell min-h-screen flex flex-col bg-ground text-ink font-sans">
      <LandingHeader />

      <main id="main-content" className="flex-1">
        {/* Hero Section */}
        <section className="page-wrap grid gap-9 pb-12 pt-10 sm:pb-16 sm:pt-16 lg:grid-cols-[.85fr_1.15fr] lg:items-center lg:gap-12">
          <div className="relative z-10 py-3">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 mb-4 border border-line bg-panel text-[11px] font-mono uppercase tracking-wider text-ink-2">
              <span className="h-1.5 w-1.5 rounded-full bg-[#FF3D00]" />
              <span>PS 26160 · NTRO IPsec Protocol Forensics</span>
            </div>
            <h1 className="hero-statement">
              Trace every packet.
              <br />
              <span>Understand every path.</span>
            </h1>
            <p className="mt-6 max-w-[50ch] text-base leading-7 text-ink-2 sm:text-lg">
              Reconstruct IPsec sessions, assess cryptographic posture, and trace deterministic
              findings back to authoritative packet evidence.
            </p>
            <div className="mt-7 flex flex-wrap items-center gap-x-4 gap-y-3">
              <ButtonLink href="/analyses/new" variant="primary" size="lg">
                Analyze a capture
              </ButtonLink>
              <ButtonLink href="/dashboard" variant="outline" size="lg">
                <LayoutDashboard className="h-4 w-4" />
                <span>SOC Workbench</span>
              </ButtonLink>
              <a
                href="#investigation-path"
                className="inline-flex min-h-11 items-center gap-2 text-sm font-semibold underline decoration-line-strong underline-offset-4 hover:decoration-ink"
              >
                Explore path
                <ArrowRight className="h-4 w-4" />
              </a>
            </div>
            <CaptureFilter />
          </div>

          <div className="relative">
            <InvestigationGraph activeStep={0} />
            <div className="absolute -bottom-3 -left-3 hidden max-w-[13rem] border border-line bg-ground px-4 py-3 md:block">
              <div className="micro-label text-ink-3">The evidence rule</div>
              <p className="mt-1 font-serif text-xl italic leading-tight">
                Every conclusion points back to its source.
              </p>
            </div>
          </div>
        </section>

        {/* Capability Strip */}
        <section className="capability-band page-wrap grid border-y border-line py-5 sm:grid-cols-2 lg:grid-cols-4">
          <div className="py-3 pr-5">
            <span className="micro-label text-ink-3">01 / Capture</span>
            <p className="mt-2 text-sm font-semibold">Packet-level input</p>
            <p className="text-xs text-ink-3">PCAP and PCAPNG evidence</p>
          </div>
          <div className="px-5 py-3">
            <span className="micro-label text-ink-3">02 / Reconstruct</span>
            <p className="mt-2 text-sm font-semibold">IKE → SA → ESP</p>
            <p className="text-xs text-ink-3">Follow the tunnel lifecycle</p>
          </div>
          <div className="px-5 py-3">
            <span className="micro-label text-ink-3">03 / Assess</span>
            <p className="mt-2 text-sm font-semibold">Deterministic findings</p>
            <p className="text-xs text-ink-3">Security conclusions with context</p>
          </div>
          <div className="py-3 pl-5">
            <span className="micro-label text-ink-3">04 / Verify</span>
            <p className="mt-2 text-sm font-semibold">Traceable evidence</p>
            <p className="text-xs text-ink-3">Return each result to its source</p>
          </div>
        </section>

        {/* Step-by-Step Investigation Path */}
        <div id="investigation-path">
          <InvestigationPath />
        </div>

        {/* Traffic Section */}
        <section
          id="traffic"
          className="page-wrap grid gap-8 border-b border-line py-14 sm:py-20 lg:grid-cols-[.7fr_1.3fr] lg:gap-16"
        >
          <div>
            <span className="micro-label text-ink-3">02 / Traffic</span>
            <h2 className="mt-3 max-w-[11ch] font-sans text-4xl font-bold leading-[.98] tracking-[-.055em] sm:text-6xl">
              Follow the encrypted flow.
            </h2>
          </div>
          <div>
            <p className="max-w-[56ch] text-sm leading-6 text-ink-2">
              TunnelTrace relates observed IKE negotiation to reconstructed security associations and
              ESP flows. Per-capture traffic details appear inside each analysis.
            </p>
            <div className="mt-7 border-y border-line py-5">
              <div className="micro-label mb-4 text-ink-3">Protocol model · not capture data</div>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2 font-mono text-xs text-ink-2">
                <span>IKE negotiation</span>
                <ArrowRight className="h-4 w-4 text-accent-ink" />
                <span>Child SA</span>
                <ArrowRight className="h-4 w-4 text-accent-ink" />
                <span>ESP flow</span>
              </div>
            </div>
            {latest ? (
              <Link
                href={`/analyses/${latest.analysis_id}/traffic`}
                className="mt-5 inline-flex min-h-11 items-center gap-2 text-sm font-medium underline decoration-line-strong underline-offset-4 hover:decoration-ink"
              >
                Open traffic analysis for {latest.capture_filename || "the latest capture"}
                <ArrowUpRight className="h-4 w-4" />
              </Link>
            ) : (
              <Link
                href="/analyses/new"
                className="mt-5 inline-flex min-h-11 items-center gap-2 text-sm font-medium underline decoration-line-strong underline-offset-4 hover:decoration-ink"
              >
                Start with a capture
                <ArrowUpRight className="h-4 w-4" />
              </Link>
            )}
          </div>
        </section>

        {/* Detection Section */}
        <section id="detection" className="section-dark border-y border-line">
          <div className="page-wrap grid gap-10 py-14 sm:py-20 lg:grid-cols-[.8fr_1.2fr] lg:gap-16">
            <div>
              <span className="micro-label text-ink-3">03 / Detection</span>
              <h2 className="mt-3 max-w-[10ch] font-sans text-4xl font-bold leading-[.98] tracking-[-.055em] sm:text-6xl">
                Findings stay tied to evidence.
              </h2>
              <p className="mt-5 max-w-[44ch] text-sm leading-6 text-ink-2">
                Review severity and security posture from a real analysis run. TunnelTrace withholds
                a score when the capture does not support one.
              </p>
            </div>
            {latest ? (
              <div className="border-t border-line pt-4">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0">
                    <span className="micro-label text-ink-3">Most recent run</span>
                    <Link
                      href={`/analyses/${latest.analysis_id}/security`}
                      className="mt-2 block max-w-[40ch] break-words font-serif text-2xl underline decoration-line-strong underline-offset-4 hover:decoration-ink"
                    >
                      {latest.capture_filename || "Recorded capture"}
                    </Link>
                    <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-ink-3">
                      <StatusBadge status={latest.status} />
                      <span>{formatRelativeTime(latest.created_at)}</span>
                    </div>
                  </div>
                  <ScoreDisplay
                    score={latest.security_score}
                    coverage={latest.coverage_percentage}
                    riskTier={latest.risk_tier}
                    status={latest.status}
                    size="md"
                  />
                </div>
                <div className="mt-8 grid grid-cols-2 gap-6 border-t border-line pt-5 sm:max-w-md">
                  <div>
                    <div className="micro-label text-ink-3">Critical findings</div>
                    <div
                      className={`mt-2 font-mono text-4xl tabular-nums ${
                        latest.critical_findings > 0 ? "text-critical" : "text-ink"
                      }`}
                    >
                      {latest.critical_findings}
                    </div>
                  </div>
                  <div>
                    <div className="micro-label text-ink-3">High findings</div>
                    <div className="mt-2 font-mono text-4xl tabular-nums text-ink">
                      {latest.high_findings}
                    </div>
                  </div>
                </div>
                <Link
                  href={`/analyses/${latest.analysis_id}/security`}
                  className="mt-6 inline-flex min-h-11 items-center gap-2 text-sm underline decoration-line-strong underline-offset-4 hover:decoration-ink"
                >
                  Open findings
                  <ArrowUpRight className="h-4 w-4" />
                </Link>
              </div>
            ) : (
              <div className="min-h-56 border-t border-line pt-5">
                <div className="grid gap-5 xl:grid-cols-[.8fr_1.2fr] xl:items-center">
                  <div className="flex items-start gap-3">
                    <div className="grid h-11 w-11 shrink-0 place-items-center border-2 border-ink bg-accent">
                      <ShieldAlert className="h-5 w-5" />
                    </div>
                    <div>
                      <h3 className="font-sans text-2xl font-extrabold tracking-tight">
                        No findings to show yet.
                      </h3>
                      <p className="mt-2 max-w-[40ch] text-sm leading-6 text-ink-2">
                        Run a capture to create an evidence-backed security assessment.
                      </p>
                    </div>
                  </div>
                  <div className="grid gap-2 sm:grid-cols-3">
                    <div className="border border-line bg-panel p-3">
                      <FileInput className="h-4 w-4 text-brand" />
                      <div className="mt-3 text-sm font-bold">Capture</div>
                      <div className="mt-1 text-xs text-ink-3">Choose PCAP or PCAPNG</div>
                    </div>
                    <div className="border border-line bg-panel p-3">
                      <ListChecks className="h-4 w-4 text-brand" />
                      <div className="mt-3 text-sm font-bold">Assess</div>
                      <div className="mt-1 text-xs text-ink-3">Review protocol findings</div>
                    </div>
                    <div className="border border-line bg-panel p-3">
                      <Fingerprint className="h-4 w-4 text-brand" />
                      <div className="mt-3 text-sm font-bold">Verify</div>
                      <div className="mt-1 text-xs text-ink-3">Trace results to packets</div>
                    </div>
                  </div>
                </div>
                <div className="mt-5 flex flex-wrap gap-3 border-t border-line pt-4">
                  <ButtonLink href="/analyses/new" variant="primary" size="md">
                    Analyze a capture
                  </ButtonLink>
                  <ButtonLink href="/analyses" variant="primary" size="md">
                    Browse investigations
                  </ButtonLink>
                </div>
              </div>
            )}
          </div>
        </section>

        {/* Evidence Section */}
        <section
          id="evidence"
          className="page-wrap grid gap-8 border-b border-line py-14 sm:py-20 lg:grid-cols-[.7fr_1.3fr] lg:gap-16"
        >
          <div>
            <span className="micro-label text-ink-3">04 / Evidence</span>
            <h2 className="mt-3 max-w-[10ch] font-sans text-4xl font-bold leading-[.98] tracking-[-.055em] sm:text-6xl">
              Keep the source in view.
            </h2>
          </div>
          {latest ? (
            <div className="border-t border-line pt-4">
              <div className="micro-label text-ink-3">Capture hash · latest run</div>
              {latest.capture_sha256 ? (
                <code className="mt-4 block break-all font-mono text-sm leading-6 text-ink">
                  SHA-256 · {latest.capture_sha256}
                </code>
              ) : (
                <p className="mt-4 text-sm text-ink-2">A capture hash is not available for this run.</p>
              )}
              <p className="mt-4 max-w-[55ch] text-sm leading-6 text-ink-2">
                Use the evidence ledger to trace findings to packet frames and analysis lineage.
              </p>
              <Link
                href={`/analyses/${latest.analysis_id}/evidence`}
                className="mt-5 inline-flex min-h-11 items-center gap-2 text-sm font-medium underline decoration-line-strong underline-offset-4 hover:decoration-ink"
              >
                Open evidence ledger
                <ArrowUpRight className="h-4 w-4" />
              </Link>
            </div>
          ) : (
            <div className="border-t border-line pt-4">
              <div className="grid gap-6 xl:grid-cols-[1.2fr_.8fr] xl:items-center">
                <div className="border-2 border-ink bg-panel p-5 sm:p-6">
                  <div className="micro-label text-ink-3">Evidence chain · schematic</div>
                  <div className="mt-6 grid grid-cols-[1fr_auto_1fr_auto_1fr] items-center gap-2 sm:gap-4">
                    <div className="min-w-0">
                      <div className="grid h-12 w-12 place-items-center border-2 border-ink bg-brand text-white">
                        <FileInput className="h-5 w-5" />
                      </div>
                      <div className="mt-2 text-sm font-bold">Capture</div>
                      <div className="text-xs text-ink-3">Source file</div>
                    </div>
                    <ArrowRight className="h-4 w-4 text-brand" />
                    <div className="min-w-0">
                      <div className="grid h-12 w-12 place-items-center border-2 border-ink bg-accent">
                        <ListChecks className="h-5 w-5" />
                      </div>
                      <div className="mt-2 text-sm font-bold">Finding</div>
                      <div className="text-xs text-ink-3">Rule result</div>
                    </div>
                    <ArrowRight className="h-4 w-4 text-brand" />
                    <div className="min-w-0">
                      <div className="grid h-12 w-12 place-items-center border-2 border-ink bg-brand text-white">
                        <Fingerprint className="h-5 w-5" />
                      </div>
                      <div className="mt-2 text-sm font-bold">Evidence</div>
                      <div className="text-xs text-ink-3">Packet reference</div>
                    </div>
                  </div>
                </div>
                <div>
                  <h3 className="font-sans text-xl font-extrabold">Start your evidence trail.</h3>
                  <p className="mt-2 max-w-[40ch] text-sm leading-6 text-ink-2">
                    Upload an authorized capture or open a previous run. Hashes and packet references
                    appear when the analysis provides them.
                  </p>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <ButtonLink href="/analyses/new" variant="primary" size="md">
                      Choose a capture
                    </ButtonLink>
                    <ButtonLink href="/analyses" variant="primary" size="md">
                      View investigations
                    </ButtonLink>
                  </div>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* Investigations Register Section */}
        <section id="investigations" className="page-wrap py-14 sm:py-20">
          <div className="flex flex-wrap items-end justify-between gap-4 border-b border-line pb-5">
            <div>
              <span className="micro-label text-ink-3">05 / Investigation register</span>
              <h2 className="mt-3 font-sans text-4xl font-bold leading-[.98] tracking-[-.055em] sm:text-6xl">
                Your recent runs.
              </h2>
            </div>
            <Link
              href="/analyses"
              className="inline-flex min-h-11 items-center gap-2 text-sm underline decoration-line-strong underline-offset-4 hover:decoration-ink"
            >
              All investigations
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
          {isLoading ? (
            <div className="py-12 text-sm text-ink-3" role="status">
              Loading investigations…
            </div>
          ) : isError ? (
            <div
              className="flex flex-wrap items-center justify-between gap-4 border-b border-line py-8"
              role="alert"
            >
              <p className="max-w-[60ch] text-sm text-critical">
                Could not connect to the local API. Check that the backend is running, then retry.
              </p>
              <button
                type="button"
                onClick={() => refetch()}
                className="min-h-11 px-3 text-sm underline underline-offset-4 cursor-pointer"
              >
                Retry
              </button>
            </div>
          ) : recent.length === 0 ? (
            <EmptyState
              title="No investigations yet"
              description="Start with an authorized PCAP or PCAPNG capture to begin an analysis."
              action={
                <ButtonLink href="/analyses/new" variant="primary">
                  Choose a capture
                </ButtonLink>
              }
            />
          ) : (
            <div>
              <div className="hidden grid-cols-[minmax(0,1.6fr)_minmax(8rem,.7fr)_auto] gap-4 py-3 text-left micro-label text-ink-3 md:grid">
                <span>Capture</span>
                <span>State</span>
                <span>Updated</span>
              </div>
              {recent.map((run) => (
                <div
                  key={run.analysis_id}
                  className="data-row grid gap-3 py-4 md:grid-cols-[minmax(0,1.6fr)_minmax(8rem,.7fr)_auto] md:items-center md:gap-4 md:py-5"
                >
                  <div className="min-w-0">
                    <Link
                      href={`/analyses/${run.analysis_id}/overview`}
                      className="block truncate text-lg font-medium tracking-tight hover:underline"
                    >
                      {run.capture_filename || "Recorded capture"}
                    </Link>
                    <span className="mt-1 block font-mono text-[.66rem] text-ink-3">
                      {run.analysis_id.slice(0, 12)}
                    </span>
                  </div>
                  <div>
                    <span className="micro-label text-ink-3 md:hidden">Status · </span>
                    <StatusBadge status={run.status} />
                  </div>
                  <div className="flex items-center justify-between gap-3 text-xs text-ink-3">
                    <span>{formatRelativeTime(run.created_at)}</span>
                    <Link
                      href={`/analyses/${run.analysis_id}/overview`}
                      aria-label={`Open ${run.capture_filename || "investigation"}`}
                    >
                      <ArrowUpRight className="h-4 w-4" />
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Workspace Diagnostics Section */}
        <section id="workspace" className="border-t border-line bg-panel-2/50">
          <div className="page-wrap grid gap-10 py-12 sm:py-16 lg:grid-cols-[.7fr_1.3fr] lg:gap-16">
            <div>
              <span className="micro-label text-ink-3">06 / Workspace</span>
              <h2 className="mt-3 max-w-[10ch] font-sans text-4xl font-bold leading-[.98] tracking-[-.055em] sm:text-6xl">
                Local tools.
                <br />
                Visible state.
              </h2>
              <p className="mt-5 max-w-[44ch] text-sm leading-6 text-ink-2">
                Service availability comes from the local backend. When a check fails, the interface
                says so.
              </p>
              <div className="mt-6">
                <ButtonLink href="/dashboard" variant="primary" size="md">
                  <LayoutDashboard className="h-4 w-4" />
                  <span>Launch SOC Workbench</span>
                </ButtonLink>
              </div>
            </div>
            <div className="grid gap-x-12 sm:grid-cols-2">
              <div>
                <div className="micro-label mb-2 text-ink-3">Runtime</div>
                <ServiceLine label="API" value={readiness?.status} error={readinessError} />
                <ServiceLine
                  label="Database"
                  value={deps?.database?.status}
                  error={readinessError}
                />
                <ServiceLine
                  label="Job queue"
                  value={deps?.redis?.status || deps?.queue_mode?.redis_status}
                  error={readinessError}
                />
              </div>
              <div>
                <div className="micro-label mb-2 text-ink-3">Analysis tools</div>
                <ServiceLine
                  label="Capture parser"
                  value={deps?.tshark?.status}
                  error={readinessError}
                />
                <ServiceLine
                  label="Policy engine"
                  value={deps?.policy_engine?.status}
                  error={readinessError}
                />
                <div className="border-t border-line py-3 text-xs text-ink-3" role="status">
                  {readinessLoading
                    ? "Checking service status…"
                    : readinessError
                    ? "Backend is not reachable"
                    : readiness?.status || "Status unavailable"}
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Global Footer */}
      <footer className="border-t border-line bg-panel">
        <div className="page-wrap flex flex-wrap items-center justify-between gap-4 py-8 text-xs text-ink-3">
          <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4">
            <span className="font-semibold text-ink">TunnelTrace.AI</span>
            <span>Deterministic IPsec Protocol Forensics & Security Assessment</span>
            <span>·</span>
            <span>PS 26160</span>
          </div>
          <div className="flex items-center gap-6 font-mono text-[11px]">
            <Link href="/dashboard" className="text-brand hover:underline font-semibold flex items-center gap-1">
              <LayoutDashboard className="h-3 w-3" />
              <span>SOC Workbench</span>
            </Link>
            <Link href="/analyses/new" className="hover:underline">
              New Capture
            </Link>
            <Link href="/how-it-works" className="hover:underline">
              How It Works
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
