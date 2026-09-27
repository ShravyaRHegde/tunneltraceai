"use client";

import React from "react";
import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";
import {
  LayoutDashboard,
  Activity,
  UploadCloud,
  Network,
  GitBranch,
  Radio,
  ShieldAlert,
  FileCheck2,
  Grid,
  FileSearch,
  SlidersHorizontal,
  FileText,
  Bot,
  FlaskConical,
  Layers,
  Globe,
  ShieldCheck,
  FileKey2,
  Server,
  Cpu,
  PanelLeftClose,
  PanelLeftOpen,
  Info,
  HelpCircle,
} from "lucide-react";

interface SidebarProps {
  analysisId?: string | null;
  isOpen?: boolean;
  onClose?: () => void;
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
}

function SidebarInner({
  analysisId,
  isOpen = true,
  onClose,
  isCollapsed = false,
  onToggleCollapse,
}: SidebarProps) {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const currentTab = searchParams ? searchParams.get("tab") : null;
  const id = analysisId || "";

  // Query live readiness for truthful status in sidebar footer
  const { data: readiness, isError: isReadinessError } = useQuery({
    queryKey: ["system-readiness"],
    queryFn: () => api.system.getReadiness(),
    refetchInterval: 30000,
  });

  const isMonitoringRoute = pathname === "/monitoring";

  return (
    <aside
      className={`fixed inset-y-0 left-0 z-40 ${
        isCollapsed ? "lg:w-16 w-64" : "w-64"
      } bg-white dark:bg-[#111113] border-r border-neutral-300 dark:border-neutral-800 flex flex-col h-full transform transition-all duration-200 lg:static lg:translate-x-0 shrink-0 ${
        isOpen ? "translate-x-0" : "-translate-x-full"
      }`}
    >
      {/* Brand Header */}
      <div
        className={`h-14 ${
          isCollapsed ? "px-2 justify-center" : "px-4 justify-between"
        } flex items-center border-b border-neutral-300 dark:border-neutral-800 bg-neutral-100 dark:bg-black shrink-0`}
      >
        {isCollapsed ? (
          <button
            type="button"
            onClick={onToggleCollapse}
            className="p-1.5 text-neutral-500 hover:text-neutral-900 dark:hover:text-white rounded hover:bg-neutral-200 dark:hover:bg-neutral-800 transition-colors flex items-center justify-center group"
            title="Expand sidebar"
            aria-label="Expand sidebar"
          >
            <div className="w-7 h-7 bg-[#FF3D00] flex items-center justify-center text-white font-mono font-bold text-xs shrink-0 rounded-sm shadow-sm group-hover:scale-105 transition-transform">
              T
            </div>
          </button>
        ) : (
          <>
            <Link href="/" className="flex items-center space-x-2" title="TunnelTrace AI Home">
              <div className="w-6 h-6 bg-[#FF3D00] flex items-center justify-center text-white font-mono font-bold text-xs shrink-0 rounded-sm shadow-sm">
                T
              </div>
              <span className="font-mono font-bold text-sm tracking-widest text-neutral-900 dark:text-white uppercase truncate">
                TunnelTrace<span className="text-[#FF3D00]">.AI</span>
              </span>
            </Link>
            <div className="flex items-center space-x-1.5">
              <span className="text-[10px] font-mono px-1.5 py-0.5 border border-neutral-300 dark:border-neutral-700 text-neutral-700 dark:text-neutral-300 font-bold uppercase">
                PS 26160
              </span>
              {onToggleCollapse && (
                <button
                  type="button"
                  onClick={onToggleCollapse}
                  className="hidden lg:flex p-1 text-neutral-500 hover:text-neutral-900 dark:hover:text-white rounded hover:bg-neutral-200 dark:hover:bg-neutral-800 transition-colors"
                  title="Collapse sidebar"
                  aria-label="Collapse sidebar"
                >
                  <PanelLeftClose className="w-4 h-4" />
                </button>
              )}
            </div>
          </>
        )}
      </div>

      {/* Navigation Groups */}
      <div className={`flex-1 overflow-y-auto ${isCollapsed ? "p-1.5 space-y-3" : "p-3 space-y-4"}`}>
        {/* GROUP 1: START */}
        <div className="space-y-1">
          {!isCollapsed && (
            <div className="px-2 pb-0.5">
              <h4 className="text-[10px] font-mono font-bold text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                START
              </h4>
            </div>
          )}
          <div className="space-y-0.5">
            <Link
              href="/"
              onClick={onClose}
              title="Home Dashboard"
              className={`flex items-center ${
                isCollapsed ? "justify-center px-1 py-2" : "justify-between px-2.5 py-1.5"
              } text-xs transition-colors border ${
                pathname === "/"
                  ? "bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-white font-semibold border-l-2 border-l-[#FF3D00] border-t-transparent border-r-transparent border-b-transparent"
                  : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-neutral-900/60 border-transparent"
              }`}
            >
              <div className="flex items-center space-x-2.5">
                <LayoutDashboard className="w-3.5 h-3.5 shrink-0" />
                {!isCollapsed && <span>Home Dashboard</span>}
              </div>
            </Link>

            <Link
              href="/how-it-works"
              onClick={onClose}
              title="How It Works (System Architecture & Flow)"
              className={`flex items-center ${
                isCollapsed ? "justify-center px-1 py-2" : "justify-between px-2.5 py-1.5"
              } text-xs transition-colors border ${
                pathname === "/how-it-works"
                  ? "bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-white font-semibold border-l-2 border-l-[#FF3D00] border-t-transparent border-r-transparent border-b-transparent"
                  : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-neutral-900/60 border-transparent"
              }`}
            >
              <div className="flex items-center space-x-2.5">
                <HelpCircle className="w-3.5 h-3.5 shrink-0 text-[#FF3D00]" />
                {!isCollapsed && <span className="font-semibold text-neutral-900 dark:text-neutral-200">How It Works (Guide)</span>}
              </div>
              {!isCollapsed && (
                <span className="text-[9px] font-mono px-1 py-0.2 bg-[#FF3D00]/10 text-[#FF3D00] font-bold uppercase rounded-xs">
                  FLOW
                </span>
              )}
            </Link>
          </div>
        </div>

        {/* GROUP 2: ANALYZE */}
        <div className="space-y-1">
          {!isCollapsed && (
            <div className="px-2 pb-0.5">
              <h4 className="text-[10px] font-mono font-bold text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                ANALYZE
              </h4>
              <p className="text-[9px] text-neutral-400 dark:text-neutral-500 leading-tight">
                Forensic capture ingestion & catalog
              </p>
            </div>
          )}
          <div className="space-y-0.5">
            <Link
              href="/analyses/new"
              onClick={onClose}
              title="Ingest Capture (Upload PCAP/PCAPNG)"
              className={`flex items-center ${
                isCollapsed ? "justify-center px-1 py-2" : "justify-between px-2.5 py-1.5"
              } text-xs transition-colors border ${
                pathname === "/analyses/new"
                  ? "bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-white font-semibold border-l-2 border-l-[#FF3D00] border-t-transparent border-r-transparent border-b-transparent"
                  : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-neutral-900/60 border-transparent"
              }`}
            >
              <div className="flex items-center space-x-2.5">
                <UploadCloud className="w-3.5 h-3.5 shrink-0" />
                {!isCollapsed && <span>Ingest Capture</span>}
              </div>
              {!isCollapsed && <span className="text-[9px] font-mono text-neutral-400 uppercase">Upload</span>}
            </Link>

            <Link
              href="/analyses"
              onClick={onClose}
              title="Investigation Catalog"
              className={`flex items-center ${
                isCollapsed ? "justify-center px-1 py-2" : "justify-between px-2.5 py-1.5"
              } text-xs transition-colors border ${
                pathname === "/analyses"
                  ? "bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-white font-semibold border-l-2 border-l-[#FF3D00] border-t-transparent border-r-transparent border-b-transparent"
                  : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-neutral-900/60 border-transparent"
              }`}
            >
              <div className="flex items-center space-x-2.5">
                <Layers className="w-3.5 h-3.5 shrink-0" />
                {!isCollapsed && <span>Investigation Catalog</span>}
              </div>
            </Link>
          </div>

          {/* Run-scoped Forensic Sections */}
          <div className={`${isCollapsed ? "pt-1" : "pt-2 pl-2 border-l border-neutral-200 dark:border-neutral-800 ml-2 mt-2"} space-y-0.5`}>
            {!isCollapsed && (
              <div className="px-1 pb-1">
                <span className="text-[9px] font-mono font-bold text-neutral-400 uppercase">
                  {analysisId ? `RUN: ${analysisId.slice(0, 8)}...` : "RUN FORENSICS (SELECT RUN)"}
                </span>
              </div>
            )}

            {!analysisId && !isCollapsed && (
              <div className="p-2 mb-1.5 bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 text-[10px] text-neutral-500 font-mono space-y-1.5">
                <div className="flex items-start space-x-1">
                  <Info className="w-3 h-3 text-[#FF3D00] shrink-0 mt-0.5" />
                  <span>Select a run to unlock dissection:</span>
                </div>
                <div className="flex items-center space-x-1">
                  <Link
                    href="/analyses"
                    onClick={onClose}
                    className="text-[#FF3D00] font-bold hover:underline"
                  >
                    Choose Run
                  </Link>
                  <span>or</span>
                  <Link
                    href="/analyses/new"
                    onClick={onClose}
                    className="text-[#FF3D00] font-bold hover:underline"
                  >
                    Upload
                  </Link>
                </div>
              </div>
            )}

            {[
              { name: "Session Overview", href: `/analyses/${id}/overview`, icon: Activity },
              { name: "Protocol Dissection", href: `/analyses/${id}/protocol`, icon: Network },
              { name: "SAs & ESP Flows", href: `/analyses/${id}/sas`, icon: GitBranch },
              { name: "Traffic & ML Intelligence", href: `/analyses/${id}/traffic`, icon: Radio },
              { name: "Security Assessment", href: `/analyses/${id}/security`, icon: ShieldAlert },
              { name: "Compliance Scorecard", href: `/analyses/${id}/compliance`, icon: FileCheck2 },
              { name: "Threat Matrix", href: `/analyses/${id}/threats`, icon: Grid },
              { name: "Evidence DAG", href: `/analyses/${id}/evidence`, icon: FileSearch },
              { name: "Audit Reports", href: `/analyses/${id}/reports`, icon: FileText },
              { name: "SOC AI Copilot", href: `/analyses/${id}/ai-analyst`, icon: Bot },
              { name: "Configuration Twin", href: `/analyses/${id}/remediation`, icon: SlidersHorizontal },
            ].map((sub) => {
              const Icon = sub.icon;
              const isActive = analysisId ? pathname === sub.href : false;

              if (!analysisId) {
                return (
                  <Link
                    key={sub.name}
                    href="/analyses"
                    onClick={onClose}
                    title={sub.name}
                    className={`flex items-center ${
                      isCollapsed ? "justify-center px-1 py-1.5" : "justify-between px-2 py-1"
                    } text-[11px] text-neutral-400 dark:text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 transition-colors`}
                  >
                    <div className="flex items-center space-x-2">
                      <Icon className="w-3.5 h-3.5 shrink-0" />
                      {!isCollapsed && <span className="truncate">{sub.name}</span>}
                    </div>
                  </Link>
                );
              }

              return (
                <Link
                  key={sub.name}
                  href={sub.href}
                  onClick={onClose}
                  title={sub.name}
                  className={`flex items-center ${
                    isCollapsed ? "justify-center px-1 py-1.5" : "justify-between px-2 py-1"
                  } text-[11px] transition-colors border ${
                    isActive
                      ? "bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-white font-semibold border-l-2 border-l-[#FF3D00] border-t-transparent border-r-transparent border-b-transparent"
                      : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-neutral-900/60 border-transparent"
                  }`}
                >
                  <div className="flex items-center space-x-2">
                    <Icon className="w-3.5 h-3.5 shrink-0" />
                    {!isCollapsed && <span className="truncate">{sub.name}</span>}
                  </div>
                </Link>
              );
            })}
          </div>
        </div>

        {/* GROUP 3: LIVE MONITOR */}
        <div className="space-y-1">
          {!isCollapsed && (
            <div className="px-2 pb-0.5">
              <h4 className="text-[10px] font-mono font-bold text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                LIVE MONITOR
              </h4>
              <p className="text-[9px] text-neutral-400 dark:text-neutral-500 leading-tight">
                Gateway telemetry & SA lifecycle
              </p>
            </div>
          )}
          <div className="space-y-0.5">
            {[
              {
                name: "Fleet Health & Status",
                href: "/monitoring?tab=fleet",
                tabKey: "fleet",
                icon: Activity,
                defaultTab: true,
              },
              {
                name: "Monitored Gateways",
                href: "/monitoring?tab=gateways",
                tabKey: "gateways",
                icon: Server,
              },
              {
                name: "Telemetry Sensors",
                href: "/monitoring?tab=sensors",
                tabKey: "sensors",
                icon: Cpu,
              },
              {
                name: "Projected SAs",
                href: "/monitoring?tab=sa_states",
                tabKey: "sa_states",
                icon: GitBranch,
              },
              {
                name: "Event Timeline",
                href: "/monitoring?tab=timeline",
                tabKey: "timeline",
                icon: Layers,
              },
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive =
                isMonitoringRoute &&
                (currentTab === tab.tabKey || (!currentTab && tab.defaultTab));

              return (
                <Link
                  key={tab.name}
                  href={tab.href}
                  onClick={onClose}
                  title={tab.name}
                  aria-current={isActive ? "page" : undefined}
                  className={`flex items-center ${
                    isCollapsed ? "justify-center px-1 py-1.5" : "justify-between px-2.5 py-1.5"
                  } text-xs transition-colors border ${
                    isActive
                      ? "bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-white font-semibold border-l-2 border-l-[#FF3D00] border-t-transparent border-r-transparent border-b-transparent"
                      : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-neutral-900/60 border-transparent"
                  }`}
                >
                  <div className="flex items-center space-x-2.5">
                    <Icon className="w-3.5 h-3.5 shrink-0" />
                    {!isCollapsed && <span className="truncate">{tab.name}</span>}
                  </div>
                </Link>
              );
            })}
          </div>
        </div>

        {/* GROUP 4: ASSETS & ASSESSMENTS */}
        <div className="space-y-1">
          {!isCollapsed && (
            <div className="px-2 pb-0.5">
              <h4 className="text-[10px] font-mono font-bold text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                ASSETS & ASSESSMENTS
              </h4>
              <p className="text-[9px] text-neutral-400 dark:text-neutral-500 leading-tight">
                Network probes & vulnerability ingestion
              </p>
            </div>
          )}
          <div className="space-y-0.5">
            <Link
              href="/discovery"
              onClick={onClose}
              title="Nmap Asset Discovery"
              className={`flex items-center ${
                isCollapsed ? "justify-center px-1 py-1.5" : "justify-between px-2.5 py-1.5"
              } text-xs transition-colors border ${
                pathname === "/discovery"
                  ? "bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-white font-semibold border-l-2 border-l-[#FF3D00] border-t-transparent border-r-transparent border-b-transparent"
                  : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-neutral-900/60 border-transparent"
              }`}
            >
              <div className="flex items-center space-x-2.5">
                <Globe className="w-3.5 h-3.5 shrink-0" />
                {!isCollapsed && <span>Nmap Asset Discovery</span>}
              </div>
            </Link>

            <Link
              href="/inventory"
              onClick={onClose}
              title="Config & Cert Inventory"
              className={`flex items-center ${
                isCollapsed ? "justify-center px-1 py-1.5" : "justify-between px-2.5 py-1.5"
              } text-xs transition-colors border ${
                pathname === "/inventory"
                  ? "bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-white font-semibold border-l-2 border-l-[#FF3D00] border-t-transparent border-r-transparent border-b-transparent"
                  : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-neutral-900/60 border-transparent"
              }`}
            >
              <div className="flex items-center space-x-2.5">
                <FileKey2 className="w-3.5 h-3.5 shrink-0" />
                {!isCollapsed && <span>Config & Cert Inventory</span>}
              </div>
            </Link>

            <Link
              href="/vulnerabilities"
              onClick={onClose}
              title="Vulnerability Feed (OpenVAS/Greenbone)"
              className={`flex items-center ${
                isCollapsed ? "justify-center px-1 py-1.5" : "justify-between px-2.5 py-1.5"
              } text-xs transition-colors border ${
                pathname === "/vulnerabilities"
                  ? "bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-white font-semibold border-l-2 border-l-[#FF3D00] border-t-transparent border-r-transparent border-b-transparent"
                  : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-neutral-900/60 border-transparent"
              }`}
            >
              <div className="flex items-center space-x-2.5">
                <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
                {!isCollapsed && <span>Vulnerability Feed</span>}
              </div>
              {!isCollapsed && <span className="text-[9px] font-mono text-neutral-400 uppercase">OpenVAS</span>}
            </Link>
          </div>
        </div>

        {/* GROUP 5: LAB & TESTBED */}
        <div className="space-y-1">
          {!isCollapsed && (
            <div className="px-2 pb-0.5">
              <h4 className="text-[10px] font-mono font-bold text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                LAB & TESTBED
              </h4>
              <p className="text-[9px] text-neutral-400 dark:text-neutral-500 leading-tight">
                strongSwan namespace testbed
              </p>
            </div>
          )}
          <div className="space-y-0.5">
            <Link
              href="/lab"
              onClick={onClose}
              title="Lab Testbed Orchestrator (9 Dual-strongSwan Scenarios)"
              className={`flex items-center ${
                isCollapsed ? "justify-center px-1 py-1.5" : "justify-between px-2.5 py-1.5"
              } text-xs transition-colors border ${
                pathname === "/lab"
                  ? "bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-white font-semibold border-l-2 border-l-[#FF3D00] border-t-transparent border-r-transparent border-b-transparent"
                  : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-neutral-900/60 border-transparent"
              }`}
            >
              <div className="flex items-center space-x-2.5">
                <FlaskConical className="w-3.5 h-3.5 shrink-0" />
                {!isCollapsed && <span>Lab Testbed Orchestrator</span>}
              </div>
              {!isCollapsed && <span className="text-[9px] font-mono text-neutral-400 uppercase">Namespace</span>}
            </Link>
          </div>
        </div>
      </div>

      {/* Footer Info: Truthful Runtime Health */}
      <div className="p-3 border-t border-neutral-300 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950 text-[10px] font-mono shrink-0">
        {isCollapsed ? (
          <div className="flex justify-center">
            {isReadinessError ? (
              <span className="text-rose-500 font-bold" title="API Status: Offline">●</span>
            ) : readiness?.status === "READY" ? (
              <span className="text-emerald-600 dark:text-emerald-400 font-bold" title="API Status: Ready">●</span>
            ) : (
              <span className="text-amber-600 dark:text-amber-400 font-bold" title="API Status: Local Dev Ready">●</span>
            )}
          </div>
        ) : (
          <div className="flex justify-between items-center">
            <span className="text-neutral-500">NTRO / SIH 26160</span>
            {isReadinessError ? (
              <span className="text-rose-500 font-bold">● OFFLINE</span>
            ) : readiness?.status === "READY" ? (
              <span className="text-emerald-600 dark:text-emerald-400 font-bold">● READY</span>
            ) : readiness?.dependencies?.database?.status === "UP" ? (
              <span
                className="text-amber-600 dark:text-amber-400 font-bold"
                title="Database & TShark UP. Redis eager in-process tasks. Windows capture unconfigured."
              >
                ● LOCAL DEV
              </span>
            ) : (
              <span className="text-neutral-400 font-bold">● POLLING</span>
            )}
          </div>
        )}
      </div>
    </aside>
  );
}

export function Sidebar(props: SidebarProps) {
  return (
    <React.Suspense
      fallback={
        <aside className="w-64 bg-white dark:bg-[#111113] border-r border-neutral-300 dark:border-neutral-800 shrink-0" />
      }
    >
      <SidebarInner {...props} />
    </React.Suspense>
  );
}
