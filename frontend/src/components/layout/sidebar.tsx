"use client";

import React, { useState, useEffect } from "react";
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
  PanelLeftClose,
  HelpCircle,
  ChevronDown,
  ChevronRight,
  Terminal,
  X,
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
  const id = analysisId || "";

  // Query live readiness for truthful status in sidebar footer
  const { data: readiness, isError: isReadinessError } = useQuery({
    queryKey: ["system-readiness"],
    queryFn: () => api.system.getReadiness(),
    refetchInterval: 30000,
  });

  // Group accordion state: analyze open by default, supporting groups auto-expand on route match
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({
    analyze: true,
    testbed: pathname.startsWith("/monitoring") || pathname.startsWith("/lab"),
    advanced:
      pathname.startsWith("/discovery") ||
      pathname.startsWith("/inventory") ||
      pathname.startsWith("/vulnerabilities"),
  });

  // Keep group containing active route open on navigation
  useEffect(() => {
    if (pathname.startsWith("/analyses")) {
      setOpenGroups((prev) => ({ ...prev, analyze: true }));
    } else if (pathname.startsWith("/monitoring") || pathname.startsWith("/lab")) {
      setOpenGroups((prev) => ({ ...prev, testbed: true }));
    } else if (
      pathname.startsWith("/discovery") ||
      pathname.startsWith("/inventory") ||
      pathname.startsWith("/vulnerabilities")
    ) {
      setOpenGroups((prev) => ({ ...prev, advanced: true }));
    }
  }, [pathname]);

  const toggleGroup = (key: string) => {
    setOpenGroups((prev) => ({ ...prev, [key]: !prev[key] }));
  };

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
              {/* Desktop Collapse Toggle */}
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
              {/* Mobile Close Button */}
              {onClose && (
                <button
                  type="button"
                  onClick={onClose}
                  className="lg:hidden p-1 text-neutral-500 hover:text-neutral-900 dark:hover:text-white rounded hover:bg-neutral-200 dark:hover:bg-neutral-800 transition-colors"
                  title="Close sidebar"
                  aria-label="Close sidebar"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
          </>
        )}
      </div>

      {/* Persistent First-Class Dashboard */}
      <div className={`pt-2.5 pb-1 ${isCollapsed ? "px-1.5" : "px-3"}`}>
        <Link
          href="/dashboard"
          onClick={onClose}
          title="Operational Dashboard"
          className={`w-full flex items-center ${
            isCollapsed ? "justify-center px-1 py-2" : "justify-between px-2.5 py-2"
          } text-xs rounded font-mono transition-all border ${
            pathname === "/dashboard"
              ? "bg-[#FF3D00]/10 text-[#FF3D00] dark:text-[#FF3D00] font-bold border-[#FF3D00]/40 shadow-xs"
              : "text-neutral-700 dark:text-neutral-300 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-100 dark:hover:bg-neutral-800/80 border-neutral-200/60 dark:border-neutral-800/60"
          }`}
        >
          <div className="flex items-center space-x-2.5">
            <LayoutDashboard className={`w-4 h-4 shrink-0 ${pathname === "/dashboard" ? "text-[#FF3D00]" : "text-neutral-500"}`} />
            {!isCollapsed && <span className="font-bold uppercase tracking-wider text-[11px]">Dashboard</span>}
          </div>
          {!isCollapsed && (
            <span className="text-[9px] font-mono px-1 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 uppercase font-bold">
              OPERATIONAL
            </span>
          )}
        </Link>
      </div>

      {/* Navigation Groups */}
      <div className={`flex-1 overflow-y-auto ${isCollapsed ? "p-1.5 space-y-3" : "p-3 space-y-3"}`}>
        {/* GROUP: INVESTIGATIONS & FORENSICS */}
        <div className="space-y-1">
          {!isCollapsed && (
            <button
              type="button"
              onClick={() => toggleGroup("analyze")}
              className="w-full flex items-center justify-between px-2 py-1 text-[10px] font-mono font-bold text-neutral-500 dark:text-neutral-400 uppercase tracking-wider hover:text-neutral-900 dark:hover:text-white transition-colors"
            >
              <span>Investigations & Forensics</span>
              {openGroups.analyze ? (
                <ChevronDown className="w-3 h-3 text-neutral-400" />
              ) : (
                <ChevronRight className="w-3 h-3 text-neutral-400" />
              )}
            </button>
          )}

          {(isCollapsed || openGroups.analyze) && (
            <div className="space-y-0.5">
              <Link
                href="/analyses/new"
                onClick={onClose}
                title="New Analysis (Upload PCAP/PCAPNG)"
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
                  {!isCollapsed && <span>New Analysis</span>}
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

              {/* Run Forensics Sub-group: Only visible when a run is active */}
              {analysisId && (
                <div className={`${isCollapsed ? "pt-1" : "pt-2 pl-2 border-l-2 border-neutral-200 dark:border-neutral-800 ml-2 mt-2"} space-y-0.5`}>
                  {!isCollapsed && (
                    <div className="px-1 pb-1">
                      <span className="text-[9px] font-mono font-bold text-neutral-400 uppercase block truncate">
                        Run: {analysisId.slice(0, 8)}...
                      </span>
                    </div>
                  )}

                  {[
                    { name: "Overview", href: `/analyses/${id}/overview`, icon: Activity },
                    { name: "Protocol", href: `/analyses/${id}/protocol`, icon: Network },
                    { name: "SAs & ESP Flows", href: `/analyses/${id}/sas`, icon: GitBranch },
                    { name: "Traffic & ML", href: `/analyses/${id}/traffic`, icon: Radio },
                    { name: "Security Assessment", href: `/analyses/${id}/security`, icon: ShieldAlert },
                    { name: "Compliance Scorecard", href: `/analyses/${id}/compliance`, icon: FileCheck2 },
                    { name: "Threat Matrix", href: `/analyses/${id}/threats`, icon: Grid },
                    { name: "Evidence DAG", href: `/analyses/${id}/evidence`, icon: FileSearch },
                    { name: "Audit Reports", href: `/analyses/${id}/reports`, icon: FileText },
                    { name: "AI Analyst", href: `/analyses/${id}/ai-analyst`, icon: Bot },
                    { name: "Configuration Twin", href: `/analyses/${id}/remediation`, icon: SlidersHorizontal },
                  ].map((sub) => {
                    const Icon = sub.icon;
                    const isActive = pathname === sub.href;

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
              )}
            </div>
          )}
        </div>

        {/* GROUP 3: TESTBED & CAPTURE (LINUX REQUIRED) */}
        <div className="space-y-1">
          {!isCollapsed && (
            <button
              type="button"
              onClick={() => toggleGroup("testbed")}
              className="w-full flex items-center justify-between px-2 py-1 text-[10px] font-mono font-bold text-neutral-500 dark:text-neutral-400 uppercase tracking-wider hover:text-neutral-900 dark:hover:text-white transition-colors"
            >
              <div className="flex items-center space-x-1.5">
                <span>Testbed & Capture</span>
                <span className="text-[9px] font-mono px-1 py-0.2 border border-neutral-300 dark:border-neutral-700 text-neutral-500 rounded-xs">
                  Linux
                </span>
              </div>
              {openGroups.testbed ? (
                <ChevronDown className="w-3 h-3 text-neutral-400" />
              ) : (
                <ChevronRight className="w-3 h-3 text-neutral-400" />
              )}
            </button>
          )}

          {(isCollapsed || openGroups.testbed) && (
            <div className="space-y-0.5">
              <Link
                href="/lab"
                onClick={onClose}
                title="Lab Scenarios (strongSwan namespace testbed)"
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
                  {!isCollapsed && <span>Lab Scenarios</span>}
                </div>
                {!isCollapsed && <span className="text-[9px] font-mono text-neutral-400 uppercase">Namespace</span>}
              </Link>

              <Link
                href="/monitoring"
                onClick={onClose}
                title="Live Gateway Monitor & Telemetry"
                className={`flex items-center ${
                  isCollapsed ? "justify-center px-1 py-1.5" : "justify-between px-2.5 py-1.5"
                } text-xs transition-colors border ${
                  pathname === "/monitoring"
                    ? "bg-neutral-100 dark:bg-neutral-800 text-neutral-900 dark:text-white font-semibold border-l-2 border-l-[#FF3D00] border-t-transparent border-r-transparent border-b-transparent"
                    : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-neutral-900/60 border-transparent"
                }`}
              >
                <div className="flex items-center space-x-2.5">
                  <Server className="w-3.5 h-3.5 shrink-0" />
                  {!isCollapsed && <span>Live Monitor</span>}
                </div>
              </Link>
            </div>
          )}
        </div>

        {/* GROUP 4: ADVANCED / OPERATIONS */}
        <div className="space-y-1">
          {!isCollapsed && (
            <button
              type="button"
              onClick={() => toggleGroup("advanced")}
              className="w-full flex items-center justify-between px-2 py-1 text-[10px] font-mono font-bold text-neutral-500 dark:text-neutral-400 uppercase tracking-wider hover:text-neutral-900 dark:hover:text-white transition-colors"
            >
              <span>Advanced / Ops</span>
              {openGroups.advanced ? (
                <ChevronDown className="w-3 h-3 text-neutral-400" />
              ) : (
                <ChevronRight className="w-3 h-3 text-neutral-400" />
              )}
            </button>
          )}

          {(isCollapsed || openGroups.advanced) && (
            <div className="space-y-0.5">
              <Link
                href="/inventory"
                onClick={onClose}
                title="Configuration & Cert Inventory"
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
                  {!isCollapsed && <span>Config & Certs</span>}
                </div>
              </Link>

              <Link
                href="/discovery"
                onClick={onClose}
                title="Nmap Asset Discovery (Requires Nmap)"
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
                  {!isCollapsed && <span>Asset Discovery</span>}
                </div>
              </Link>

              <Link
                href="/vulnerabilities"
                onClick={onClose}
                title="Vulnerability Feed (Greenbone / OpenVAS)"
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
              </Link>
            </div>
          )}
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
