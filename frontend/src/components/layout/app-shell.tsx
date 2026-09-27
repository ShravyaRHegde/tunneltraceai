"use client";

import React, { useState, useEffect } from "react";
import { Sidebar } from "./sidebar";
import { Header } from "./header";
import { OfflineBanner } from "./offline-banner";
import { useAnalysis } from "@/lib/analysis-context";

export function AppShell({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [desktopCollapsed, setDesktopCollapsed] = useState(false);
  const { activeAnalysisId } = useAnalysis();

  // Escape key closes mobile sidebar drawer
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && sidebarOpen) {
        setSidebarOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [sidebarOpen]);

  useEffect(() => {
    if ("serviceWorker" in navigator && process.env.NODE_ENV === "production") {
      navigator.serviceWorker
        .register("/sw.js")
        .then(() => {
          // SW registered safely
        })
        .catch(() => {
          // SW registration ignored in dev/unsupported environments
        });
    }
  }, []);

  return (
    <div className="h-screen bg-[#F7F7F4] dark:bg-[#0E0E10] text-neutral-900 dark:text-neutral-100 flex flex-col font-sans overflow-hidden">
      <OfflineBanner />

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <Sidebar
          analysisId={activeAnalysisId}
          isOpen={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
          isCollapsed={desktopCollapsed}
          onToggleCollapse={() => setDesktopCollapsed(!desktopCollapsed)}
        />

        {/* Backdrop for mobile */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 bg-black/50 z-30 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
          <Header onToggleSidebar={() => setSidebarOpen(!sidebarOpen)} />
          <main className="flex-1 p-4 lg:p-6 max-w-[1600px] w-full mx-auto space-y-6">
            {children}
          </main>
        </div>
      </div>
    </div>
  );
}
