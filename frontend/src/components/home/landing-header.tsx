"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ArrowUpRight, Menu, X, LayoutDashboard, UploadCloud } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/client";

const navItems = [
  { label: "Workbench", href: "/dashboard" },
  { label: "Investigations", href: "/analyses" },
  { label: "Live Monitoring", href: "/monitoring" },
  { label: "Asset Inventory", href: "/inventory" },
  { label: "Lab & Twin", href: "/lab" },
  { label: "How It Works", href: "/how-it-works" },
];

export function LandingHeader() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  const { data: readiness, isError, isLoading } = useQuery({
    queryKey: ["system-readiness"],
    queryFn: () => api.system.getReadiness(),
    refetchInterval: 30000,
  });

  const apiStatus = isError
    ? "API offline"
    : readiness?.status === "READY"
    ? "API ready"
    : readiness?.status
    ? `API · ${readiness.status.replaceAll("_", " ").toLowerCase()}`
    : isLoading
    ? "Checking API"
    : "API status unavailable";

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

  return (
    <header className="site-header border-b border-line" data-scrolled={scrolled}>
      <div className="header-inner flex min-h-[4.6rem] items-center justify-between gap-4">
        <Link href="/" aria-label="TunnelTrace.AI home" className="site-wordmark flex shrink-0 items-center gap-2.5">
          <div className="w-7 h-7 bg-white text-[#FF3D00] flex items-center justify-center font-mono font-black text-xs shrink-0 rounded-xs shadow-sm">
            T
          </div>
          <span>
            TunnelTrace<span className="align-top font-sans text-[.58rem] font-semibold tracking-normal text-white/90">.AI</span>
          </span>
        </Link>

        <nav aria-label="Primary navigation" className="hidden items-center gap-1 xl:flex">
          {navItems.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="site-nav-link"
            >
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="flex shrink-0 items-center gap-2 sm:gap-3">
          <div
            className="flex items-center gap-2 text-[.63rem] uppercase tracking-[.08em] text-white/80"
            title={apiStatus}
            aria-live="polite"
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                isError || readiness?.status === "FAILED"
                  ? "bg-critical"
                  : readiness?.status === "READY"
                  ? "bg-white"
                  : "bg-white/60"
              }`}
            />
            <span className="hidden sm:inline">{apiStatus}</span>
          </div>

          <Link
            href="/dashboard"
            className="editorial-btn editorial-btn-primary inline-flex min-h-10 items-center gap-2 px-3 text-xs font-bold uppercase tracking-wider sm:px-4 sm:text-sm bg-white text-[#FF3D00] hover:bg-black hover:text-white border-2 border-black"
          >
            <LayoutDashboard className="h-4 w-4" />
            <span>Launch Workbench</span>
          </Link>

          <button
            type="button"
            onClick={() => setMobileOpen((open) => !open)}
            aria-label={mobileOpen ? "Close navigation" : "Open navigation"}
            aria-expanded={mobileOpen}
            aria-controls="mobile-navigation"
            className="grid h-10 w-10 place-items-center border border-white/50 text-white xl:hidden cursor-pointer"
          >
            {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>
      </div>

      {mobileOpen && (
        <div id="mobile-navigation" className="border-t border-line bg-[#FF3D00] text-white xl:hidden">
          <nav aria-label="Mobile navigation" className="header-inner grid py-3">
            {navItems.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className="border-b border-white/20 py-3 text-[15px] font-semibold flex items-center justify-between"
              >
                <span>{item.label}</span>
                <ArrowUpRight className="h-4 w-4" />
              </Link>
            ))}
            <Link
              href="/analyses/new"
              className="mt-3 inline-flex items-center justify-center gap-2 bg-white text-[#FF3D00] hover:bg-black hover:text-white py-2.5 px-4 font-bold uppercase text-xs border-2 border-black"
            >
              <UploadCloud className="h-4 w-4" />
              <span>Analyze Capture</span>
            </Link>
          </nav>
        </div>
      )}
    </header>
  );
}
