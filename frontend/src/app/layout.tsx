import type { Metadata, Viewport } from "next";
import "./globals.css";
import { QueryProvider } from "@/lib/query-provider";
import { AnalysisProvider } from "@/lib/analysis-context";
import { AppShell } from "@/components/layout/app-shell";

export const metadata: Metadata = {
  title: "TunnelTrace AI — Explainable IPsec Security Intelligence Platform",
  description:
    "AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework (NTRO PS 26160).",
  manifest: "/manifest.json",
  icons: {
    icon: "/favicon.ico",
    apple: "/icon-192.png",
  },
};

export const viewport: Viewport = {
  themeColor: "#FF3D00",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="h-full" suppressHydrationWarning>
      <head>
        <link rel="manifest" href="/manifest.json" />
        <script
          id="theme-initializer"
          suppressHydrationWarning
          dangerouslySetInnerHTML={{
            __html: `
              try {
                if (localStorage.theme === 'dark') {
                  document.documentElement.classList.add('dark');
                } else {
                  document.documentElement.classList.remove('dark');
                }
              } catch (_) {}
            `,
          }}
        />
      </head>
      <body className="h-full antialiased selection:bg-[#FF3D00] selection:text-white">
        <QueryProvider>
          <AnalysisProvider>
            <AppShell>{children}</AppShell>
          </AnalysisProvider>
        </QueryProvider>
      </body>
    </html>
  );
}
