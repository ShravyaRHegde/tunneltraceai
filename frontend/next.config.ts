import type { NextConfig } from "next";

const cspHeader = `
    default-src 'self';
    script-src 'self' 'unsafe-eval' 'unsafe-inline';
    style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
    img-src 'self' blob: data:;
    font-src 'self' data: https://fonts.gstatic.com;
    connect-src 'self' http://127.0.0.1:8000 ws://127.0.0.1:8000 http://localhost:8000 ws://localhost:8000 http://127.0.0.1:8002 ws://127.0.0.1:8002 http://localhost:8002 ws://localhost:8002;
    frame-src 'self';
    frame-ancestors 'self';
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    upgrade-insecure-requests;
`.replace(/\s{2,}/g, " ").trim();

const nextConfig: NextConfig = {
  reactStrictMode: true,
  allowedDevOrigins: ["127.0.0.1", "localhost", "127.0.0.1:3002", "localhost:3002"],
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          {
            key: "Content-Security-Policy",
            value: cspHeader,
          },
          {
            key: "X-Frame-Options",
            value: "SAMEORIGIN",
          },
          {
            key: "X-Content-Type-Options",
            value: "nosniff",
          },
          {
            key: "Referrer-Policy",
            value: "strict-origin-when-cross-origin",
          },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=()",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
