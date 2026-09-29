# TunnelTrace AI — Cloud Demonstration Deployment Guide
## Vercel (Frontend) and Render (Backend Docker) Setup

---

## 1. Overview and Architecture

This guide details the procedure for deploying a public, high-availability demonstration instance of **TunnelTrace AI** using:
- **Frontend Console:** Hosted on **Vercel** (Serverless Next.js edge runtime, zero cold starts).
- **Backend API & Forensics:** Hosted on **Render** (Containerized Docker runtime with TShark, PyTorch CPU, XGBoost, and pre-seeded forensic state).

```
   [ Evaluators / Judges ]
              |
              v (HTTPS)
   +----------------------+
   |  Vercel Edge Network |  Next.js 16 Web Console
   |  (tunneltrace.app)   |  - Instant load, 0ms cold start
   +----------------------+  - Fully responsive SOC interface
              |
              | REST / WebSockets (CORS Regex: https://.*\.vercel\.app)
              v
   +----------------------+
   |  Render Web Service  |  FastAPI Docker Container
   |  (Docker Runtime)    |  - TShark 4.x protocol dissector
   +----------------------+  - Pre-seeded SQLite database (soc_dev.sqlite)
              ^              - Calibrated ML models (XGBoost + 1D-CNN)
              |              - Grounded AI Cryptographic fast-path
      [ Uptime Monitor ]
      Pings /health/live every 5-10m
      (Keeps single free service warm 24/7)
```

---

## 2. Part 1: Deploy Backend on Render (Docker)

### Step 1: Create a New Web Service
1. Log in to [Render Dashboard](https://dashboard.render.com).
2. Click **New +** > **Web Service**.
3. Connect your GitHub repository: `https://github.com/sharancode3/TunnelTrace-AI.git`.
4. Choose **main** branch.

### Step 2: Configure Service Settings
- **Name:** `tunneltrace-backend` (or your preferred name)
- **Region:** Frankfurt (EU) or Oregon (US)
- **Language / Runtime:** **Docker**
- **Dockerfile Path:** `./Dockerfile` (in the repository root)
- **Instance Type:** Free (512 MB) or Starter ($7/mo for 1 GB RAM if available)

### Step 3: Add Environment Variables
Under the **Environment Variables** section, configure:

| Key | Value | Description |
| :--- | :--- | :--- |
| `APP_ENV` | `production` | Enables production security guards |
| `APP_DEBUG` | `false` | Disables debug overhead |
| `DATABASE_URL` | `sqlite+aiosqlite:////app/backend/soc_dev.sqlite` | Points to pre-seeded forensic database |
| `STORAGE_ROOT` | `/app/storage` | Local storage directory for captures |
| `CORS_ORIGIN_REGEX` | `https://.*\.vercel\.app` | Permits all Vercel deployments and previews |

*(Note: Render automatically injects `PORT=10000`. The Dockerfile binds dynamically to `${PORT:-8000}`, so no manual port configuration is required).*

### Step 4: Deploy and Verify
1. Click **Deploy Web Service**.
2. Wait for the Docker build to complete (approx. 3-5 minutes on first build).
3. Once live, test the liveness and readiness probes in your browser or terminal:
   ```bash
   # Liveness check
   curl -s https://<your-render-subdomain>.onrender.com/api/v1/system/health/live
   
   # Readiness check
   curl -s https://<your-render-subdomain>.onrender.com/api/v1/system/health/ready
   ```
   Both endpoints will return `HTTP 200` with `status: READY`.

### Step 5: Configure Uptime Monitor (Keep Alive)
To prevent the free tier service from sleeping after 15 minutes of inactivity:
1. Create a free account on [UptimeRobot](https://uptimerobot.com) or [Cron-job.org](https://cron-job.org).
2. Add a new **HTTP(s) Monitor**:
   - **URL:** `https://<your-render-subdomain>.onrender.com/api/v1/system/health/live`
   - **Monitoring Interval:** Every **7 minutes** (or 10 minutes).
   - **HTTP Method:** `GET`
3. *Budget Note:* A single service monitored 24/7 uses ~720 hours/month, fitting safely inside Render's 750 free monthly hour allowance.

---

## 3. Part 2: Deploy Frontend on Vercel

### Step 1: Import Project into Vercel
1. Log in to [Vercel Dashboard](https://vercel.com).
2. Click **Add New...** > **Project**.
3. Import your GitHub repository: `TunnelTrace-AI`.

### Step 2: Configure Build Settings
- **Framework Preset:** `Next.js` (automatically detected)
- **Root Directory:** Click **Edit** and select `frontend`
- **Build Command:** `next build` (default)
- **Output Directory:** `.next` (default)
- **Install Command:** `npm install` (default)

### Step 3: Add Environment Variables
Under the **Environment Variables** accordion, add:

| Key | Value | Description |
| :--- | :--- | :--- |
| `NEXT_PUBLIC_API_URL` | `https://<your-render-subdomain>.onrender.com/api/v1` | URL to your deployed Render backend |
| `NEXT_PUBLIC_WS_URL` | `wss://<your-render-subdomain>.onrender.com/api/v1/monitoring/ws` | (Optional) WebSocket endpoint for live monitoring |

### Step 4: Deploy
1. Click **Deploy**.
2. Vercel will build the 14 routes using Turbopack in ~40 seconds.
3. You will receive your public URL: `https://<project-name>.vercel.app`.

---

## 4. Evaluator Experience & Demonstration Features

When evaluators visit your public URL, they experience a complete, responsive security platform with zero setup required:

### 1. Pre-Loaded Golden Forensics Sessions
- The platform includes the verified `real_tunnel_gcm.pcapng` session in the database.
- Evaluators can immediately inspect:
  - **Overview:** Posture score (100/100, 85.7% evaluated coverage) and protocol distribution.
  - **SA Graph:** Interactive React Flow canvas showing IKEv2 and bidirectional Child SAs (`0xc0ffee01` / `0xc0ffee02`).
  - **Protocol Forensics:** Proposal transforms, DH group 19, and exact packet frame numbers.
  - **Traffic ML:** 24 tabular features, directionality tensors, and OOD status.
  - **AI Analyst:** Grounded cryptographic analysis with citations.

### 2. One-Click Sample Ingestion
On the `/analyses/new` page, under the **Sample Captures** tab:
- Evaluators can click **"Analyze Sample"** on:
  - `real_tunnel_gcm.pcapng` (IKEv2 AES-256-GCM / ECP-256 / PFS)
  - `real_esp_only.pcap` (Mid-stream ESP packets illustrating partial visibility)
- The system instantaneously loads the pre-verified analysis results without server delays.

### 3. Live Monitoring Demonstration
On the `/monitoring` tab:
- Evaluators see the pre-registered **`Perimeter-Gateway-ALPHA`** and active collector sensor **`gw-collector-eth0`**.
- They can view active Child SAs, gateway health status, and live telemetry tabs.
- During video presentations, run `scripts/gateway_collector.py` locally or on a VPS to stream real live heartbeats.
