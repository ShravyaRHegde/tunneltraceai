import os
import sys

def main():
    port = int(os.environ.get("PORT", "8000"))
    print(f"[*] Starting TunnelTrace AI backend on port {port}...")

    root_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(root_dir, "backend")

    if root_dir not in sys.path:
        sys.path.insert(0, root_dir)
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        app_dir=backend_dir,
        log_level="info",
    )

if __name__ == "__main__":
    main()
