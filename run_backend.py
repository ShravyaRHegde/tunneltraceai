import os
import sys
import uvicorn

if __name__ == "__main__":
    root_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(root_dir, "backend")
    db_path = os.path.join(backend_dir, "soc_dev.sqlite").replace("\\", "/")
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    os.environ["APP_ENV"] = "development"
    os.environ["APP_DEBUG"] = "true"

    if root_dir not in sys.path:
        sys.path.insert(0, root_dir)
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8002,
        reload=True,
        app_dir=backend_dir,
        log_level="info",
    )
