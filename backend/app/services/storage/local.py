"""Local filesystem storage provider with path traversal protection and atomic writes."""

import logging
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from app.core.errors import NotFoundError, PathTraversalError, StorageError
from app.services.storage.base import StorageProvider

logger = logging.getLogger(__name__)


class LocalStorageProvider(StorageProvider):
    """Local filesystem storage provider enforcing root containment and atomic writes."""

    def __init__(
        self,
        root_path: Path | str | None = None,
        root_dir: Path | str | None = None,
    ) -> None:
        repo_storage = Path(__file__).resolve().parent.parent.parent.parent / "storage"
        chosen = root_path if root_path is not None else (root_dir if root_dir is not None else "./storage")
        candidate_root = Path(chosen).resolve()
        if not (candidate_root / "captures").exists() and (repo_storage / "captures").exists():
            self._root_path = repo_storage
        else:
            self._root_path = candidate_root
        self._initialize_directories()

    @property
    def root_path(self) -> Path:
        """Root filesystem path for storage."""
        return self._root_path

    def _initialize_directories(self) -> None:
        """Create standard storage hierarchy if it does not already exist."""
        try:
            self._root_path.mkdir(parents=True, exist_ok=True)
            for sub_dir in ("captures", "live", "reports", "tmp"):
                (self._root_path / sub_dir).mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.error(f"Failed to initialize storage root directory '{self._root_path}': {exc}")
            raise StorageError(f"Storage initialization failed: {exc}") from exc

    def resolve_safe_path(self, relative_path: str) -> Path:
        """Resolve path and verify it remains strictly enclosed within self.root_path.

        Raises:
            PathTraversalError: If path contains traversal characters or escapes root.
        """
        if not relative_path or not relative_path.strip():
            raise PathTraversalError("Invalid storage path: Path cannot be empty.")

        # Reject obvious null bytes or absolute path indicators
        if "\0" in relative_path:
            raise PathTraversalError("Invalid storage path: Null byte detected.")

        clean_relative = relative_path.lstrip("/\\")
        candidate = (self._root_path / clean_relative).resolve()

        # Strict containment check
        try:
            candidate.relative_to(self._root_path)
        except ValueError:
            logger.warning(f"Path traversal attempt blocked: '{relative_path}' -> '{candidate}'")
            raise PathTraversalError(f"Access denied: Path '{relative_path}' escapes storage root.")

        return candidate

    def save_file(self, relative_path: str, data: bytes) -> str:
        """Atomically persist binary data to the target relative path."""
        target_path = self.resolve_safe_path(relative_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write: write to temporary sibling file and rename
        temp_dir = self._root_path / "tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)

        try:
            with tempfile.NamedTemporaryFile(dir=temp_dir, delete=False) as tmp_file:
                tmp_file.write(data)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
                temp_name = tmp_file.name

            os.replace(temp_name, target_path)
            logger.debug(f"Saved {len(data)} bytes to safe path: {relative_path}")
            return str(target_path)
        except Exception as exc:
            logger.error(f"Failed to save file '{relative_path}': {exc}")
            raise StorageError(f"File write failed: {exc}") from exc

    def write_file(self, relative_path: str, data: bytes) -> Path:
        """Convenience alias for save_file returning a Path object."""
        path_str = self.save_file(relative_path, data)
        return Path(path_str)

    def read_file(self, relative_path: str) -> bytes:
        """Read and return binary bytes from the target relative path."""
        target_path = self.resolve_safe_path(relative_path)
        if not target_path.exists() or not target_path.is_file():
            raise NotFoundError(f"File not found: '{relative_path}'")

        try:
            with open(target_path, "rb") as f:
                return f.read()
        except NotFoundError:
            raise
        except Exception as exc:
            logger.error(f"Failed to read file '{relative_path}': {exc}")
            raise StorageError(f"File read failed: {exc}") from exc

    def delete_file(self, relative_path: str) -> bool:
        """Delete file at the target relative path if it exists."""
        target_path = self.resolve_safe_path(relative_path)
        if not target_path.exists():
            return False

        try:
            target_path.unlink()
            logger.debug(f"Deleted file: {relative_path}")
            return True
        except Exception as exc:
            logger.error(f"Failed to delete file '{relative_path}': {exc}")
            raise StorageError(f"File deletion failed: {exc}") from exc

    def exists(self, relative_path: str) -> bool:
        """Check if file exists at the safe relative path."""
        try:
            target_path = self.resolve_safe_path(relative_path)
            return target_path.exists() and target_path.is_file()
        except PathTraversalError:
            return False

    def check_health(self) -> dict[str, Any]:
        """Perform a real writability, read, and delete probe to verify storage health."""
        start_time = time.perf_counter()
        probe_id = f"tmp/health_probe_{uuid.uuid4().hex}.tmp"
        probe_data = b"TUNNELTRACE_HEALTH_PROBE"

        try:
            self.save_file(probe_id, probe_data)
            read_back = self.read_file(probe_id)
            self.delete_file(probe_id)

            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            if read_back == probe_data:
                return {
                    "status": "UP",
                    "root": str(self._root_path),
                    "latency_ms": latency_ms,
                    "error": None,
                }
            return {
                "status": "DOWN",
                "root": str(self._root_path),
                "latency_ms": latency_ms,
                "error": "Storage probe read-back verification failed.",
            }
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.warning(f"Storage health probe failed: {exc}")
            return {
                "status": "DOWN",
                "root": str(self._root_path),
                "latency_ms": latency_ms,
                "error": str(exc),
            }

    def check_writability(self) -> bool:
        """Convenience method returning True if storage probe passes."""
        return self.check_health().get("status") == "UP"
