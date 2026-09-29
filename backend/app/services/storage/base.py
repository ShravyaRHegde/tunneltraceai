"""Abstract interface for local and object storage providers."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class StorageProvider(ABC):
    """Abstract base class for all file and artifact storage providers."""

    @property
    @abstractmethod
    def root_path(self) -> Path:
        """Root filesystem path for storage."""
        pass

    @abstractmethod
    def resolve_safe_path(self, relative_path: str) -> Path:
        """Resolve and validate a relative path, rejecting directory traversal attempts."""
        pass

    @abstractmethod
    def save_file(self, relative_path: str, data: bytes) -> str:
        """Persist binary data to the target relative path."""
        pass

    @abstractmethod
    def read_file(self, relative_path: str) -> bytes:
        """Read binary data from the target relative path."""
        pass

    @abstractmethod
    def delete_file(self, relative_path: str) -> bool:
        """Delete file at the target relative path if it exists."""
        pass

    @abstractmethod
    def exists(self, relative_path: str) -> bool:
        """Check if file exists at the target relative path."""
        pass

    @abstractmethod
    def check_health(self) -> dict[str, Any]:
        """Perform a live writability and read-back test to verify storage health."""
        pass
