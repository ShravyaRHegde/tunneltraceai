"""Storage service interfaces and provider implementations."""

from pathlib import Path
from app.core.config import get_settings
from app.services.storage.base import StorageProvider
from app.services.storage.local import LocalStorageProvider

_storage_provider: StorageProvider | None = None


def get_storage_provider() -> StorageProvider:
    """Retrieve or initialize the singleton configured storage provider."""
    global _storage_provider
    if _storage_provider is None:
        settings = get_settings()
        _storage_provider = LocalStorageProvider(settings.STORAGE_ROOT)
    return _storage_provider
