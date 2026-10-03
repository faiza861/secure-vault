"""Storage backends and the Vault orchestrator."""

from securevault.config import Settings, get_settings
from securevault.storage.base import StorageBackend

_memory_singleton = None


def make_backend(settings: Settings | None = None) -> StorageBackend:
    """Build the backend named by STORAGE_BACKEND."""
    global _memory_singleton
    settings = settings or get_settings()
    if settings.storage_backend == "local":
        from securevault.storage.local import LocalBackend

        return LocalBackend(settings.data_dir)
    if settings.storage_backend == "postgres":
        from securevault.storage.remote import PostgresBackend

        return PostgresBackend(settings.database_url)
    from securevault.storage.memory import MemoryBackend

    if _memory_singleton is None:  # one shared store per process, so requests see each other
        _memory_singleton = MemoryBackend()
    return _memory_singleton
