"""Storage interface. The vault logic never touches disk or a database directly."""

import re
from abc import ABC, abstractmethod

from securevault.utils.exceptions import FileNotFound

_FILE_ID = re.compile(r"^[0-9a-f]{32}$")


def validate_file_id(file_id: str) -> str:
    """File ids are uuid4 hex. Rejecting everything else blocks path traversal ('../x')."""
    if not isinstance(file_id, str) or not _FILE_ID.match(file_id):
        raise FileNotFound("invalid file id")
    return file_id


class StorageBackend(ABC):
    """Everything stored here is already encrypted or is public metadata."""

    name = "abstract"

    # keystore -------------------------------------------------------------
    @abstractmethod
    def load_keystore(self) -> dict | None: ...

    @abstractmethod
    def save_keystore(self, keystore: dict) -> None:
        """Atomically replace the keystore."""

    # files ----------------------------------------------------------------
    @abstractmethod
    def put_file(self, file_id: str, blob: bytes, meta: dict) -> None: ...

    @abstractmethod
    def get_file(self, file_id: str) -> tuple[bytes, dict]:
        """Return (blob, meta) or raise FileNotFound."""

    @abstractmethod
    def get_meta(self, file_id: str) -> dict: ...

    @abstractmethod
    def update_meta(self, file_id: str, meta: dict) -> None: ...

    @abstractmethod
    def delete_file(self, file_id: str) -> None: ...

    @abstractmethod
    def list_meta(self) -> list[dict]: ...

    # audit log ------------------------------------------------------------
    @abstractmethod
    def read_audit(self) -> list[dict]: ...

    @abstractmethod
    def append_audit(self, entry: dict) -> None:
        """Append one entry. Raise StorageConflict unless entry['index'] is exactly last+1."""

    def read_audit_tail(self, n: int) -> list[dict]:
        """Return the last `n` audit entries in ascending order.

        Default is correct for every backend; backends override it so appending to a long
        log does not need to read the whole log (scalability fix for Vault._log).
        """
        if n <= 0:
            return []
        return self.read_audit()[-n:]
