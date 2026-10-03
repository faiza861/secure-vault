"""In-memory backend. Used by tests and for throw-away demos (data vanishes on exit)."""

import copy

from securevault.storage.base import StorageBackend, validate_file_id
from securevault.utils.exceptions import FileNotFound, StorageConflict


class MemoryBackend(StorageBackend):
    name = "memory"

    def __init__(self) -> None:
        self._keystore: dict | None = None
        self._files: dict[str, tuple[bytes, dict]] = {}
        self._audit: list[dict] = []

    def load_keystore(self):
        return copy.deepcopy(self._keystore)

    def save_keystore(self, keystore):
        self._keystore = copy.deepcopy(keystore)

    def put_file(self, file_id, blob, meta):
        self._files[validate_file_id(file_id)] = (bytes(blob), copy.deepcopy(meta))

    def get_file(self, file_id):
        try:
            blob, meta = self._files[validate_file_id(file_id)]
        except KeyError:
            raise FileNotFound(file_id) from None
        return blob, copy.deepcopy(meta)

    def get_meta(self, file_id):
        return self.get_file(file_id)[1]

    def update_meta(self, file_id, meta):
        blob, _ = self.get_file(file_id)
        self._files[file_id] = (blob, copy.deepcopy(meta))

    def delete_file(self, file_id):
        try:
            del self._files[validate_file_id(file_id)]
        except KeyError:
            raise FileNotFound(file_id) from None

    def list_meta(self):
        return sorted((copy.deepcopy(m) for _, m in self._files.values()), key=lambda m: m["created_ts"])

    def read_audit(self):
        return copy.deepcopy(self._audit)

    def read_audit_tail(self, n):
        return copy.deepcopy(self._audit[-n:]) if n > 0 else []

    def append_audit(self, entry):
        if entry["index"] != len(self._audit):
            raise StorageConflict("audit chain moved on")
        self._audit.append(copy.deepcopy(entry))
