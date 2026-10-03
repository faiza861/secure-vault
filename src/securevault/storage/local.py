"""Local-disk backend (used by the CLI).

Layout under data_dir:
    keystore.json          wrapped keys + KDF parameters (no secrets in the clear)
    audit.jsonl            one JSON audit entry per line
    files/<id>.bin         ciphertext
    files/<id>.json        metadata (sizes, hashes, wrapped DEK, encrypted name)
"""

import json
import os
import tempfile
from pathlib import Path

from securevault.storage.base import StorageBackend, validate_file_id
from securevault.utils.exceptions import FileNotFound, IntegrityError, StorageConflict


def _atomic_write(path: Path, data: bytes) -> None:
    """Write to a temp file in the same folder, then rename. A crash never leaves half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


class LocalBackend(StorageBackend):
    name = "local"

    def __init__(self, data_dir: Path) -> None:
        self.root = Path(data_dir)
        self.files_dir = self.root / "files"
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self._keystore_path = self.root / "keystore.json"
        self._audit_path = self.root / "audit.jsonl"

    # keystore
    def load_keystore(self):
        if not self._keystore_path.exists():
            return None
        return json.loads(self._keystore_path.read_text(encoding="utf-8"))

    def save_keystore(self, keystore):
        _atomic_write(self._keystore_path, json.dumps(keystore, indent=2).encode("utf-8"))

    # files
    def _paths(self, file_id: str) -> tuple[Path, Path]:
        file_id = validate_file_id(file_id)
        return self.files_dir / f"{file_id}.bin", self.files_dir / f"{file_id}.json"

    def put_file(self, file_id, blob, meta):
        blob_path, meta_path = self._paths(file_id)
        _atomic_write(blob_path, blob)
        _atomic_write(meta_path, json.dumps(meta).encode("utf-8"))

    def get_meta(self, file_id):
        _, meta_path = self._paths(file_id)
        if not meta_path.exists():
            raise FileNotFound(file_id)
        return json.loads(meta_path.read_text(encoding="utf-8"))

    def get_file(self, file_id):
        blob_path, _ = self._paths(file_id)
        meta = self.get_meta(file_id)
        if not blob_path.exists():
            raise IntegrityError("ciphertext is missing from storage")
        return blob_path.read_bytes(), meta

    def update_meta(self, file_id, meta):
        _, meta_path = self._paths(file_id)
        if not meta_path.exists():
            raise FileNotFound(file_id)
        _atomic_write(meta_path, json.dumps(meta).encode("utf-8"))

    def delete_file(self, file_id):
        blob_path, meta_path = self._paths(file_id)
        if not meta_path.exists():
            raise FileNotFound(file_id)
        meta_path.unlink()
        blob_path.unlink(missing_ok=True)

    def list_meta(self):
        metas = [json.loads(p.read_text(encoding="utf-8")) for p in self.files_dir.glob("*.json")]
        return sorted(metas, key=lambda m: m["created_ts"])

    # audit
    def read_audit(self):
        if not self._audit_path.exists():
            return []
        with self._audit_path.open(encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def read_audit_tail(self, n):
        """Last `n` entries. Reads backwards from the end of the file in blocks, so cost
        depends on `n`, not on how long the log has grown."""
        if n <= 0 or not self._audit_path.exists():
            return []
        block, data, lines = 8192, b"", []
        with self._audit_path.open("rb") as handle:
            pos = handle.seek(0, os.SEEK_END)
            while pos > 0 and data.count(b"\n") <= n:
                step = min(block, pos)
                pos -= step
                handle.seek(pos)
                data = handle.read(step) + data
            lines = [ln for ln in data.split(b"\n") if ln.strip()]
            if pos > 0:  # first line in the buffer may be cut off mid-way; drop it
                lines = lines[1:]
        return [json.loads(ln) for ln in lines[-n:]]

    def _last_index(self) -> int:
        tail = self.read_audit_tail(1)
        return tail[0]["index"] if tail else -1

    def append_audit(self, entry):
        # Same slot rule as before (index must be exactly last+1) without parsing the whole log.
        if entry["index"] != self._last_index() + 1:
            raise StorageConflict("audit chain moved on")
        with self._audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
