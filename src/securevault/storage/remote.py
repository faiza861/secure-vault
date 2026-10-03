"""PostgreSQL backend (works with Neon's free tier). Used by the hosted/Vercel deployment.

Everything stored is ciphertext or public metadata, so the database never holds plaintext.
A new connection is opened per call, which suits serverless functions.
"""

import json

from securevault.storage.base import StorageBackend, validate_file_id
from securevault.utils.exceptions import FileNotFound, StorageConflict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sv_keystore (id INT PRIMARY KEY CHECK (id = 1), data JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS sv_files (
    file_id TEXT PRIMARY KEY, blob BYTEA NOT NULL, meta JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS sv_audit (idx BIGINT PRIMARY KEY, entry JSONB NOT NULL);
"""


class PostgresBackend(StorageBackend):
    name = "postgres"

    def __init__(self, database_url: str) -> None:
        if not database_url:
            raise ValueError("DATABASE_URL is required for the postgres backend")
        self._url = database_url
        self._schema_ready = False

    def _connect(self):
        import psycopg  # imported lazily so local/CLI use does not need it

        conn = psycopg.connect(self._url, autocommit=False)
        if not self._schema_ready:
            conn.execute(_SCHEMA)
            conn.commit()
            self._schema_ready = True
        return conn

    # keystore
    def load_keystore(self):
        with self._connect() as conn:
            row = conn.execute("SELECT data FROM sv_keystore WHERE id = 1").fetchone()
        return row[0] if row else None

    def save_keystore(self, keystore):
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sv_keystore (id, data) VALUES (1, %s::jsonb) "
                "ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data",
                (json.dumps(keystore),),
            )

    # files
    def put_file(self, file_id, blob, meta):
        validate_file_id(file_id)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO sv_files (file_id, blob, meta) VALUES (%s, %s, %s::jsonb) "
                "ON CONFLICT (file_id) DO UPDATE SET blob = EXCLUDED.blob, meta = EXCLUDED.meta",
                (file_id, blob, json.dumps(meta)),
            )

    def get_file(self, file_id):
        validate_file_id(file_id)
        with self._connect() as conn:
            row = conn.execute("SELECT blob, meta FROM sv_files WHERE file_id = %s", (file_id,)).fetchone()
        if row is None:
            raise FileNotFound(file_id)
        return bytes(row[0]), row[1]

    def get_meta(self, file_id):
        validate_file_id(file_id)
        with self._connect() as conn:
            row = conn.execute("SELECT meta FROM sv_files WHERE file_id = %s", (file_id,)).fetchone()
        if row is None:
            raise FileNotFound(file_id)
        return row[0]

    def update_meta(self, file_id, meta):
        validate_file_id(file_id)
        with self._connect() as conn:
            cur = conn.execute("UPDATE sv_files SET meta = %s::jsonb WHERE file_id = %s", (json.dumps(meta), file_id))
            if cur.rowcount == 0:
                raise FileNotFound(file_id)

    def delete_file(self, file_id):
        validate_file_id(file_id)
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM sv_files WHERE file_id = %s", (file_id,))
            if cur.rowcount == 0:
                raise FileNotFound(file_id)

    def list_meta(self):
        with self._connect() as conn:
            rows = conn.execute("SELECT meta FROM sv_files").fetchall()
        return sorted((r[0] for r in rows), key=lambda m: m["created_ts"])

    # audit
    def read_audit(self):
        with self._connect() as conn:
            rows = conn.execute("SELECT entry FROM sv_audit ORDER BY idx").fetchall()
        return [r[0] for r in rows]

    def read_audit_tail(self, n):
        if n <= 0:
            return []
        # idx is the primary key, so this is an index scan of n rows, not a full read.
        with self._connect() as conn:
            rows = conn.execute("SELECT entry FROM sv_audit ORDER BY idx DESC LIMIT %s", (int(n),)).fetchall()
        return [r[0] for r in reversed(rows)]

    def append_audit(self, entry):
        import psycopg

        # Insert only if this entry's index is exactly last+1. If two writers race for the same
        # slot, the primary key on idx rejects the loser (UniqueViolation).
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "INSERT INTO sv_audit (idx, entry) "
                    "SELECT %s, %s::jsonb WHERE %s = (SELECT COALESCE(MAX(idx) + 1, 0) FROM sv_audit)",
                    (entry["index"], json.dumps(entry), entry["index"]),
                )
                if cur.rowcount == 0:
                    raise StorageConflict("audit chain moved on")
        except psycopg.errors.UniqueViolation:
            raise StorageConflict("audit chain moved on") from None
