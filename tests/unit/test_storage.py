import pytest

from securevault.audit import chain
from securevault.storage.local import LocalBackend
from securevault.storage.memory import MemoryBackend
from securevault.utils.exceptions import FileNotFound, StorageConflict

FID = "a" * 32
META = {"file_id": FID, "created_ts": 1.0, "size": 3, "key_version": 1}


@pytest.fixture(scope="session")
def pg_url(tmp_path_factory):
    """A throw-away real PostgreSQL (pip install pgserver). Skipped if unavailable."""
    pgserver = pytest.importorskip("pgserver")
    pytest.importorskip("psycopg")
    server = pgserver.get_server(tmp_path_factory.mktemp("pg"), cleanup_mode="stop")
    return server.get_uri()


@pytest.fixture(params=["memory", "local", "postgres"])
def store(request, tmp_path):
    if request.param == "memory":
        return MemoryBackend()
    if request.param == "local":
        return LocalBackend(tmp_path / "vault")
    from securevault.storage.remote import PostgresBackend

    backend = PostgresBackend(request.getfixturevalue("pg_url"))
    with backend._connect() as conn:
        conn.execute("TRUNCATE sv_keystore, sv_files, sv_audit")
    return backend


def test_keystore_roundtrip(store):
    assert store.load_keystore() is None
    store.save_keystore({"a": 1})
    assert store.load_keystore() == {"a": 1}


def test_file_roundtrip_update_delete(store):
    store.put_file(FID, b"cipher", META)
    blob, meta = store.get_file(FID)
    assert blob == b"cipher" and meta == META
    store.update_meta(FID, {**META, "key_version": 2})
    assert store.get_meta(FID)["key_version"] == 2
    assert [m["file_id"] for m in store.list_meta()] == [FID]
    store.delete_file(FID)
    with pytest.raises(FileNotFound):
        store.get_file(FID)
    assert store.list_meta() == []


def test_missing_file(store):
    with pytest.raises(FileNotFound):
        store.get_file("b" * 32)
    with pytest.raises(FileNotFound):
        store.delete_file("b" * 32)


@pytest.mark.parametrize("bad", ["../etc/passwd", "..\\x", "", "short", "G" * 32, "a" * 31, "a" * 33])
def test_path_traversal_ids_rejected(store, bad):
    with pytest.raises(FileNotFound):
        store.get_file(bad)
    with pytest.raises(FileNotFound):
        store.put_file(bad, b"x", META)


def test_audit_append_enforces_sequence(store):
    e0 = chain.make_entry(None, "a", "t", {}, 1.0)
    e1 = chain.make_entry(e0, "b", "t", {}, 2.0)
    store.append_audit(e0)
    with pytest.raises(StorageConflict):
        store.append_audit(e0)  # same index twice = forked chain
    with pytest.raises(StorageConflict):
        store.append_audit(chain.make_entry(e1, "c", "t", {}, 3.0))  # skipped an index
    store.append_audit(e1)
    assert store.read_audit() == [e0, e1]


def test_local_files_survive_new_instance(tmp_path):
    a = LocalBackend(tmp_path / "v")
    a.put_file(FID, b"cipher", META)
    assert LocalBackend(tmp_path / "v").get_file(FID)[0] == b"cipher"


# ---- read_audit_tail (Phase 1): same contract on memory, local and postgres ---------------


def _fill(store, count):
    prev = None
    for i in range(count):
        prev = chain.make_entry(prev, f"e{i}", "t", {"i": i}, 1000.0 + i)
        store.append_audit(prev)


def test_audit_tail_returns_last_n_in_ascending_order(store):
    assert store.read_audit_tail(3) == []
    _fill(store, 10)
    tail = store.read_audit_tail(3)
    assert [e["index"] for e in tail] == [7, 8, 9]
    assert tail == store.read_audit()[-3:]


def test_audit_tail_edge_sizes(store):
    _fill(store, 4)
    assert store.read_audit_tail(0) == []
    assert [e["index"] for e in store.read_audit_tail(1)] == [3]
    assert [e["index"] for e in store.read_audit_tail(50)] == [0, 1, 2, 3]  # n larger than the log


def test_audit_tail_spans_many_blocks_and_keeps_chain_valid(store):
    # Long entries force the local backend to read several blocks backwards.
    prev = None
    for i in range(60):
        prev = chain.make_entry(prev, "bulk", "t", {"pad": "x" * 600}, 1000.0 + i)
        store.append_audit(prev)
    tail = store.read_audit_tail(25)
    assert [e["index"] for e in tail] == list(range(35, 60))
    assert chain.verify(store.read_audit()).ok


def test_append_still_rejects_a_stale_slot(store):
    _fill(store, 3)
    stale = chain.make_entry(None, "fork", "t", {}, 5.0)  # index 0 again: would fork the chain
    with pytest.raises(StorageConflict):
        store.append_audit(stale)
    gap = {**stale, "index": 9}
    with pytest.raises(StorageConflict):
        store.append_audit(gap)
