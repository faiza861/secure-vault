import pytest
from tests.conftest import PASSPHRASE

from securevault.core.kdf import FAST_TEST_PARAMS
from securevault.monitor.detector import Detector
from securevault.storage.vault import Vault
from securevault.utils.exceptions import (
    FileNotFound,
    IntegrityError,
    InvalidPassphrase,
    UploadTooLarge,
    VaultAlreadyInitialized,
    VaultLocked,
    VaultNotInitialized,
    WeakPassphrase,
)


def test_full_roundtrip(vault):
    info = vault.upload("report.pdf", b"top secret contents")
    assert vault.download(info.file_id) == ("report.pdf", b"top secret contents")


def test_storage_holds_only_ciphertext(vault, backend):
    info = vault.upload("diary.txt", b"dear diary, my secret is 42")
    blob, meta = backend.get_file(info.file_id)
    assert b"dear diary" not in blob
    assert "diary" not in repr(meta)  # file name is encrypted too


def test_upload_works_while_locked_download_does_not(vault, backend, clock):
    locked = Vault(backend, clock=clock)
    info = locked.upload("a.txt", b"written while locked")
    with pytest.raises(VaultLocked):
        locked.download(info.file_id)
    locked.unlock(PASSPHRASE)
    assert locked.download(info.file_id)[1] == b"written while locked"


def test_wrong_passphrase_rejected_and_logged(vault, backend, clock):
    other = Vault(backend, clock=clock)
    with pytest.raises(InvalidPassphrase):
        other.unlock("not the passphrase!!")
    assert other.audit_entries()[-1]["event"] == "unlock_failed"


def test_cannot_init_twice_or_weak(backend):
    with pytest.raises(WeakPassphrase):
        Vault.initialize(backend, "short", kdf_params=FAST_TEST_PARAMS)
    Vault.initialize(backend, PASSPHRASE, kdf_params=FAST_TEST_PARAMS)
    with pytest.raises(VaultAlreadyInitialized):
        Vault.initialize(backend, PASSPHRASE, kdf_params=FAST_TEST_PARAMS)


def test_operations_need_a_vault(backend):
    with pytest.raises(VaultNotInitialized):
        Vault(backend).upload("a", b"b")


def test_names_hidden_until_unlocked(vault, backend, clock):
    vault.upload("secret-plans.docx", b"x")
    assert vault.list_files()[0].name == "secret-plans.docx"
    fresh = Vault(backend, clock=clock)
    assert fresh.list_files()[0].name is None


def test_delete(vault):
    info = vault.upload("a", b"b")
    vault.delete(info.file_id)
    with pytest.raises(FileNotFound):
        vault.download(info.file_id)


def test_upload_limit(backend, clock):
    v = Vault.initialize(backend, PASSPHRASE, kdf_params=FAST_TEST_PARAMS, max_upload_bytes=10, clock=clock)
    with pytest.raises(UploadTooLarge):
        v.upload("big", b"x" * 11)


def test_tampered_ciphertext_detected_and_logged(vault, backend):
    info = vault.upload("a", b"data")
    blob, meta = backend.get_file(info.file_id)
    backend.put_file(info.file_id, blob[:-1] + bytes([blob[-1] ^ 1]), meta)
    with pytest.raises(IntegrityError):
        vault.download(info.file_id)
    assert vault.audit_entries()[-1]["event"] == "integrity_failure"


def test_swapped_files_detected(vault, backend):
    a, b = vault.upload("a", b"AAAA"), vault.upload("b", b"BBBB")
    blob_b, meta_b = backend.get_file(b.file_id)
    _, meta_a = backend.get_file(a.file_id)
    # attacker swaps stored ciphertext AND its hash between the two ids
    backend.put_file(a.file_id, blob_b, {**meta_a, "ciphertext_sha256": meta_b["ciphertext_sha256"]})
    with pytest.raises(IntegrityError):
        vault.download(a.file_id)


def test_passphrase_rotation_keeps_files_readable(vault, backend, clock):
    info = vault.upload("a", b"data")
    before = backend.get_file(info.file_id)
    vault.rotate_passphrase("my brand new passphrase")
    assert backend.get_file(info.file_id) == before  # file untouched
    new = Vault(backend, clock=clock)
    with pytest.raises(InvalidPassphrase):
        new.unlock(PASSPHRASE)
    new.unlock("my brand new passphrase")
    assert new.download(info.file_id)[1] == b"data"


def test_key_rotation_rewraps_without_touching_ciphertext(vault, backend, clock):
    ids = [vault.upload(f"f{i}", f"data{i}".encode()).file_id for i in range(3)]
    blobs = {i: backend.get_file(i)[0] for i in ids}
    old_wrapped = {i: backend.get_meta(i)["wrapped_dek"] for i in ids}
    assert vault.rotate_keys() == 3
    for i in ids:
        assert backend.get_file(i)[0] == blobs[i]  # ciphertext identical
        assert backend.get_meta(i)["wrapped_dek"] != old_wrapped[i]
        assert backend.get_meta(i)["key_version"] == 2
    fresh = Vault(backend, clock=clock)
    fresh.unlock(PASSPHRASE)
    assert [fresh.download(i)[1] for i in ids] == [b"data0", b"data1", b"data2"]
    assert len(backend.load_keystore()["keys"]) == 1  # old key discarded


def test_new_uploads_use_the_new_key_after_rotation(vault):
    vault.rotate_keys()
    info = vault.upload("n", b"after rotation")
    assert info.key_version == 2 and vault.download(info.file_id)[1] == b"after rotation"


def test_interrupted_key_rotation_can_be_resumed(vault, backend, monkeypatch):
    ids = [vault.upload(f"f{i}", b"x").file_id for i in range(3)]
    real_update, calls = backend.update_meta, []

    def flaky(file_id, meta):
        calls.append(file_id)
        if len(calls) == 2:
            raise RuntimeError("simulated crash")
        real_update(file_id, meta)

    monkeypatch.setattr(backend, "update_meta", flaky)
    with pytest.raises(RuntimeError):
        vault.rotate_keys()
    monkeypatch.undo()
    assert {backend.get_meta(i)["key_version"] for i in ids} == {1, 2}  # mixed state
    assert all(vault.download(i)[1] == b"x" for i in ids)  # still fully readable
    vault.rotate_keys()  # resume
    assert {backend.get_meta(i)["key_version"] for i in ids} == {2}
    assert len(backend.load_keystore()["keys"]) == 1


def test_audit_chain_records_everything_and_verifies(vault):
    info = vault.upload("a", b"b")
    vault.download(info.file_id)
    vault.delete(info.file_id)
    events = [e["event"] for e in vault.audit_entries()]
    assert events == ["vault_created", "upload", "download", "delete"]
    assert vault.verify_audit().ok


def test_audit_never_stores_secrets_or_names(vault):
    vault.upload("very-secret-name.txt", b"very secret body")
    text = repr(vault.audit_entries())
    assert "very-secret-name" not in text and "very secret body" not in text and PASSPHRASE not in text


def test_audit_tampering_detected_and_anchor_catches_truncation(vault, backend):
    info = vault.upload("a", b"b")
    vault.download(info.file_id)
    anchor = vault.verify_audit().head_hash
    backend._audit[1]["details"]["bytes"] = 0
    assert not vault.verify_audit().ok
    backend._audit[1]["details"]["bytes"] = 1  # restore
    assert vault.verify_audit(anchor).ok
    del backend._audit[-1]
    assert vault.verify_audit().ok and not vault.verify_audit(anchor).ok


def test_scan_flags_brute_force_and_records_alert_once(backend, clock, monkeypatch):
    # Deliberate change (Phase 1): this test exercises the MONITOR rule with six consecutive bad
    # unlocks. The new lockout would stop the 6th attempt, so the limiter is set far above six here.
    # Lockout behaviour itself is covered in tests/unit/test_lockout.py. Assertions are unchanged.
    from securevault.config import get_settings

    monkeypatch.setenv("RATE_LIMIT_MAX_FAILURES", "1000")
    monkeypatch.setenv("RATE_LIMIT_GLOBAL_MAX_FAILURES", "1000")
    get_settings.cache_clear()
    v = Vault.initialize(backend, PASSPHRASE, kdf_params=FAST_TEST_PARAMS, clock=clock,
                         detector=Detector(None, window_seconds=300))
    attacker = Vault(backend, clock=clock, detector=Detector(None, window_seconds=300))
    for _ in range(6):
        with pytest.raises(InvalidPassphrase):
            attacker.unlock("guess-guess-guess")
        clock.advance(1)
    result = v.scan()
    assert any(a.rule == "failed_unlocks" for a in result.alerts)
    assert sum(e["event"] == "alert" for e in v.audit_entries()) >= 1
    n = len(v.audit_entries())
    v.scan()  # same window: must not log duplicates
    assert len(v.audit_entries()) == n
    assert v.verify_audit().ok
    get_settings.cache_clear()


def test_alerts_do_not_feed_back_into_the_monitor(vault):
    vault.scan()
    first = vault.scan().windows_scanned
    assert vault.scan().windows_scanned == first


def test_vault_flow_on_real_postgres(tmp_path_factory, clock):
    pgserver = pytest.importorskip("pgserver")
    pytest.importorskip("psycopg")
    from securevault.storage.remote import PostgresBackend

    server = pgserver.get_server(tmp_path_factory.mktemp("pgflow"), cleanup_mode="stop")
    v = Vault.initialize(PostgresBackend(server.get_uri()), PASSPHRASE, kdf_params=FAST_TEST_PARAMS, clock=clock)
    info = v.upload("a.txt", b"stored in postgres")
    assert v.download(info.file_id)[1] == b"stored in postgres"
    assert v.rotate_keys() == 1
    assert v.download(info.file_id)[1] == b"stored in postgres"
    assert v.verify_audit().ok
