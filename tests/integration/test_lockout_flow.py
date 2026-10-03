"""Lockout wired into Vault, API and CLI."""

import json

import pytest
from fastapi.testclient import TestClient
from tests.conftest import PASSPHRASE
from typer.testing import CliRunner

import securevault.storage as storage_pkg
from securevault.audit import chain
from securevault.cli.main import app as cli_app
from securevault.config import get_settings
from securevault.core.kdf import FAST_TEST_PARAMS
from securevault.storage.memory import MemoryBackend
from securevault.storage.vault import Vault
from securevault.utils.exceptions import InvalidPassphrase, RateLimited, StorageConflict

BAD = "definitely not the passphrase"


@pytest.fixture(autouse=True)
def _fresh_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _attempt(vault, pw=BAD):
    try:
        vault.unlock(pw)
    except (InvalidPassphrase, RateLimited) as exc:
        return exc
    return None


def test_audit_chain_stays_valid_across_many_appends(vault):
    for _ in range(25):
        vault._log("note", {})
    assert vault.verify_audit().ok and vault.verify_audit().length >= 26


def test_log_retries_on_conflict_and_chain_still_verifies(backend, clock):
    v = Vault.initialize(backend, PASSPHRASE, kdf_params=FAST_TEST_PARAMS, clock=clock)
    real_append = backend.append_audit
    calls = {"n": 0}

    def racing_append(entry):
        calls["n"] += 1
        if calls["n"] == 1:  # another writer sneaks in first, so our slot is taken
            real_append(chain.make_entry(backend.read_audit()[-1], "other_writer", "peer", {}, clock()))
            raise StorageConflict("audit chain moved on")
        real_append(entry)

    backend.append_audit = racing_append
    v._log("probe", {})
    entries = backend.read_audit()
    assert [e["event"] for e in entries][-2:] == ["other_writer", "probe"]
    assert chain.verify(entries).ok


def test_fifth_failure_locks_and_sixth_is_blocked_before_argon2(vault, monkeypatch):
    for _ in range(4):
        assert isinstance(_attempt(vault), InvalidPassphrase)
    tripped = _attempt(vault)
    assert isinstance(tripped, RateLimited) and tripped.retry_after >= 1
    events = [e["event"] for e in vault.audit_entries()]
    assert events.count("unlock_failed") == 5 and events.count("lockout") == 1

    from securevault.core import envelope

    def boom(*a, **k):
        raise AssertionError("Argon2id ran while locked out")

    monkeypatch.setattr(envelope, "unlock", boom)
    assert isinstance(_attempt(vault, PASSPHRASE), RateLimited)  # even the CORRECT passphrase is refused
    assert [e["event"] for e in vault.audit_entries()].count("lockout") == 1  # no log flooding while locked


def test_below_limit_correct_passphrase_still_works_and_recovers_after_wait(vault, clock):
    for _ in range(4):
        _attempt(vault)
    vault.unlock(PASSPHRASE)  # 4 failures: not blocked
    assert vault.unlocked
    vault.lock()
    _attempt(vault)  # 5th failure trips the limit
    assert isinstance(_attempt(vault, PASSPHRASE), RateLimited)
    clock.advance(61)
    vault.unlock(PASSPHRASE)  # recovered
    assert vault.unlocked


def test_env_configuration_is_respected(backend, clock, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_MAX_FAILURES", "2")
    monkeypatch.setenv("LOCKOUT_SECONDS", "30")
    get_settings.cache_clear()
    v = Vault.initialize(backend, PASSPHRASE, kdf_params=FAST_TEST_PARAMS, clock=clock)
    _attempt(v)
    exc = _attempt(v)
    assert isinstance(exc, RateLimited) and exc.retry_after == 30


def test_guard_failure_fails_closed(vault, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("storage exploded")

    vault.lock()  # the fixture's vault starts unlocked from initialize()
    monkeypatch.setattr(vault.backend, "read_audit_tail", broken)
    with pytest.raises(RateLimited):  # denied, not allowed and not an unhandled RuntimeError
        vault.unlock(PASSPHRASE)
    assert not vault.unlocked


def test_events_hold_no_secrets(vault):
    for _ in range(5):
        _attempt(vault)
    dump = json.dumps(vault.audit_entries())
    assert BAD not in dump and PASSPHRASE not in dump
    for e in vault.audit_entries():
        if e["event"] in {"unlock_failed", "lockout"}:
            assert set(e["details"]) <= {"scope", "seconds"}


# ------------------------------------------------------------------------------- API


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("STORAGE_BACKEND", "memory")
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "none.json"))
    get_settings.cache_clear()
    storage_pkg._memory_singleton = None
    from securevault.api.main import create_app

    yield TestClient(create_app())
    storage_pkg._memory_singleton = None


def test_api_returns_429_with_retry_after(client):
    pw = "api lockout passphrase"
    client.post("/api/init", json={"passphrase": pw})
    codes = [client.post("/api/files/list", json={"passphrase": BAD}).status_code for _ in range(4)]
    assert codes == [401, 401, 401, 401]
    r = client.post("/api/files/list", json={"passphrase": BAD})  # 5th failure
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) == r.json()["retry_after"] >= 1
    assert r.json()["code"] == "rate_limited"
    # The correct passphrase is refused too while locked out, and nothing leaks about why.
    r2 = client.post("/api/files/list", json={"passphrase": pw})
    assert r2.status_code == 429 and "mfa" not in r2.text.lower()
    assert client.get("/api/audit").json()["ok"]


# ------------------------------------------------------------------------------- CLI


def test_cli_enforces_lockout(tmp_path, monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "vault"))
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "none.json"))
    monkeypatch.setenv("SECUREVAULT_PASSPHRASE", "cli lockout passphrase")
    get_settings.cache_clear()
    runner = CliRunner()
    pw = "cli lockout passphrase"
    assert runner.invoke(cli_app, ["init"], input=f"{pw}\n{pw}\n").exit_code == 0
    monkeypatch.setenv("SECUREVAULT_PASSPHRASE", BAD)
    for _ in range(5):
        assert runner.invoke(cli_app, ["list"]).exit_code == 1
    monkeypatch.setenv("SECUREVAULT_PASSPHRASE", pw)
    blocked = runner.invoke(cli_app, ["list"])
    assert blocked.exit_code == 1 and "Too many attempts" in blocked.output


def test_memory_backend_isolation_helper():
    assert MemoryBackend().read_audit_tail(5) == []
