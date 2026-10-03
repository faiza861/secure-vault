"""MFA at the Vault (library) level: enrollment, replay, passphrase change, legacy, tamper, disable."""

import json

import pytest
from tests.conftest import PASSPHRASE
from typer.testing import CliRunner

from securevault.cli.main import app as cli_app
from securevault.config import get_settings
from securevault.core import mfa_secret, totp
from securevault.core.kdf import FAST_TEST_PARAMS
from securevault.storage.local import LocalBackend
from securevault.storage.vault import Vault
from securevault.utils.exceptions import IntegrityError, InvalidMfaCode, MfaAlreadyEnabled, RateLimited


@pytest.fixture(autouse=True)
def _settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def enroll(vault, clock):
    secret, _ = vault.mfa_begin_enrollment()
    vault.mfa_confirm_enrollment(secret, totp.totp(secret, clock()))
    return secret


def test_legacy_keystore_without_mfa_block_works_unchanged(vault, backend):
    assert "mfa" not in backend.load_keystore()
    assert vault.mfa_required is False
    fresh = Vault(backend, clock=vault.clock)
    fresh.unlock(PASSPHRASE)
    assert fresh.upload("a.txt", b"x").size == 1 and fresh.verify_audit().ok


def test_begin_enrollment_persists_nothing_and_needs_unlock(vault, backend):
    before = json.dumps(backend.load_keystore(), sort_keys=True)
    secret, uri = vault.mfa_begin_enrollment()
    assert totp.is_valid_secret(secret) and secret in uri
    assert json.dumps(backend.load_keystore(), sort_keys=True) == before and vault.mfa_required is False
    vault.lock()
    from securevault.utils.exceptions import VaultLocked

    with pytest.raises(VaultLocked):
        vault.mfa_begin_enrollment()


def test_enrollment_happy_path(vault, backend, clock):
    secret = enroll(vault, clock)
    assert vault.mfa_required is True
    block = backend.load_keystore()["mfa"]
    assert block["enabled"] is True and block["version"] == 1
    assert secret not in json.dumps(backend.load_keystore())  # only ciphertext is stored
    events = [e["event"] for e in vault.audit_entries()]
    assert "mfa_enabled" in events and vault.verify_audit().ok
    with pytest.raises(MfaAlreadyEnabled):
        vault.mfa_begin_enrollment()


def test_wrong_confirmation_code_is_not_persisted(vault, backend, clock):
    secret, _ = vault.mfa_begin_enrollment()
    wrong = "000000" if totp.totp(secret, clock()) != "000000" else "111111"
    with pytest.raises(InvalidMfaCode):
        vault.mfa_confirm_enrollment(secret, wrong)
    assert "mfa" not in backend.load_keystore() and vault.mfa_required is False
    assert [e["event"] for e in vault.audit_entries()].count("mfa_failed") == 1
    with pytest.raises(InvalidMfaCode):  # a secret we never issued is refused too
        vault.mfa_confirm_enrollment("AAAAAAAA", "123456")
    assert "mfa" not in backend.load_keystore()


def test_replay_is_rejected_and_next_step_is_accepted(vault, clock):
    secret = enroll(vault, clock)  # enrollment consumed this step's code
    with pytest.raises(InvalidMfaCode):
        vault.verify_mfa(totp.totp(secret, clock()))  # same code again: replay
    clock.advance(30)
    step = vault.verify_mfa(totp.totp(secret, clock()))
    assert step == int(clock() // 30)
    with pytest.raises(InvalidMfaCode):
        vault.verify_mfa(totp.totp(secret, clock()))


def test_codes_older_than_the_newest_used_step_are_rejected(vault, clock):
    secret = enroll(vault, clock)
    clock.advance(60)
    vault.verify_mfa(totp.totp(secret, clock()))
    with pytest.raises(InvalidMfaCode):  # a still-in-window but OLDER step than the one just used
        vault.verify_mfa(totp.hotp(totp._decode_secret(secret), int(clock() // 30) - 1))


def test_window_tolerance_accepts_neighbouring_steps(vault, clock):
    secret = enroll(vault, clock)
    clock.advance(60)
    assert vault.verify_mfa(totp.totp(secret, clock() + 30)) == int(clock() // 30) + 1  # one step ahead
    clock.advance(120)
    with pytest.raises(InvalidMfaCode):  # two steps off: outside the window
        vault.verify_mfa(totp.totp(secret, clock() - 90))


def test_missing_and_malformed_codes(vault, clock):
    enroll(vault, clock)
    clock.advance(30)
    for bad in ("", "12345", "abcdef", "1234567"):
        with pytest.raises(InvalidMfaCode):
            vault.verify_mfa(bad)


def test_passphrase_change_keeps_mfa_working(vault, backend, clock):
    secret = enroll(vault, clock)
    old_block = backend.load_keystore()["mfa"]["enc_secret"]
    vault.rotate_passphrase("a brand new passphrase", params=FAST_TEST_PARAMS)
    ks = backend.load_keystore()
    assert ks["mfa"]["enc_secret"] != old_block  # re-encrypted under the new KEK
    fresh = Vault(backend, clock=clock)
    fresh.unlock("a brand new passphrase")
    assert fresh.mfa_required
    clock.advance(30)
    fresh.verify_mfa(totp.totp(secret, clock()))  # the SAME authenticator still works
    # and the old KEK can no longer read the block
    with pytest.raises(IntegrityError):
        from securevault.core import kdf
        from securevault.core.envelope import b64d
        old = kdf.derive_key(PASSPHRASE, b64d(ks["kdf"]["salt"]), FAST_TEST_PARAMS)
        mfa_secret.open_secret(old, ks["mfa"])


def test_corrupt_mfa_block_blocks_passphrase_change_without_saving(vault, backend, clock):
    enroll(vault, clock)
    ks = backend.load_keystore()
    ks["mfa"]["enc_secret"] = ks["mfa"]["enc_secret"][:-6] + "AAAAAA"
    backend.save_keystore(ks)
    snapshot = json.dumps(backend.load_keystore(), sort_keys=True)
    with pytest.raises(IntegrityError):
        vault.rotate_passphrase("another good passphrase", params=FAST_TEST_PARAMS)
    assert json.dumps(backend.load_keystore(), sort_keys=True) == snapshot  # nothing half-written
    Vault(backend, clock=clock).unlock(PASSPHRASE)  # old passphrase still opens the vault


def test_key_rotation_leaves_mfa_block_untouched(vault, backend, clock):
    enroll(vault, clock)
    vault.upload("f.txt", b"data")
    before = backend.load_keystore()["mfa"]
    vault.rotate_keys()
    assert backend.load_keystore()["mfa"] == before and vault.mfa_required


def test_tampered_ciphertext_raises_integrity_error(vault, backend, clock):
    enroll(vault, clock)
    ks = backend.load_keystore()
    raw = bytearray(__import__("base64").b64decode(ks["mfa"]["enc_secret"]))
    raw[-1] ^= 1
    ks["mfa"]["enc_secret"] = __import__("base64").b64encode(bytes(raw)).decode()
    backend.save_keystore(ks)
    clock.advance(30)
    with pytest.raises(IntegrityError):
        vault.verify_mfa("123456")
    ks["mfa"] = "garbage"  # malformed block: still required (fail closed), still no crash
    backend.save_keystore(ks)
    assert vault.mfa_required is True
    with pytest.raises(InvalidMfaCode):
        vault.verify_mfa("123456")


def test_disable_needs_a_valid_code(vault, backend, clock):
    secret = enroll(vault, clock)
    with pytest.raises(InvalidMfaCode):
        vault.mfa_disable("000000")
    assert vault.mfa_required
    clock.advance(30)
    vault.mfa_disable(totp.totp(secret, clock()))
    assert vault.mfa_required is False and "mfa" not in backend.load_keystore()
    assert "mfa_disabled" in [e["event"] for e in vault.audit_entries()]
    with pytest.raises(InvalidMfaCode):  # nothing left to disable
        vault.mfa_disable("123456")


def test_audit_never_contains_codes_or_secrets(vault, clock):
    secret = enroll(vault, clock)
    code = totp.totp(secret, clock() + 30)
    clock.advance(30)
    vault.verify_mfa(code)
    with pytest.raises(InvalidMfaCode):
        vault.verify_mfa("654321")
    dump = json.dumps(vault.audit_entries())
    assert secret not in dump and code not in dump and "654321" not in dump
    for e in vault.audit_entries():
        if e["event"].startswith("mfa_"):
            assert set(e["details"]) <= {"step", "via"}


def test_mfa_failures_feed_the_lockout(vault, clock):
    enroll(vault, clock)
    clock.advance(30)
    for _ in range(4):
        with pytest.raises(InvalidMfaCode):
            vault.verify_mfa("000000")
    with pytest.raises(RateLimited):  # 5th wrong code trips the lockout, like wrong passphrases do
        vault.verify_mfa("000000")
    with pytest.raises(RateLimited):
        vault.verify_mfa("000000")


def test_mfa_works_on_the_local_backend_and_cli_recovery(tmp_path, monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "v"))
    monkeypatch.setenv("SECUREVAULT_PASSPHRASE", PASSPHRASE)
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "none.json"))
    get_settings.cache_clear()
    backend = LocalBackend(tmp_path / "v")
    v = Vault.initialize(backend, PASSPHRASE, kdf_params=FAST_TEST_PARAMS)
    secret, _ = v.mfa_begin_enrollment()
    v.mfa_confirm_enrollment(secret, totp.totp(secret))
    runner = CliRunner()
    assert "enabled" in runner.invoke(cli_app, ["mfa", "status"]).output
    r = runner.invoke(cli_app, ["mfa", "disable"])  # passphrase only: the documented recovery path
    assert r.exit_code == 0 and "disabled" in r.output
    assert "disabled" in runner.invoke(cli_app, ["mfa", "status"]).output
    last = [e for e in backend.read_audit() if e["event"] == "mfa_disabled"][-1]
    assert last["details"] == {"via": "local_recovery"} and backend.read_audit() and Vault(backend).verify_audit().ok
