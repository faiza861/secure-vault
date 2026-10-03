"""The Vault: ties encryption, storage, the audit chain and the monitor together."""

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from securevault.audit import chain
from securevault.config import get_settings
from securevault.core import envelope, mfa_secret, totp
from securevault.core.integrity import constant_time_equal, sha256_hex
from securevault.core.kdf import KdfParams
from securevault.monitor.detector import Detector, ScanResult
from securevault.monitor.model import load_model
from securevault.monitor.rules import Alert
from securevault.security.lockout import check_lockout, policy_from_settings
from securevault.storage.base import StorageBackend
from securevault.utils.exceptions import (
    IntegrityError,
    InvalidMfaCode,
    InvalidPassphrase,
    MfaAlreadyEnabled,
    RateLimited,
    StorageConflict,
    UploadTooLarge,
    VaultAlreadyInitialized,
    VaultLocked,
    VaultNotInitialized,
    WeakPassphrase,
)

Clock = Callable[[], float]
_APPEND_RETRIES = 5
# How many recent audit entries the lockout check looks at. Failures are capped by the
# lockout itself, so a bounded tail is enough and keeps the check cheap on a long log.
_LOCKOUT_SCAN_ENTRIES = 500


@dataclass(frozen=True)
class FileInfo:
    file_id: str
    size: int
    created_ts: float
    key_version: int
    name: str | None  # None while the vault is locked


def check_passphrase(passphrase: str, minimum: int) -> None:
    if len(passphrase) < minimum:
        raise WeakPassphrase(f"passphrase must be at least {minimum} characters")


class Vault:
    def __init__(
        self,
        backend: StorageBackend,
        *,
        actor: str = "local",
        clock: Clock = time.time,
        detector: Detector | None = None,
        min_passphrase_length: int | None = None,
        max_upload_bytes: int | None = None,
    ) -> None:
        settings = get_settings()
        self.backend = backend
        self.actor = actor
        self.clock = clock
        self.min_passphrase_length = min_passphrase_length or settings.min_passphrase_length
        self.max_upload_bytes = max_upload_bytes or settings.max_upload_bytes
        self._detector = detector
        self._unlocked: envelope.UnlockedKeys | None = None

    # ------------------------------------------------------------ lifecycle
    @classmethod
    def initialize(
        cls,
        backend: StorageBackend,
        passphrase: str,
        *,
        kdf_params: KdfParams = KdfParams(),
        **kwargs,
    ) -> "Vault":
        vault = cls(backend, **kwargs)
        if backend.load_keystore() is not None:
            raise VaultAlreadyInitialized("a vault already exists here")
        check_passphrase(passphrase, vault.min_passphrase_length)
        keystore, unlocked = envelope.create_keystore(passphrase, kdf_params)
        backend.save_keystore(keystore)
        vault._unlocked = unlocked
        vault._log("vault_created", {"kem": keystore["kem"]["algorithm"], "kdf": "argon2id"})
        return vault

    @property
    def initialized(self) -> bool:
        return self.backend.load_keystore() is not None

    @property
    def unlocked(self) -> bool:
        return self._unlocked is not None

    def _keystore(self) -> dict:
        keystore = self.backend.load_keystore()
        if keystore is None:
            raise VaultNotInitialized("run init first")
        return keystore

    def _need_unlock(self) -> envelope.UnlockedKeys:
        if self._unlocked is None:
            raise VaultLocked("unlock the vault first")
        return self._unlocked

    def _lockout_decision(self):
        policy = policy_from_settings(get_settings())
        tail = self.backend.read_audit_tail(_LOCKOUT_SCAN_ENTRIES)
        return check_lockout(tail, self.clock(), self.actor, policy)

    def enforce_lockout(self) -> None:
        """Raise RateLimited if this actor (or the whole vault) is currently locked out.

        SECURITY: runs BEFORE any Argon2id work, so a flood of guesses cannot burn CPU while
        locked out. FAIL CLOSED: if the check itself breaks for any unexpected reason the
        attempt is denied with a generic error; it is never silently allowed.
        """
        try:
            decision = self._lockout_decision()
        except Exception:  # noqa: BLE001 - deliberate: any failure of the guard means "deny"
            raise RateLimited(get_settings().lockout_seconds, "Temporarily unavailable. Try again later.") from None
        if not decision.allowed:
            raise RateLimited(decision.retry_after)

    def record_auth_failure(self, event: str) -> None:
        """Write `unlock_failed` / `mfa_failed` to the audit chain and, if this failure trips a
        limit, write a `lockout` event and raise RateLimited. Details never hold secrets."""
        entry = self._log(event, {})
        try:
            decision = self._lockout_decision()
        except Exception:  # noqa: BLE001 - fail closed, see enforce_lockout
            raise RateLimited(get_settings().lockout_seconds, "Temporarily unavailable. Try again later.") from None
        # A lockout that began at THIS failure's timestamp was triggered by it: record it once.
        if not decision.allowed and decision.started_at == entry["ts"]:
            self._log("lockout", {"scope": decision.scope, "seconds": decision.duration})
        if not decision.allowed:
            raise RateLimited(decision.retry_after)

    def unlock(self, passphrase: str) -> None:
        self.enforce_lockout()  # before Argon2id and before anything else (CLI and API share this path)
        keystore = self._keystore()
        try:
            self._unlocked = envelope.unlock(keystore, passphrase)
        except InvalidPassphrase:
            self.record_auth_failure("unlock_failed")
            raise
        except (KeyError, TypeError, ValueError):
            # A corrupt keystore must surface as a controlled error, never an unhandled crash.
            raise IntegrityError("keystore is malformed") from None
        self._log("unlock", {})

    def lock(self) -> None:
        self._unlocked = None

    # ---------------------------------------------------------------- audit
    def _log(self, event: str, details: dict) -> dict:
        """Append to the hash chain. Retries if another writer extended the chain first."""
        for _ in range(_APPEND_RETRIES):
            tail = self.backend.read_audit_tail(1)  # only the newest entry is needed to extend the chain
            entry = chain.make_entry(tail[-1] if tail else None, event, self.actor, details, self.clock())
            try:
                self.backend.append_audit(entry)
                return entry
            except StorageConflict:
                continue
        raise StorageConflict("could not append to the audit log")

    def record_event(self, event: str, details: dict) -> dict:
        """Public way for the API layer to add a (non-secret) event, e.g. session_created."""
        return self._log(event, details)

    def audit_since(self, since_ts: float, cap: int = 5000) -> list[dict]:
        """Every entry with ts >= since_ts, reading only as much of the log tail as needed. If the
        window is larger than `cap` entries it raises instead of returning a partial answer, so a
        caller that relies on completeness (session revocation) fails closed."""
        n = 200
        while True:
            tail = self.backend.read_audit_tail(n)
            if len(tail) < n or (tail and tail[0]["ts"] < since_ts):
                return [e for e in tail if e["ts"] >= since_ts]
            if n >= cap:
                raise IntegrityError("audit window too large to check")
            n = min(n * 4, cap)

    def audit_entries(self) -> list[dict]:
        return self.backend.read_audit()

    def verify_audit(self, expected_head: str | None = None) -> chain.Verification:
        return chain.verify(self.backend.read_audit(), expected_head)

    # ---------------------------------------------------------------- files
    def upload(self, name: str, data: bytes) -> FileInfo:
        """Encrypt and store a file. Needs only the PUBLIC key, so the vault can stay locked."""
        if len(data) > self.max_upload_bytes:
            raise UploadTooLarge(f"file exceeds {self.max_upload_bytes} bytes")
        keystore = self._keystore()
        version, public_key = envelope.active_public_key(keystore)
        file_id = uuid.uuid4().hex
        sealed = envelope.seal_file(public_key, file_id, name, data)
        meta = {
            "file_id": file_id,
            "created_ts": round(self.clock(), 3),
            "size": len(data),
            "key_version": version,
            # Hash of the CIPHERTEXT. Hashing the plaintext would let anyone holding the
            # metadata confirm a guess about a file's contents.
            "ciphertext_sha256": sha256_hex(sealed.blob),
            "wrapped_dek": sealed.wrapped_dek,
            "enc_name": sealed.enc_name,
        }
        self.backend.put_file(file_id, sealed.blob, meta)
        self._log("upload", {"file_id": file_id, "bytes": len(data)})
        return FileInfo(file_id, len(data), meta["created_ts"], version, name)

    def download(self, file_id: str) -> tuple[str, bytes]:
        unlocked = self._need_unlock()
        blob, meta = self.backend.get_file(file_id)
        if not constant_time_equal(sha256_hex(blob), meta["ciphertext_sha256"]):
            self._log("integrity_failure", {"file_id": file_id, "stage": "ciphertext_hash"})
            raise IntegrityError("stored ciphertext does not match its recorded hash")
        secret_key = unlocked.secret_keys.get(meta["key_version"])
        if secret_key is None:
            raise IntegrityError("no key available for this file's key version")
        try:
            name, data = envelope.open_file(secret_key, file_id, blob, meta["wrapped_dek"], meta["enc_name"])
        except IntegrityError:
            self._log("integrity_failure", {"file_id": file_id, "stage": "decrypt"})
            raise
        self._log("download", {"file_id": file_id, "bytes": len(data)})
        return name, data

    def list_files(self) -> list[FileInfo]:
        """Names are encrypted, so they only appear while the vault is unlocked."""
        infos = []
        for meta in self.backend.list_meta():
            name = None
            if self._unlocked is not None:
                secret_key = self._unlocked.secret_keys.get(meta["key_version"])
                if secret_key is not None:
                    name = envelope.open_name(secret_key, meta["file_id"], meta["wrapped_dek"], meta["enc_name"])
            infos.append(FileInfo(meta["file_id"], meta["size"], meta["created_ts"], meta["key_version"], name))
        return infos

    def delete(self, file_id: str) -> None:
        self._need_unlock()
        self.backend.delete_file(file_id)
        self._log("delete", {"file_id": file_id})

    # ------------------------------------------------------------- rotation
    def rotate_passphrase(self, new_passphrase: str, params: KdfParams = KdfParams()) -> None:
        """Re-encrypt the ML-KEM secret key(s) under a new passphrase. O(1): no file is touched."""
        unlocked = self._need_unlock()
        check_passphrase(new_passphrase, self.min_passphrase_length)
        keystore = self._keystore()
        new_keystore, new_unlocked = envelope.change_passphrase(keystore, unlocked, new_passphrase, params)
        if "mfa" in keystore:
            # SECURITY: envelope.change_passphrase copies the MFA block unchanged, i.e. still encrypted
            # under the OLD key. Re-encrypt it under the NEW key HERE, before the one atomic save, so
            # the keystore is never written in a state where MFA cannot be decrypted. If the block is
            # corrupt this raises IntegrityError and nothing is saved (the passphrase stays unchanged).
            new_keystore["mfa"] = mfa_secret.rewrap(unlocked.kek, new_unlocked.kek, keystore["mfa"])
        self.backend.save_keystore(new_keystore)  # single atomic replace
        self._unlocked = new_unlocked
        self._log("rotate_passphrase", {})

    def rotate_keys(self) -> int:
        """Create a new ML-KEM key pair and re-wrap every file's data key to it.

        File ciphertext is never re-encrypted: only the 32-byte DEK wrappers change.
        Crash-safe: the new key is added to the keystore FIRST, files are then migrated one
        by one (each file records which key version wraps it), and old keys are dropped last.
        Running rotate_keys() again after a crash finishes the migration.
        """
        unlocked = self._need_unlock()
        keystore = self._keystore()
        if len(keystore["keys"]) == 1:  # normal case; otherwise resume an interrupted rotation
            keystore, unlocked = envelope.add_key_version(keystore, unlocked)
            self.backend.save_keystore(keystore)
            self._unlocked = unlocked
        version, public_key = envelope.active_public_key(keystore)
        migrated = 0
        for meta in self.backend.list_meta():
            if meta["key_version"] == version:
                continue
            old_sk = unlocked.secret_keys[meta["key_version"]]
            meta["wrapped_dek"] = envelope.rewrap_dek(old_sk, public_key, meta["file_id"], meta["wrapped_dek"])
            meta["key_version"] = version
            self.backend.update_meta(meta["file_id"], meta)
            migrated += 1
        in_use = {m["key_version"] for m in self.backend.list_meta()}
        keystore, unlocked = envelope.drop_unused_versions(keystore, unlocked, in_use)
        self.backend.save_keystore(keystore)
        self._unlocked = unlocked
        self._log("rotate_keys", {"new_version": version, "files_rewrapped": migrated})
        return migrated


    # ------------------------------------------------------------------ MFA (TOTP)
    @property
    def mfa_required(self) -> bool:
        """True when this vault has MFA switched on. A keystore with no "mfa" block (every vault
        created before this feature) is simply 'disabled'. FAIL CLOSED: a block that exists but is
        malformed counts as required, so damaging it can never be a way to skip the second factor."""
        block = self._keystore().get("mfa")
        if block is None:
            return False
        return not (isinstance(block, dict) and block.get("enabled") is False)

    def _mfa_secret(self) -> str:
        unlocked = self._need_unlock()
        block = self._keystore().get("mfa")
        if not isinstance(block, dict):
            raise InvalidMfaCode("MFA is not enabled")
        return mfa_secret.open_secret(unlocked.kek, block)  # IntegrityError if tampered

    def _last_mfa_step(self) -> int:
        """Newest TOTP step already used, read from the audit log (replay protection without new
        storage). Steps are only valid for ~90 s, so the recent tail is enough."""
        steps = [
            e["details"]["step"]
            for e in self.backend.read_audit_tail(_LOCKOUT_SCAN_ENTRIES)
            if e["event"] == "mfa_ok" and isinstance(e.get("details", {}).get("step"), int)
        ]
        return max(steps, default=-1)

    def _check_code(self, secret: str, code: str) -> int:
        """Validate a code against `secret`; return its step. Every failure is logged as `mfa_failed`
        (never with the code) and counts toward the lockout. A step that was already accepted, or is
        older than the newest accepted one, is rejected: a code works once."""
        self.enforce_lockout()
        step = totp.verify(secret, code, now=self.clock())
        if step is None or step <= self._last_mfa_step():
            self.record_auth_failure("mfa_failed")
            raise InvalidMfaCode("invalid authenticator code")
        self._log("mfa_ok", {"step": step})  # the step counter is non-secret metadata
        return step

    def mfa_begin_enrollment(self, account: str = "vault") -> tuple[str, str]:
        """Make a NEW secret and its otpauth URI. Persists NOTHING: MFA stays off until the user proves
        their authenticator works through mfa_confirm_enrollment. Needs an unlocked vault."""
        self._need_unlock()
        if self.mfa_required:
            raise MfaAlreadyEnabled("MFA is already enabled")
        secret = totp.generate_secret()
        return secret, totp.provisioning_uri(secret, account)

    def mfa_confirm_enrollment(self, secret: str, code: str) -> None:
        """Turn MFA on, but only after `code` is valid for `secret`. One atomic keystore replace."""
        unlocked = self._need_unlock()
        if self.mfa_required:
            raise MfaAlreadyEnabled("MFA is already enabled")
        if not totp.is_valid_secret(secret):  # reject anything that is not a secret we could have issued
            self.enforce_lockout()
            self.record_auth_failure("mfa_failed")
            raise InvalidMfaCode("invalid authenticator code")
        step = self._check_code(secret, code)
        keystore = self._keystore()
        keystore["mfa"] = mfa_secret.seal(unlocked.kek, secret)
        self.backend.save_keystore(keystore)
        self._log("mfa_enabled", {"step": step})

    def verify_mfa(self, code: str) -> int:
        """Check a code for an MFA-enabled vault (needs the vault unlocked). Returns the used step."""
        return self._check_code(self._mfa_secret(), code)

    def mfa_disable(self, code: str) -> None:
        """Switch MFA off. Needs a currently valid code, so a passphrase alone cannot remove it."""
        self.verify_mfa(code)
        self._remove_mfa_block("mfa_disabled", {})

    def mfa_reset_local(self) -> None:
        """Lost-authenticator RECOVERY, used only by the local CLI. Requires the passphrase (unlock)
        but no code: whoever can run the CLI already owns the disk, and an MFA that can never be
        recovered would lock the owner out of their own files. Logged so it cannot be silent."""
        self._need_unlock()
        if not self.mfa_required:
            raise InvalidMfaCode("MFA is not enabled")
        self._remove_mfa_block("mfa_disabled", {"via": "local_recovery"})

    def _remove_mfa_block(self, event: str, details: dict) -> None:
        keystore = self._keystore()
        keystore.pop("mfa", None)  # back to the legacy shape: missing block == disabled
        self.backend.save_keystore(keystore)  # atomic
        self._log(event, details)

    # -------------------------------------------------------------- monitor
    def detector(self) -> Detector:
        if self._detector is None:
            settings = get_settings()
            self._detector = Detector(
                model=load_model(settings.model_path),
                window_seconds=settings.window_seconds,
                tz_offset_hours=settings.tz_offset_hours,
            )
        return self._detector

    def scan(self, record: bool = True) -> ScanResult:
        """Run the detector over the whole audit log. New alerts are written into the chain."""
        entries = self.backend.read_audit()
        result = self.detector().scan(entries)
        if record:
            known = {
                (e["details"].get("window_start"), e["details"].get("rule"))
                for e in entries
                if e["event"] == "alert"
            }
            for alert in result.alerts:
                if (alert.window_start, alert.rule) not in known:
                    self._log("alert", _alert_details(alert))
        return result


def _alert_details(alert: Alert) -> dict:
    return {k: v for k, v in alert.to_dict().items() if v is not None}
