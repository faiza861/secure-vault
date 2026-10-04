"""Exception hierarchy. Every error raised on purpose derives from SecureVaultError."""


class SecureVaultError(Exception):
    """Base class for all Secure Vault errors."""


class WeakPassphrase(SecureVaultError):
    """The passphrase does not meet the minimum length."""


class InvalidPassphrase(SecureVaultError):
    """The passphrase could not unlock the vault."""


class VaultLocked(SecureVaultError):
    """The operation needs the vault to be unlocked first."""


class VaultNotInitialized(SecureVaultError):
    """No vault exists in this storage backend yet."""


class VaultAlreadyInitialized(SecureVaultError):
    """A vault already exists in this storage backend."""


class FileNotFound(SecureVaultError):
    """No file with this id exists."""


class IntegrityError(SecureVaultError):
    """Stored data failed an integrity or authenticity check."""


class StorageConflict(SecureVaultError):
    """A concurrent writer changed the data first (e.g. audit chain fork)."""


class UploadTooLarge(SecureVaultError):
    """The file exceeds the configured upload limit."""


class RateLimited(SecureVaultError):
    """Too many failed attempts. The caller must wait `retry_after` seconds."""

    code = "rate_limited"

    def __init__(self, retry_after: int, message: str = "Too many attempts. Try again later.") -> None:
        super().__init__(message)
        self.retry_after = max(1, int(retry_after))


class MfaRequired(SecureVaultError):
    """The passphrase was right, but this action also needs a current authenticator code."""

    code = "mfa_required"


class InvalidMfaCode(SecureVaultError):
    """The authenticator code was wrong, malformed, expired or already used."""

    code = "invalid_mfa_code"


class MfaAlreadyEnabled(SecureVaultError):
    """MFA is already switched on for this vault."""

    code = "mfa_already_enabled"


class SessionInvalid(SecureVaultError):
    """The session token is missing, malformed, forged, revoked or could not be checked."""

    code = "session_invalid"


class SessionExpired(SecureVaultError):
    """The session token was genuine but has timed out (absolute lifetime or inactivity)."""

    code = "session_expired"

    def __init__(self, reason: str = "expired") -> None:
        super().__init__("session expired")
        self.reason = reason  # "idle" or "absolute"; used for the audit log only


class DemoRestricted(SecureVaultError):
    """This action is switched off in the shared public demo (DEMO_MODE)."""

    code = "demo_restricted"
