from pydantic import BaseModel, Field

# Upper bound stops someone from sending a megabyte "passphrase" to burn CPU.
Passphrase = Field(min_length=1, max_length=256)
# Optional authenticator code: digits only and length-limited, so junk never reaches the verifier.
# Optional so every old client (and test) that sends only a passphrase keeps working.
TotpCode = Field(default=None, max_length=8, pattern=r"^[0-9]{1,8}$")


class InitRequest(BaseModel):
    passphrase: str = Passphrase


class PassphraseRequest(BaseModel):
    passphrase: str = Passphrase
    totp_code: str | None = TotpCode


class RotatePassphraseRequest(BaseModel):
    passphrase: str = Passphrase
    new_passphrase: str = Field(min_length=1, max_length=256)
    totp_code: str | None = TotpCode


class SessionRequest(PassphraseRequest):
    """Passphrase (+ code when MFA is on) to open or renew a session."""


class MfaConfirmRequest(BaseModel):
    passphrase: str = Passphrase
    secret: str = Field(min_length=16, max_length=64, pattern=r"^[A-Za-z2-7]+$")  # Base32 only
    code: str = Field(min_length=1, max_length=8, pattern=r"^[0-9]{1,8}$")


class MfaDisableRequest(BaseModel):
    passphrase: str = Passphrase
    totp_code: str = Field(min_length=1, max_length=8, pattern=r"^[0-9]{1,8}$")  # a code is mandatory


class FileOut(BaseModel):
    file_id: str
    size: int
    created_ts: float
    key_version: int
    name: str | None = None
