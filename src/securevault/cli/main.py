"""Command-line interface.  Run `securevault --help` (after `pip install -e .`)
or `python -m securevault --help`.

The passphrase is read from a hidden prompt. For scripting you may set the
SECUREVAULT_PASSPHRASE environment variable instead (less safe: other processes
and shell history on some systems can expose environment variables).
"""

import os
from datetime import UTC, datetime
from pathlib import Path

import typer

from securevault.config import get_settings
from securevault.storage import make_backend
from securevault.storage.vault import Vault
from securevault.utils.exceptions import SecureVaultError

app = typer.Typer(help="Secure Vault: post-quantum encrypted file locker.", no_args_is_help=True)


def _vault() -> Vault:
    return Vault(make_backend(), actor="cli")


def _passphrase(prompt: str = "Passphrase", confirm: bool = False) -> str:
    env = os.environ.get("SECUREVAULT_PASSPHRASE")
    if env and not confirm:
        return env
    return typer.prompt(prompt, hide_input=True, confirmation_prompt=confirm)


def _fail(error: Exception) -> None:
    typer.secho(f"Error: {error}", fg=typer.colors.RED, err=True)
    raise typer.Exit(1)


def _unlocked() -> Vault:
    vault = _vault()
    vault.unlock(_passphrase())
    return vault


def _when(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


@app.command()
def init() -> None:
    """Create a new vault (asks for a new passphrase twice)."""
    try:
        passphrase = _passphrase("New passphrase", confirm=True)
        vault = Vault.initialize(make_backend(), passphrase, actor="cli")
    except SecureVaultError as e:
        _fail(e)
    typer.echo("Vault created. Keys: Argon2id -> ML-KEM-768 -> AES-256-GCM.")
    typer.echo(f"Audit anchor (save this somewhere safe): {vault.verify_audit().head_hash}")


@app.command()
def upload(path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True)) -> None:
    """Encrypt and store a file. No passphrase needed (uses the public key)."""
    try:
        info = _vault().upload(path.name, path.read_bytes())
    except SecureVaultError as e:
        _fail(e)
    typer.echo(f"Stored {path.name} ({info.size} bytes) as {info.file_id}")


@app.command()
def download(
    file_id: str,
    out_dir: Path = typer.Option(Path("."), "--out", "-o", file_okay=False, help="Folder to write into"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file"),
) -> None:
    """Decrypt a file and write it to disk."""
    try:
        name, data = _unlocked().download(file_id)
    except SecureVaultError as e:
        _fail(e)
    target = out_dir / Path(name).name  # strip any directory parts from the stored name
    if target.exists() and not force:
        _fail(FileExistsError(f"{target} already exists (use --force)"))
    out_dir.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    typer.echo(f"Wrote {target} ({len(data)} bytes)")


@app.command("list")
def list_files(show_names: bool = typer.Option(True, help="Ask for the passphrase to show file names")) -> None:
    """List stored files. Names are encrypted, so they need the passphrase."""
    try:
        vault = _unlocked() if show_names else _vault()
        files = vault.list_files()
    except SecureVaultError as e:
        _fail(e)
    if not files:
        typer.echo("The vault is empty.")
    for f in files:
        typer.echo(f"{f.file_id}  {f.size:>10} B  {_when(f.created_ts)}  key v{f.key_version}  {f.name or '(locked)'}")


@app.command()
def delete(file_id: str) -> None:
    """Permanently delete a file."""
    try:
        _unlocked().delete(file_id)
    except SecureVaultError as e:
        _fail(e)
    typer.echo("Deleted.")


@app.command("rotate-passphrase")
def rotate_passphrase() -> None:
    """Change the passphrase. Re-encrypts one key; no file is touched."""
    try:
        vault = _unlocked()
        vault.rotate_passphrase(_passphrase("New passphrase", confirm=True))
    except SecureVaultError as e:
        _fail(e)
    typer.echo("Passphrase changed.")


@app.command("rotate-keys")
def rotate_keys() -> None:
    """Generate a new ML-KEM key pair and re-wrap every file key. File data is not re-encrypted."""
    try:
        count = _unlocked().rotate_keys()
    except SecureVaultError as e:
        _fail(e)
    typer.echo(f"Rotated. {count} file key(s) re-wrapped.")


@app.command()
def audit(limit: int = typer.Option(20, help="Show the last N entries")) -> None:
    """Show recent audit entries and whether the chain is intact."""
    try:
        vault = _vault()
        entries, result = vault.audit_entries(), vault.verify_audit()
    except SecureVaultError as e:
        _fail(e)
    for e in entries[-limit:]:
        typer.echo(f"#{e['index']:<4} {_when(e['ts'])}  {e['event']:<18} {e['hash'][:12]}")
    status = "INTACT" if result.ok else f"BROKEN at entry {result.first_bad_index}: {result.reason}"
    typer.secho(f"Chain: {status}  ({result.length} entries, head {result.head_hash[:16]}...)",
                fg=typer.colors.GREEN if result.ok else typer.colors.RED)


@app.command()
def verify(anchor: str = typer.Option(None, help="Head hash you saved earlier; also catches truncation")) -> None:
    """Verify the audit chain. Exit code 1 if it was tampered with."""
    result = _vault().verify_audit(anchor)
    if result.ok:
        typer.secho(f"Audit chain intact ({result.length} entries).", fg=typer.colors.GREEN)
    else:
        typer.secho(f"TAMPERED: {result.reason} (entry {result.first_bad_index})", fg=typer.colors.RED)
        raise typer.Exit(1)


@app.command()
def scan() -> None:
    """Run the anomaly detector (rules + Isolation Forest) over the audit log."""
    try:
        result = _vault().scan()
    except SecureVaultError as e:
        _fail(e)
    model = "rules + Isolation Forest" if result.model_loaded else "rules only (no trained model found)"
    typer.echo(f"Scanned {result.windows_scanned} activity window(s) with {model}.")
    for a in result.alerts:
        typer.secho(f"[{a.severity.upper()}] {_when(a.window_start)}  {a.rule}: {a.message}", fg=typer.colors.YELLOW)
    if not result.alerts:
        typer.echo("No anomalies found.")


mfa_app = typer.Typer(help="Authenticator-app (TOTP) protection.", no_args_is_help=True)
app.add_typer(mfa_app, name="mfa")


@mfa_app.command("status")
def mfa_status() -> None:
    """Show whether MFA is enabled (asks for the passphrase)."""
    try:
        vault = _unlocked()
        enabled = vault.mfa_required
    except SecureVaultError as e:
        _fail(e)
    typer.echo(f"MFA: {'enabled' if enabled else 'disabled'}")


@mfa_app.command("disable")
def mfa_disable() -> None:
    """Switch MFA off using only the passphrase. This is the lost-authenticator recovery path."""
    try:
        vault = _unlocked()
        if not vault.mfa_required:
            typer.echo("MFA is already disabled.")
            return
        vault.mfa_reset_local()
    except SecureVaultError as e:
        _fail(e)
    typer.echo("MFA disabled (recorded in the audit log as local recovery).")


@app.command()
def status() -> None:
    """Show vault configuration and health."""
    settings = get_settings()
    vault = _vault()
    typer.echo(f"Storage backend : {settings.storage_backend}")
    if not vault.initialized:
        typer.echo("Vault           : not initialised (run `init`)")
        return
    ks = vault.backend.load_keystore()
    typer.echo(f"Key encapsulation: {ks['kem']['algorithm']} (active key v{ks['active_version']})")
    typer.echo(f"Passphrase KDF   : {ks['kdf']['algorithm']}")
    typer.echo(f"Files            : {len(vault.backend.list_meta())}")
    result = vault.verify_audit()
    typer.echo(f"Audit chain      : {'intact' if result.ok else 'BROKEN'} ({result.length} entries)")


if __name__ == "__main__":
    app()
