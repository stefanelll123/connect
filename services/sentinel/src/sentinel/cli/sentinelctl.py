"""sentinelctl CLI — init, rotate-key, backup, restore (TASK-039)."""
from __future__ import annotations

import base64
import json
import os
import sys
import tarfile
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional

try:
    import typer
except ImportError:  # pragma: no cover
    raise SystemExit("Install typer: pip install typer")

from sentinel.wallet.key_manager import (
    Wallet,
    derive_did_key,
    generate_ed25519_keypair,
    load_manifest,
)
from sentinel.wallet.rotation import RotationManager

app = typer.Typer(name="sentinelctl", help="Sentinel key management CLI")

_DEFAULT_STORE = Path(os.environ.get("SENTINEL_HOME", str(Path.home() / ".sentinel"))) / "store"
_AUDIT_LOG = Path(os.environ.get("SENTINEL_HOME", str(Path.home() / ".sentinel"))) / "key_operations.log"


def _passphrase_from_env(env_var: str = "SENTINEL_PASSPHRASE") -> bytes:
    value = os.environ.get(env_var, "")
    if not value:
        typer.echo(f"Error: env var {env_var!r} is not set or empty", err=True)
        raise typer.Exit(code=1)
    return value.encode()


def _write_audit_log(operation: str, key_version: int, did: str, outcome: str, error: str = "") -> None:
    entry = {
        "ts": time.time(),
        "operation": operation,
        "key_version": key_version,
        "did_truncated": did[:20] + "..." if len(did) > 20 else did,
        "outcome": outcome,
    }
    if error:
        entry["error"] = error
    try:
        _AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with _AUDIT_LOG.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# sentinelctl init
# ---------------------------------------------------------------------------

@app.command("init")
def cmd_init(
    service_id: str = typer.Option(..., "--service-id", help="Service identifier"),
    role: str = typer.Option("producer", "--role", help="producer or consumer"),
    env: str = typer.Option("prod", "--env", help="dev / staging / prod"),
    output: Path = typer.Option(_DEFAULT_STORE, "--output", help="Store directory"),
    passphrase_env: str = typer.Option("SENTINEL_PASSPHRASE", "--passphrase-env"),
) -> None:
    """Generate a new Ed25519 keypair and derive a did:key DID."""
    passphrase = _passphrase_from_env(passphrase_env)
    wallet = Wallet(output)
    try:
        manifest = wallet.init(service_id=service_id, role=role, env=env, passphrase=passphrase)
        typer.echo(f"DID: {manifest.did}")
        typer.echo(f"Sentinel ID: {manifest.sentinel_id}")
        typer.echo(f"Key version: {manifest.key_version}")
        _write_audit_log("init", manifest.key_version, manifest.did, "success")
    except FileExistsError as exc:
        typer.echo(f"Error: {exc}", err=True)
        _write_audit_log("init", 0, "", "failure", str(exc))
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# sentinelctl rotate-key
# ---------------------------------------------------------------------------

@app.command("rotate-key")
def cmd_rotate_key(
    store: Path = typer.Option(_DEFAULT_STORE, "--store"),
    grace_period_seconds: int = typer.Option(300, "--grace-period-seconds"),
    passphrase_env: str = typer.Option("SENTINEL_PASSPHRASE", "--passphrase-env"),
) -> None:
    """Rotate the sentinel key (generates new DID, keeps grace window)."""
    passphrase = _passphrase_from_env(passphrase_env)
    wallet = Wallet(store)
    try:
        wallet.load(passphrase)
    except Exception as exc:
        typer.echo(f"Error loading wallet: {exc}", err=True)
        raise typer.Exit(code=1)

    mgr = RotationManager(wallet)
    try:
        old_did, new_did = mgr.rotate(passphrase, grace_period_seconds)
        typer.echo(f"Old DID: {old_did}")
        typer.echo(f"New DID: {new_did}")
        typer.echo(f"Grace window: {grace_period_seconds}s")
        _write_audit_log("rotate-key", wallet.manifest.key_version, new_did, "success")
    except Exception as exc:
        _write_audit_log("rotate-key", 0, "", "failure", str(exc))
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# sentinelctl backup / restore
# ---------------------------------------------------------------------------

def _derive_backup_key(passphrase: bytes, salt: bytes, n: int = 2**18) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    kdf = Scrypt(salt=salt, length=32, n=n, r=8, p=1)
    return kdf.derive(passphrase)


def _encrypt_backup(plaintext: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _decrypt_backup(ciphertext: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = ciphertext[:12]
    return AESGCM(key).decrypt(nonce, ciphertext[12:], None)


@app.command("backup")
def cmd_backup(
    store: Path = typer.Option(_DEFAULT_STORE, "--store"),
    output: Path = typer.Option(Path("wallet_backup.enc"), "--output"),
    passphrase_env: str = typer.Option("BACKUP_PASSPHRASE", "--passphrase-env"),
    scrypt_n: int = typer.Option(2**18, "--scrypt-n"),
) -> None:
    """Encrypt the wallet store to a portable backup file."""
    passphrase = _passphrase_from_env(passphrase_env)
    if not store.exists():
        typer.echo(f"Error: store directory {store} not found", err=True)
        raise typer.Exit(code=1)

    try:
        manifest = load_manifest(store)
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    # Create tarball in memory
    with tempfile.TemporaryFile() as tmp:
        with tarfile.open(fileobj=tmp, mode="w:gz") as tar:
            tar.add(store, arcname="store")
        tmp.seek(0)
        tarball = tmp.read()

    salt = os.urandom(16)
    key = _derive_backup_key(passphrase, salt, n=scrypt_n)
    encrypted = _encrypt_backup(tarball, key)

    header = json.dumps({
        "version": 1,
        "salt": base64.b64encode(salt).decode(),
        "key_version": manifest.key_version,
        "did": manifest.did,
        "generated_at": time.time(),
        "scrypt_n": scrypt_n,
    }).encode()
    header_len = len(header).to_bytes(4, "big")

    output.write_bytes(header_len + header + encrypted)
    typer.echo(f"Backup written to {output} ({output.stat().st_size} bytes)")
    _write_audit_log("backup", manifest.key_version, manifest.did, "success")


@app.command("restore")
def cmd_restore(
    input: Path = typer.Option(Path("wallet_backup.enc"), "--input"),
    store: Path = typer.Option(_DEFAULT_STORE, "--store"),
    passphrase_env: str = typer.Option("BACKUP_PASSPHRASE", "--passphrase-env"),
) -> None:
    """Decrypt a backup and restore the wallet store."""
    passphrase = _passphrase_from_env(passphrase_env)
    if not input.exists():
        typer.echo(f"Error: backup file {input} not found", err=True)
        raise typer.Exit(code=1)

    raw = input.read_bytes()
    header_len = int.from_bytes(raw[:4], "big")
    header = json.loads(raw[4:4 + header_len])
    encrypted = raw[4 + header_len:]

    salt = base64.b64decode(header["salt"])
    scrypt_n = header.get("scrypt_n", 2**18)
    key = _derive_backup_key(passphrase, salt, n=scrypt_n)

    try:
        tarball = _decrypt_backup(encrypted, key)
    except Exception as exc:
        typer.echo(f"Error: decryption failed — wrong passphrase? ({exc})", err=True)
        raise typer.Exit(code=1)

    store.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile() as tmp:
        tmp.write(tarball)
        tmp.seek(0)
        with tarfile.open(fileobj=tmp, mode="r:gz") as tar:
            tar.extractall(store.parent)  # extracts "store/" inside parent

    typer.echo(f"Restored to {store}")
    # Validate post-restore
    try:
        manifest = load_manifest(store)
        typer.echo(f"Validated: DID={manifest.did[:20]}... key_version={manifest.key_version}")
        _write_audit_log("restore", manifest.key_version, manifest.did, "success")
    except Exception as exc:
        _write_audit_log("restore", 0, "", "failure", str(exc))
        typer.echo(f"Warning: post-restore validation failed: {exc}", err=True)


def main() -> None:  # pragma: no cover
    app()


# ---------------------------------------------------------------------------
# sentinelctl status
# ---------------------------------------------------------------------------

@app.command("status")
def cmd_status(
    store: Path = typer.Option(_DEFAULT_STORE, "--store"),
    discovery_url: str = typer.Option(
        os.environ.get("DISCOVERY_URL", "http://localhost:8000"),
        "--discovery-url",
    ),
    chain_rpc_url: str = typer.Option(
        os.environ.get("CHAIN_RPC_URL", "http://localhost:8545"),
        "--chain-rpc-url",
    ),
    sentinel_home: str = typer.Option(
        os.environ.get("SENTINEL_HOME", str(Path.home() / ".sentinel")),
        "--sentinel-home",
    ),
) -> None:
    """Display sentinel operational status and connectivity checks."""
    import httpx

    all_ok = True

    # --- Instance ID ---
    try:
        from sentinel.core.instance import get_or_create_instance_id
        instance_id = get_or_create_instance_id(sentinel_home)
    except Exception as exc:
        instance_id = f"<error: {exc}>"
        all_ok = False

    # --- DID / key mode ---
    did = "<not loaded>"
    key_mode = "local"
    key_version = 0
    try:
        manifest = load_manifest(store)
        did = manifest.did
        key_version = manifest.key_version
        key_mode = os.environ.get("SECRET_STORAGE_BACKEND", "local")
    except Exception:
        all_ok = False

    # --- Credential count ---
    cred_count = 0
    try:
        cred_dir = store / "credentials"
        if cred_dir.is_dir():
            cred_count = sum(1 for f in cred_dir.iterdir() if f.suffix == ".enc")
    except Exception:
        pass

    # --- Discovery ping ---
    discovery_ok = False
    try:
        resp = httpx.get(f"{discovery_url}/health", timeout=5.0)
        discovery_ok = resp.status_code < 500
    except Exception:
        pass
    if not discovery_ok:
        all_ok = False

    # --- Chain RPC ping ---
    chain_ok = False
    try:
        resp = httpx.post(
            chain_rpc_url,
            json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
            timeout=5.0,
        )
        chain_ok = resp.status_code == 200 and "result" in resp.json()
    except Exception:
        pass

    # --- Output ---
    typer.echo("┌─ Sentinel Status ─────────────────────────────────────┐")
    typer.echo(f"  instance_id    : {instance_id}")
    typer.echo(f"  DID            : {did[:40]}{'...' if len(did) > 40 else ''}")
    typer.echo(f"  key_mode       : {key_mode}")
    typer.echo(f"  key_version    : {key_version}")
    typer.echo(f"  credentials    : {cred_count} cached")
    typer.echo(f"  discovery      : {'✓ online' if discovery_ok else '✗ unreachable'}")
    typer.echo(f"  chain_rpc      : {'✓ online' if chain_ok else '✗ unreachable (non-critical)'}")
    typer.echo(f"  sentinel_operational: {'true' if all_ok else 'false'}")
    typer.echo("└───────────────────────────────────────────────────────┘")

    raise typer.Exit(code=0 if all_ok else 1)


# ---------------------------------------------------------------------------
# sentinelctl rejoin
# ---------------------------------------------------------------------------

@app.command("rejoin")
def cmd_rejoin(
    store: Path = typer.Option(_DEFAULT_STORE, "--store"),
    discovery_url: str = typer.Option(
        os.environ.get("DISCOVERY_URL", "http://localhost:8000"),
        "--discovery-url",
        help="Base URL of the Discovery Service",
    ),
    service_id: str = typer.Option(
        os.environ.get("SENTINEL_SERVICE_ID", ""),
        "--service-id",
    ),
    passphrase_env: str = typer.Option("SENTINEL_PASSPHRASE", "--passphrase-env"),
    endpoint_url: str = typer.Option(
        os.environ.get("SENTINEL_ENDPOINT_URL", ""),
        "--endpoint-url",
        help="Public URL of this sentinel instance",
    ),
) -> None:
    """Re-register this sentinel with Discovery after host migration.

    Steps:
      1. Load DID key from local store (or Vault via DIDKeyManager).
      2. Request onboarding challenge from Discovery.
      3. Sign the challenge nonce → proof-of-possession.
      4. Submit signed response to complete re-registration.
      5. Exit 0 on success (409 = already registered = also success).
    """
    import httpx

    passphrase = _passphrase_from_env(passphrase_env)

    # --- Load wallet / DID key ---
    wallet = Wallet(store)
    try:
        wallet.load(passphrase)
    except Exception as exc:
        typer.echo(f"Error: failed to load wallet — {exc}", err=True)
        raise typer.Exit(code=1)

    sentinel_did = wallet.manifest.did
    if not service_id:
        typer.echo("Error: --service-id or SENTINEL_SERVICE_ID is required", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Rejoining as DID={sentinel_did[:30]}...")

    with httpx.Client(timeout=10.0) as client:
        # Step 1: request challenge
        try:
            challenge_resp = client.post(
                f"{discovery_url}/api/v1/sentinels/onboard/challenge",
                json={"sentinel_did": sentinel_did, "service_id": service_id},
            )
        except Exception as exc:
            typer.echo(f"Error: cannot reach Discovery — {exc}", err=True)
            raise typer.Exit(code=1)

        if challenge_resp.status_code != 200:
            typer.echo(
                f"Error: challenge request failed (HTTP {challenge_resp.status_code}):\n"
                f"{challenge_resp.text[:400]}",
                err=True,
            )
            raise typer.Exit(code=1)

        challenge_data = challenge_resp.json()
        nonce = challenge_data.get("nonce") or challenge_data.get("challenge_nonce", "")
        enrollment_token = challenge_data.get("enrollment_token", "")

        if not nonce:
            typer.echo("Error: Discovery did not return a nonce", err=True)
            raise typer.Exit(code=1)

        # Step 2: sign the nonce with DID key via wallet.sign_pop
        try:
            jti = str(uuid.uuid4())
            signature_b64url = wallet.sign_pop(challenge_nonce=nonce, token_jti=jti)
        except Exception as exc:
            typer.echo(f"Error: signing failed — {exc}", err=True)
            raise typer.Exit(code=1)

        # Step 3: submit signed proof
        try:
            complete_resp = client.post(
                f"{discovery_url}/api/v1/sentinels/onboard/complete",
                json={
                    "sentinel_did": sentinel_did,
                    "service_id": service_id,
                    "nonce": nonce,
                    "enrollment_token": enrollment_token,
                    "proof": signature_b64url,
                    "endpoint_url": endpoint_url,
                },
            )
        except Exception as exc:
            typer.echo(f"Error: cannot reach Discovery (complete) — {exc}", err=True)
            raise typer.Exit(code=1)

        if complete_resp.status_code in (200, 201, 409):
            if complete_resp.status_code == 409:
                typer.echo("Sentinel already registered (idempotent). ✓")
            else:
                typer.echo(f"Rejoin successful (HTTP {complete_resp.status_code}). ✓")
            _write_audit_log("rejoin", wallet.manifest.key_version, sentinel_did, "success")
            raise typer.Exit(code=0)
        else:
            typer.echo(
                f"Error: rejoin failed (HTTP {complete_resp.status_code}):\n"
                f"{complete_resp.text[:400]}",
                err=True,
            )
            _write_audit_log("rejoin", wallet.manifest.key_version, sentinel_did, "failure")
            raise typer.Exit(code=1)


if __name__ == "__main__":  # pragma: no cover
    main()
