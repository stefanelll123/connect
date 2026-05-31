"""TASK-039 unit tests: DID and key lifecycle."""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# DID derivation + key generation
# ---------------------------------------------------------------------------

class TestDIDDerivation:
    def test_generate_returns_32_byte_keys(self):
        from sentinel.wallet.key_manager import generate_ed25519_keypair
        priv, pub = generate_ed25519_keypair()
        assert len(priv) == 32
        assert len(pub) == 32

    def test_derive_did_key_format(self):
        from sentinel.wallet.key_manager import derive_did_key, generate_ed25519_keypair
        _, pub = generate_ed25519_keypair()
        did = derive_did_key(pub)
        assert did.startswith("did:key:z")
        assert len(did) > 40

    def test_did_derive_is_deterministic(self):
        from sentinel.wallet.key_manager import derive_did_key, generate_ed25519_keypair
        _, pub = generate_ed25519_keypair()
        did1 = derive_did_key(pub)
        did2 = derive_did_key(pub)
        assert did1 == did2

    def test_different_keys_produce_different_dids(self):
        from sentinel.wallet.key_manager import derive_did_key, generate_ed25519_keypair
        _, pub1 = generate_ed25519_keypair()
        _, pub2 = generate_ed25519_keypair()
        assert derive_did_key(pub1) != derive_did_key(pub2)

    def test_resolve_did_key_round_trip(self):
        from sentinel.wallet.key_manager import (
            derive_did_key, generate_ed25519_keypair, resolve_did_key_public_key
        )
        _, pub = generate_ed25519_keypair()
        did = derive_did_key(pub)
        recovered = resolve_did_key_public_key(did)
        assert recovered == pub

    def test_resolve_invalid_did_raises(self):
        from sentinel.wallet.key_manager import resolve_did_key_public_key
        with pytest.raises(ValueError):
            resolve_did_key_public_key("did:web:example.com")


# ---------------------------------------------------------------------------
# Proof-of-Possession signing / verification
# ---------------------------------------------------------------------------

class TestPoP:
    def test_sign_pop_returns_base64url_string(self):
        from sentinel.wallet.key_manager import (
            derive_did_key, generate_ed25519_keypair, sign_pop
        )
        priv, pub = generate_ed25519_keypair()
        did = derive_did_key(pub)
        sig = sign_pop(priv, did, "nonce123", "jti-abc")
        assert isinstance(sig, str)
        # base64url: no +/= characters, only -_ and alphanumeric
        assert "+" not in sig and "/" not in sig

    def test_sign_pop_verify_round_trip(self):
        from sentinel.wallet.key_manager import (
            derive_did_key, generate_ed25519_keypair, sign_pop, verify_pop
        )
        priv, pub = generate_ed25519_keypair()
        did = derive_did_key(pub)
        sig = sign_pop(priv, did, "nonce-xyz", "jti-42")
        assert verify_pop(did, "nonce-xyz", "jti-42", sig)

    def test_verify_pop_wrong_nonce_fails(self):
        from sentinel.wallet.key_manager import (
            derive_did_key, generate_ed25519_keypair, sign_pop, verify_pop
        )
        priv, pub = generate_ed25519_keypair()
        did = derive_did_key(pub)
        sig = sign_pop(priv, did, "correct-nonce", "jti-42")
        assert not verify_pop(did, "wrong-nonce", "jti-42", sig)

    def test_verify_pop_tampered_signature_fails(self):
        from sentinel.wallet.key_manager import (
            derive_did_key, generate_ed25519_keypair, sign_pop, verify_pop
        )
        priv, pub = generate_ed25519_keypair()
        did = derive_did_key(pub)
        sig = sign_pop(priv, did, "nonce", "jti")
        tampered = sig[:5] + "AAAAA" + sig[10:]
        assert not verify_pop(did, "nonce", "jti", tampered)


# ---------------------------------------------------------------------------
# Wallet init and load
# ---------------------------------------------------------------------------

class TestWalletInit:
    def test_wallet_init_creates_manifest_and_key(self, tmp_path):
        from sentinel.wallet.key_manager import Wallet
        wallet = Wallet(tmp_path)
        manifest = wallet.init("my-svc", "producer", "dev", b"testpassphrase")
        assert manifest.did.startswith("did:key:z")
        assert manifest.key_version == 1
        assert manifest.service_id == "my-svc"
        assert (tmp_path / "did_private_key_v1.enc").exists()
        assert (tmp_path / "sentinel.json").exists()

    def test_wallet_init_idempotent_protection(self, tmp_path):
        from sentinel.wallet.key_manager import Wallet
        wallet = Wallet(tmp_path)
        wallet.init("svc", "producer", "dev", b"pass")
        with pytest.raises(FileExistsError):
            wallet.init("svc", "producer", "dev", b"pass")

    def test_wallet_load_validates_did(self, tmp_path):
        from sentinel.wallet.key_manager import Wallet
        wallet = Wallet(tmp_path)
        manifest = wallet.init("svc", "producer", "dev", b"testpass")
        # Reload in a fresh instance
        wallet2 = Wallet(tmp_path)
        wallet2.load(b"testpass")
        assert wallet2.did == manifest.did

    def test_wallet_load_detects_tampered_manifest(self, tmp_path):
        from sentinel.wallet.key_manager import Wallet
        import json as _json
        wallet = Wallet(tmp_path)
        wallet.init("svc", "producer", "dev", b"pass")
        manifest_path = tmp_path / "sentinel.json"
        data = _json.loads(manifest_path.read_text())
        data["did"] = "did:key:z6MkFAKEDID"
        manifest_path.write_text(_json.dumps(data))
        wallet2 = Wallet(tmp_path)
        with pytest.raises(ValueError, match="DID mismatch"):
            wallet2.load(b"pass")

    def test_wallet_sign_pop_works_after_load(self, tmp_path):
        from sentinel.wallet.key_manager import Wallet, verify_pop
        wallet = Wallet(tmp_path)
        wallet.init("svc", "producer", "dev", b"pass")
        wallet2 = Wallet(tmp_path)
        wallet2.load(b"pass")
        sig = wallet2.sign_pop("challenge-abc", "jti-99")
        assert verify_pop(wallet2.did, "challenge-abc", "jti-99", sig)


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------

class TestKeyRotation:
    def test_rotate_changes_did_and_key_version(self, tmp_path):
        from sentinel.wallet.key_manager import Wallet
        from sentinel.wallet.rotation import RotationManager
        wallet = Wallet(tmp_path)
        wallet.init("svc", "producer", "dev", b"pass")
        wallet.load(b"pass")
        old_did = wallet.did
        mgr = RotationManager(wallet)
        old_returned, new_returned = mgr.rotate(b"pass", grace_period_seconds=300)
        assert old_returned == old_did
        assert new_returned != old_did
        assert wallet.manifest.key_version == 2
        assert wallet.manifest.did == new_returned
        assert wallet.manifest.previous_did == old_did
        assert wallet.manifest.grace_until is not None

    def test_grace_window_accepts_old_did(self, tmp_path):
        from sentinel.wallet.key_manager import Wallet
        from sentinel.wallet.rotation import RotationManager
        wallet = Wallet(tmp_path)
        wallet.init("svc", "producer", "dev", b"pass")
        wallet.load(b"pass")
        old_did = wallet.did
        mgr = RotationManager(wallet)
        _, new_did = mgr.rotate(b"pass", grace_period_seconds=3600)
        assert wallet.accept_did_for_verification(new_did) is True
        assert wallet.accept_did_for_verification(old_did) is True

    def test_expired_grace_window_rejects_old_did(self, tmp_path):
        from sentinel.wallet.key_manager import Wallet
        from sentinel.wallet.rotation import RotationManager
        wallet = Wallet(tmp_path)
        wallet.init("svc", "producer", "dev", b"pass")
        wallet.load(b"pass")
        old_did = wallet.did
        mgr = RotationManager(wallet)
        mgr.rotate(b"pass", grace_period_seconds=300)
        # Simulate expired grace window
        wallet.manifest.grace_until = time.time() - 1
        assert wallet.accept_did_for_verification(old_did) is False

    def test_evict_old_keys_removes_file(self, tmp_path):
        from sentinel.wallet.key_manager import Wallet
        from sentinel.wallet.rotation import RotationManager
        wallet = Wallet(tmp_path)
        wallet.init("svc", "producer", "dev", b"pass")
        wallet.load(b"pass")
        mgr = RotationManager(wallet)
        mgr.rotate(b"pass", grace_period_seconds=0)
        # Grace window immediately expired; old key should be removable
        wallet.manifest.grace_until = time.time() - 1
        removed = mgr.evict_old_keys()
        assert removed == 1
        assert not (tmp_path / "did_private_key_v1.enc").exists()
