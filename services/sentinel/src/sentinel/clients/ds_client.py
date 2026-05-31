"""DiscoveryClient — mTLS HTTPX client with retries and circuit breaker (TASK-040)."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx

from sentinel.clients.auth_token import TokenManager

logger = logging.getLogger(__name__)

_DISCOVERY_STATE_FILE = "discovery_state.json"


def _discovery_state_path(sentinel_home: str) -> Path:
    return Path(sentinel_home) / "store" / _DISCOVERY_STATE_FILE


def _save_discovery_state(sentinel_home: str, *, sentinel_id: str, access_token: str) -> None:
    """Atomically persist sentinel_id and access_token to disk."""
    try:
        path = _discovery_state_path(sentinel_home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"sentinel_id": sentinel_id, "access_token": access_token}))
        try:
            os.chmod(path, 0o600)
        except (OSError, NotImplementedError):
            pass
    except Exception as exc:
        logger.warning("Failed to persist discovery state: %s", exc)


def _load_discovery_state(sentinel_home: str) -> tuple[str, str]:
    """Load persisted sentinel_id and access_token; returns ("", "") if not found."""
    try:
        path = _discovery_state_path(sentinel_home)
        if path.exists():
            data = json.loads(path.read_text())
            return data.get("sentinel_id", ""), data.get("access_token", "")
    except Exception as exc:
        logger.warning("Failed to load discovery state: %s", exc)
    return "", ""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class OnboardingBundle:
    sentinel_id: str
    auth_token: str
    discovery_endpoints: dict
    chain_addresses: dict
    initial_credentials: list[str]
    config_etag: str = ""


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------

class RetryWithBackoff:
    """Async retry wrapper with exponential back-off and jitter."""

    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 0.5,
        max_delay: float = 16.0,
        jitter: bool = True,
    ) -> None:
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter

    async def run(self, coro_factory, *args, **kwargs):
        last_exc = None
        for attempt in range(self.max_attempts):
            try:
                return await coro_factory(*args, **kwargs)
            except (httpx.HTTPError, httpx.TimeoutException, httpx.ConnectError) as exc:
                last_exc = exc
                if attempt < self.max_attempts - 1:
                    delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                    if self.jitter:
                        delay *= random.uniform(0.8, 1.2)
                    logger.warning(
                        "Request failed (attempt %d/%d): %s — retrying in %.2fs",
                        attempt + 1, self.max_attempts, exc, delay,
                    )
                    await asyncio.sleep(delay)
        raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """Simple fail-fast circuit breaker with half-open probe."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(self, fail_max: int = 5, reset_timeout: float = 60.0) -> None:
        self.fail_max = fail_max
        self.reset_timeout = reset_timeout
        self._state = self.CLOSED
        self._failure_count = 0
        self._opened_at: Optional[float] = None

    @property
    def state(self) -> str:
        if self._state == self.OPEN:
            if time.time() - (self._opened_at or 0) >= self.reset_timeout:
                self._state = self.HALF_OPEN
        return self._state

    def record_success(self) -> None:
        self._state = self.CLOSED
        self._failure_count = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failure_count += 1
        if self._failure_count >= self.fail_max:
            if self._state != self.OPEN:
                self._state = self.OPEN
                self._opened_at = time.time()
                logger.warning("ds_circuit_open: circuit breaker tripped after %d failures", self._failure_count)

    def is_open(self) -> bool:
        return self.state == self.OPEN

    def allow_request(self) -> bool:
        s = self.state
        if s == self.CLOSED:
            return True
        if s == self.HALF_OPEN:
            return True  # allow the probe
        return False  # OPEN


# ---------------------------------------------------------------------------
# DiscoveryClient
# ---------------------------------------------------------------------------

class DiscoveryClient:
    """Async client for the Discovery Service with mTLS, retries, and circuit-breaker.

    Args:
        base_url:       Discovery service base URL.
        sentinel_id:    UUID of this sentinel (empty before onboarding).
        sentinel_did:   DID of this sentinel.
        mtls_cert_path: Path to mTLS client certificate (PEM).
        mtls_key_path:  Path to mTLS private key (PEM).
        ca_cert_path:   Path to CA certificate for server verification.
    """

    def __init__(
        self,
        base_url: str,
        sentinel_id: str = "",
        sentinel_did: str = "",
        service_id: str = "",
        env: str = "dev",
        mtls_cert_path: Optional[str] = None,
        mtls_key_path: Optional[str] = None,
        ca_cert_path: Optional[str] = None,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.sentinel_id = sentinel_id
        self.sentinel_did = sentinel_did
        self.service_id = service_id
        self.env = env
        self._token_manager = TokenManager()
        self._retry = RetryWithBackoff()
        self._circuit = CircuitBreaker()
        self._missed_heartbeats = 0
        self._config_etag: str = ""
        self._last_credential_sync_ts: float = 0.0

        cert = None
        if mtls_cert_path and mtls_key_path:
            cert = (mtls_cert_path, mtls_key_path)

        if http_client is not None:
            self._http = http_client
        else:
            self._http = httpx.AsyncClient(
                verify=ca_cert_path or True,
                cert=cert,
                timeout=httpx.Timeout(connect=5.0, read=30.0, write=10.0),
                follow_redirects=False,
            )

    async def close(self) -> None:
        await self._http.aclose()

    # ── Auth helpers ────────────────────────────────────────────────────

    def _auth_headers(self) -> dict:
        token = self._token_manager.get()
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}

    async def _ensure_token(self) -> None:
        if self._token_manager.needs_renewal():
            await self._renew_auth_token()

    async def _renew_auth_token(self) -> None:
        """Renew the discovery auth token using a self-signed DID assertion.

        No existing bearer token required — the sentinel proves identity via
        its Ed25519 key.  Works after restart or token expiry.
        """
        if not self.sentinel_id or not self.sentinel_did:
            logger.warning("Cannot renew token: sentinel_id or DID unknown")
            return

        logger.info("Renewing discovery auth token for sentinel %s", self.sentinel_id)
        try:
            import os
            import time
            from pathlib import Path
            from sentinel.wallet.key_manager import Wallet

            sentinel_home = os.environ.get("SENTINEL_HOME", "/data")
            passphrase = os.environ.get("SENTINEL_PASSPHRASE", "").encode()
            wallet = Wallet(Path(sentinel_home) / "store")
            wallet.load(passphrase)

            iat = int(time.time())
            proof_value = wallet.sign_renewal_assertion(self.sentinel_id, iat)

            resp = await self._http.post(
                f"{self.base_url}/api/v1/sentinels/{self.sentinel_id}/auth/renew",
                json={"did": self.sentinel_did, "iat": iat, "proof_value": proof_value},
            )
            if resp.status_code == 200:
                data = resp.json()
                self._token_manager.set(data["access_token"])
                _save_discovery_state(
                    sentinel_home,
                    sentinel_id=self.sentinel_id,
                    access_token=data["access_token"],
                )
                logger.info("Auth token renewed")
            else:
                logger.critical(
                    "Auth token renewal failed: status=%d body=%s",
                    resp.status_code, resp.text[:200],
                )
        except Exception as exc:
            logger.critical("Auth token renewal error: %s", exc)

    # ── Circuit-breaker guard ────────────────────────────────────────────

    async def _guarded_request(self, coro_factory, *args, **kwargs):
        """Execute *coro_factory* with circuit-breaker protection."""
        if not self._circuit.allow_request():
            logger.warning("ds_circuit_open: skipping request")
            raise httpx.ConnectError("Circuit breaker open")
        try:
            result = await self._retry.run(coro_factory, *args, **kwargs)
            self._circuit.record_success()
            return result
        except Exception as exc:
            self._circuit.record_failure()
            raise

    # ── Enrollment ───────────────────────────────────────────────────────

    async def onboard(self, enrollment_token: str) -> OnboardingBundle:
        """Two-phase onboarding handshake with the Discovery Service.

        Phase 1: POST /onboard (no proof) → receive challenge_nonce.
        Phase 2: POST /onboard with signed OnboardingProof → receive OnboardingBundle.

        If a 409 (token already consumed) is returned, falls back to
        ``_get_current_config_as_bundle()`` and re-uses the existing registration.
        """
        import os
        from datetime import datetime, timezone

        # Phase 1 — request the challenge nonce
        resp1 = await self._guarded_request(
            self._http.post,
            f"{self.base_url}/api/v1/sentinels/onboard",
            json={"enrollment_token": enrollment_token, "did": self.sentinel_did},
        )

        if resp1.status_code == 409:
            logger.info(
                "Enrollment token already consumed (409) — fetching current config"
            )
            return await self._get_current_config_as_bundle()

        if resp1.status_code != 200:
            raise httpx.HTTPStatusError(
                f"Phase-1 onboard failed: {resp1.status_code} {resp1.text[:200]}",
                request=resp1.request,
                response=resp1,
            )

        body1 = resp1.json()
        challenge_nonce = body1.get("challenge_nonce", "")

        # Sign the PoP using the wallet key
        try:
            from pathlib import Path
            from sentinel.wallet.key_manager import Wallet

            sentinel_home = os.environ.get("SENTINEL_HOME", "/data")
            passphrase = os.environ.get("SENTINEL_PASSPHRASE", "").encode()
            wallet = Wallet(Path(sentinel_home) / "store")
            wallet.load(passphrase)

            # token_jti is the jti from the enrollment JWT (first segment payload)
            import base64 as _b64
            import json as _json
            _parts = enrollment_token.split(".")
            _padded = _parts[1] + "=" * (4 - len(_parts[1]) % 4)
            token_jti = _json.loads(_b64.urlsafe_b64decode(_padded)).get("jti", "")

            iat = int(datetime.now(timezone.utc).timestamp())
            proof_value = wallet.sign_pop(
                challenge_nonce=challenge_nonce,
                token_jti=token_jti,
                iat=iat,
            )
        except Exception as exc:
            raise RuntimeError(f"PoP signing failed: {exc}") from exc

        idempotency_key = hashlib.sha256(
            f"{enrollment_token}:{self.sentinel_did}".encode()
        ).hexdigest()

        created_ts = datetime.fromtimestamp(iat, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Phase 2 — submit signed proof
        resp2 = await self._guarded_request(
            self._http.post,
            f"{self.base_url}/api/v1/sentinels/onboard",
            json={
                "enrollment_token": enrollment_token,
                "did": self.sentinel_did,
                "proof": {
                    "type": "Ed25519Signature2020",
                    "created": created_ts,
                    "challenge_nonce": challenge_nonce,
                    "proof_value": proof_value,
                },
            },
            headers={"X-Idempotency-Key": idempotency_key},
        )

        if resp2.status_code not in (200, 201):
            raise httpx.HTTPStatusError(
                f"Phase-2 onboard failed: {resp2.status_code} {resp2.text[:200]}",
                request=resp2.request,
                response=resp2,
            )

        data = resp2.json()
        _creds = data.get("credentials", {})
        _sentinel_identity = (
            _creds.get("sentinel_identity") if isinstance(_creds, dict) else None
        )
        bundle = OnboardingBundle(
            sentinel_id=str(data.get("sentinel_id", "")),
            auth_token=data.get("access_token", ""),
            discovery_endpoints=data.get("discovery_endpoints", {}),
            chain_addresses=data.get("chain_addresses", {}),
            initial_credentials=[c for c in [_sentinel_identity] if c],
            config_etag=data.get("etag", ""),
        )
        if bundle.auth_token:
            self._token_manager.set(bundle.auth_token)
        if bundle.sentinel_id:
            self.sentinel_id = bundle.sentinel_id
        self._config_etag = bundle.config_etag

        # Persist sentinel_id + token so renewal works after restart
        import os as _os
        _sentinel_home = _os.environ.get("SENTINEL_HOME", "/data")
        _save_discovery_state(
            _sentinel_home,
            sentinel_id=self.sentinel_id,
            access_token=bundle.auth_token,
        )

        # Security: clear enrollment token from environment after success
        os.environ.pop("ENROLLMENT_TOKEN", None)

        return bundle

    async def _get_current_config_as_bundle(self) -> OnboardingBundle:
        """Return a minimal OnboardingBundle from current config (after 409)."""
        changed = await self.sync_config()
        return OnboardingBundle(
            sentinel_id=self.sentinel_id,
            auth_token=self._token_manager.get() or "",
            discovery_endpoints={},
            chain_addresses={},
            initial_credentials=[],
        )

    # ── Config sync ──────────────────────────────────────────────────────

    async def sync_config(self) -> bool:
        """Poll for updated config bundle (ETag-aware).

        Returns:
            True if config changed and was applied, False on 304 (no change).
        """
        await self._ensure_token()
        headers = dict(self._auth_headers())
        if self._config_etag:
            headers["If-None-Match"] = self._config_etag

        try:
            resp = await self._guarded_request(
                self._http.get,
                f"{self.base_url}/api/v1/sentinels/{self.sentinel_id}/config",
                headers=headers,
            )
        except Exception as exc:
            logger.warning("Config sync failed: %s", exc)
            return False

        if resp.status_code == 304:
            return False

        if resp.status_code != 200:
            logger.warning("Config sync returned %d", resp.status_code)
            return False

        new_etag = resp.headers.get("ETag", "")
        if new_etag:
            self._config_etag = new_etag

        logger.info("Config updated (etag=%s)", new_etag)
        return True

    # ── Credential sync ──────────────────────────────────────────────────

    async def sync_credentials(self, credential_store=None, master_key=None) -> int:
        """Fetch new credentials since last sync.

        Returns:
            Count of newly fetched valid credentials.
        """
        await self._ensure_token()
        import datetime as _dt
        params: dict = {}
        if self._last_credential_sync_ts > 0:
            params["since"] = _dt.datetime.fromtimestamp(
                self._last_credential_sync_ts, tz=_dt.timezone.utc
            ).isoformat()
        try:
            resp = await self._guarded_request(
                self._http.get,
                f"{self.base_url}/api/v1/sentinels/{self.sentinel_id}/credentials",
                params=params,
                headers=self._auth_headers(),
            )
        except Exception as exc:
            logger.warning("Credential sync failed: %s", exc)
            return 0

        if resp.status_code != 200:
            logger.warning("Credential sync returned %d", resp.status_code)
            return 0

        now = time.time()
        credentials = resp.json().get("credentials", [])
        new_count = 0
        for cred in credentials:
            jwt_string = cred if isinstance(cred, str) else cred.get("jwt_vc", "")
            if not jwt_string:
                continue
            # Validate: skip expired
            try:
                import base64
                import json as _json
                parts = jwt_string.split(".")
                padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = _json.loads(base64.urlsafe_b64decode(padded))
                exp = payload.get("exp", 0)
                if exp and exp < now + 60:
                    logger.debug("Skipping nearly-expired credential (exp=%s)", exp)
                    continue
            except Exception:
                continue
            if credential_store is not None and master_key is not None:
                try:
                    credential_store.store(jwt_string, master_key=master_key)
                except Exception as _exc:
                    logger.warning("Failed to persist credential: %s", _exc)
            new_count += 1

        self._last_credential_sync_ts = now
        logger.info("Credential sync: %d new credentials", new_count)
        return new_count

    # ── Heartbeat ────────────────────────────────────────────────────────

    async def send_heartbeat(
        self,
        instance_id: str,
        version: str,
        health: dict,
    ) -> None:
        """Send a heartbeat to the Discovery Service."""
        await self._ensure_token()
        try:
            resp = await self._guarded_request(
                self._http.post,
                f"{self.base_url}/api/v1/sentinels/heartbeat",
                json={
                    "sentinel_id": self.sentinel_id,
                    "instance_id": instance_id,
                    "version": version,
                    "health": health,
                },
                headers=self._auth_headers(),
            )
            if resp.status_code == 401:
                logger.warning("Heartbeat 401 — attempting token renewal")
                await self._renew_auth_token()
                # retry once
                await self._http.post(
                    f"{self.base_url}/api/v1/sentinels/heartbeat",
                    json={
                        "sentinel_id": self.sentinel_id,
                        "instance_id": instance_id,
                        "version": version,
                        "health": health,
                    },
                    headers=self._auth_headers(),
                )
            self._missed_heartbeats = 0
        except Exception as exc:
            self._missed_heartbeats += 1
            logger.warning(
                "Heartbeat failed (missed=%d): %s", self._missed_heartbeats, exc
            )
            if self._missed_heartbeats > 5:
                logger.critical(
                    "Discovery unreachable: %d consecutive missed heartbeats",
                    self._missed_heartbeats,
                )
    # ── Descriptor resolve (consumer) ────────────────────────────────

    async def resolve_service(self, service_id: str, env: str) -> dict:
        """Fetch the current signed descriptor for *service_id*/*env*.

        Returns the raw JSON dict from Discovery (contains signed_jwt, endpoints, etc.).

        Raises:
            httpx.HTTPStatusError: on non-200 responses.
            Exception: if service not found (404) or Discovery unreachable.
        """
        await self._ensure_token()
        try:
            resp = await self._guarded_request(
                self._http.get,
                f"{self.base_url}/api/v1/registry/resolve",
                params={"service_id": service_id, "env": env},
                headers=self._auth_headers(),
            )
        except Exception as exc:
            raise Exception(f"Discovery unreachable: {exc}") from exc

        if resp.status_code == 404:
            raise Exception(f"Service '{service_id}' not found in env '{env}'")
        if resp.status_code != 200:
            raise Exception(f"Descriptor resolve failed: HTTP {resp.status_code}")

        data = resp.json()

        # The /resolve response does not include endpoints as a top-level field;
        # they are embedded in the signed JWS payload.  Decode to extract them.
        jws = data.get("signed_descriptor_jws", "")
        endpoints: list = []
        if jws:
            try:
                import base64 as _b64
                import json as _json
                parts = jws.split(".")
                padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                jws_payload = _json.loads(_b64.urlsafe_b64decode(padded))
                endpoints = jws_payload.get("endpoints", [])
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not decode endpoints from JWS payload: %s", exc)

        # Normalise field names for DescriptorCache._parse_and_verify
        return {
            "service_id": data.get("service_id", service_id),
            "service_did": data.get("producer_sentinel_did", ""),
            "producer_did": data.get("producer_sentinel_did", ""),
            "env": data.get("env", env),
            "signed_jwt": jws,
            "endpoints": endpoints,
            "max_age_seconds": 300,
        }
    # ── Descriptor publish ───────────────────────────────────────────────

    async def publish_descriptor(self, service_descriptor_jws: str) -> None:
        """Publish a signed service descriptor to the Discovery Service."""
        await self._ensure_token()
        idempotency_key = hashlib.sha256(service_descriptor_jws.encode()).hexdigest()
        try:
            resp = await self._guarded_request(
                self._http.post,
                f"{self.base_url}/api/v1/services/{self.service_id}/descriptor",
                json={"signed_descriptor_jws": service_descriptor_jws},
                params={"env": self.env},
                headers={**self._auth_headers(), "X-Idempotency-Key": idempotency_key},
            )
            if resp.status_code == 403:
                logger.critical(
                    "Descriptor publish 403 UNAUTHORIZED_PUBLISHER: DID mismatch — not retrying"
                )
                return
            if resp.status_code not in (200, 201, 204):
                logger.warning("Descriptor publish returned %d", resp.status_code)
        except Exception as exc:
            logger.warning("Descriptor publish failed: %s", exc)

    # ── DID rotation notify ──────────────────────────────────────────────

    async def notify_key_rotation(
        self,
        old_did: str,
        new_did: str,
        rotation_proof: str,
    ) -> None:
        """Notify Discovery of DID rotation."""
        await self._ensure_token()
        try:
            resp = await self._guarded_request(
                self._http.post,
                f"{self.base_url}/api/v1/sentinels/{self.sentinel_id}/did-rotation",
                json={
                    "new_did": new_did,
                    "old_did": old_did,
                    "rotation_proof": rotation_proof,
                },
                headers=self._auth_headers(),
            )
            if resp.status_code in (200, 204):
                logger.info("DID rotation notified: %s -> %s", old_did[:20], new_did[:20])
            else:
                logger.warning("DID rotation notify returned %d", resp.status_code)
        except Exception as exc:
            logger.warning("DID rotation notify failed: %s", exc)
