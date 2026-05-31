"""In-memory LRU cache with TTL for TrustLayerClient (TASK-042)."""
from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import Optional, TypeVar

T = TypeVar("T")

_MAX_ENTRIES = 1000


class MemoryCache:
    """Thread-safe LRU in-memory cache with per-entry TTL.

    Each cache namespace is a separate dict, all guarded by a per-namespace lock.
    """

    def __init__(self, max_entries: int = _MAX_ENTRIES) -> None:
        self._max = max_entries
        # namespace → OrderedDict[key → (value, cached_at)]
        self._stores: dict[str, OrderedDict] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _ensure_ns(self, ns: str) -> tuple[OrderedDict, asyncio.Lock]:
        if ns not in self._stores:
            self._stores[ns] = OrderedDict()
            self._locks[ns] = asyncio.Lock()
        return self._stores[ns], self._locks[ns]

    async def get(self, ns: str, key: str, ttl: float) -> Optional[object]:
        store, lock = self._ensure_ns(ns)
        async with lock:
            entry = store.get(key)
            if entry is None:
                return None
            value, cached_at = entry
            if time.time() - cached_at > ttl:
                # Do not delete — peek() may still serve it as stale fallback.
                # Eviction happens at LRU capacity boundary.
                return None
            # LRU: move to end
            store.move_to_end(key)
            return value

    async def put(self, ns: str, key: str, value: object) -> None:
        store, lock = self._ensure_ns(ns)
        async with lock:
            if key in store:
                store.move_to_end(key)
            elif len(store) >= self._max:
                store.popitem(last=False)  # evict LRU
            store[key] = (value, time.time())

    async def invalidate(self, ns: str, key: str) -> None:
        store, lock = self._ensure_ns(ns)
        async with lock:
            store.pop(key, None)

    async def peek(self, ns: str, key: str) -> Optional[object]:
        """Return stored value regardless of TTL (stale-safe read).  None if absent."""
        store, lock = self._ensure_ns(ns)
        async with lock:
            entry = store.get(key)
            if entry is None:
                return None
            value, _ = entry
            return value

    async def get_all(self, ns: str, ttl: float) -> list:
        """Return all non-expired entries in namespace *ns*."""
        store, lock = self._ensure_ns(ns)
        now = time.time()
        async with lock:
            results = []
            expired_keys = []
            for key, (value, cached_at) in store.items():
                if now - cached_at > ttl:
                    expired_keys.append(key)
                else:
                    results.append(value)
            for k in expired_keys:
                del store[k]
            return results

    def to_dict(self) -> dict:
        """Dump all namespaces to a plain dict for persistence."""
        return {
            ns: {k: (v, ts) for k, (v, ts) in items.items()}
            for ns, items in self._stores.items()
        }

    def load_dict(self, data: dict) -> None:
        """Restore from a previously dumped dict."""
        for ns, items in data.items():
            store, _ = self._ensure_ns(ns)
            for k, (v, ts) in items.items():
                store[k] = (v, ts)
