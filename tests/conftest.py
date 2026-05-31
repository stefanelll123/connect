"""Root conftest.py — shared pytest fixtures for integration and e2e tests."""
from __future__ import annotations

import pytest


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"
