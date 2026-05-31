"""Uvicorn entry point for the Sentinel Node (TASK-037)."""
from __future__ import annotations

import os
import sys

import uvicorn


def main() -> None:
    role = os.environ.get("SENTINEL_ROLE")
    if not role:
        print("ERROR: SENTINEL_ROLE environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    if role not in ("producer", "consumer"):
        print(
            f"ERROR: SENTINEL_ROLE must be 'producer' or 'consumer', got '{role}'",
            file=sys.stderr,
        )
        sys.exit(1)

    uvicorn.run(
        "sentinel.app:create_app",
        factory=True,
        host=os.environ.get("HOST", "0.0.0.0"),  # noqa: S104 — intentional
        port=int(os.environ.get("PORT", "8080")),
        workers=int(os.environ.get("WORKERS", "1")),
        log_level=os.environ.get("LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()
