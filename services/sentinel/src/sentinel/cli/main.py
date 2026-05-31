"""Entry-point shim so the pyproject.toml script `sentinelctl = 'sentinel.cli.main:cli'` resolves."""
from sentinel.cli.sentinelctl import app as cli

__all__ = ["cli"]
