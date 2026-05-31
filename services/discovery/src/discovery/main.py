"""Discovery Service entry point.

Uvicorn access logs are disabled — replaced by RequestLoggingMiddleware
which emits structured log lines with the request ID attached.
"""
import logging

import uvicorn

from discovery.app import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
)

app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "discovery.main:app",
        host="0.0.0.0",
        port=8000,
        log_config=None,   # structured logging via RequestLoggingMiddleware
        access_log=False,
    )
