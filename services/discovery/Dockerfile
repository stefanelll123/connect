# Discovery Service — Multi-stage Dockerfile
# Final image ~200MB with only runtime dependencies.
#
# See TASK-061 for full production Dockerfile implementation.
# This is a working development image.

# ---- Stage 1: Build wheels ----
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY libs/common/pyproject.toml libs/common/
COPY libs/common/src/ libs/common/src/
COPY services/discovery/pyproject.toml services/discovery/
COPY services/discovery/src/ services/discovery/src/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir /build/libs/common \
    && pip install --no-cache-dir /build/services/discovery

# ---- Stage 2: Runtime ----
FROM python:3.12-slim AS runtime

RUN useradd -u 1001 -m -s /sbin/nologin appuser

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=builder /usr/local/bin/alembic /usr/local/bin/alembic

COPY services/discovery/src/ /app/src/
COPY services/discovery/alembic/ /app/alembic/
COPY services/discovery/alembic.ini /app/alembic.ini
COPY services/discovery/entrypoint.sh /app/entrypoint.sh

RUN mkdir -p /tmp/discovery && chown appuser:appuser /tmp/discovery \
    && chmod +x /app/entrypoint.sh

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/live')" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
