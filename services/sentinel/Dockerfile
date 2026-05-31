# Sentinel Node — Multi-stage Dockerfile
# Supports both PRODUCER and CONSUMER modes via SENTINEL_MODE env var.
#
# See TASK-061 for full production Dockerfile implementation.

# ---- Stage 1: Build wheels ----
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY libs/common/pyproject.toml libs/common/
COPY libs/common/src/ libs/common/src/
COPY services/sentinel/pyproject.toml services/sentinel/
COPY services/sentinel/src/ services/sentinel/src/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir /build/libs/common \
    && pip install --no-cache-dir /build/services/sentinel

# ---- Stage 2: Runtime ----
FROM python:3.12-slim AS runtime

RUN useradd -u 1001 -m -s /sbin/nologin appuser

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=builder /usr/local/bin/sentinelctl /usr/local/bin/sentinelctl

COPY services/sentinel/src/ /app/src/
COPY services/sentinel/entrypoint.sh /app/entrypoint.sh

# Sentinel home for key material — volume mounted at /data by docker-compose
RUN mkdir -p /data && chown appuser:appuser /data

RUN mkdir -p /tmp/sentinel && chown appuser:appuser /tmp/sentinel \
    && chmod +x /app/entrypoint.sh

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health/live')" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
