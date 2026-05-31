# ── Stage 1: build wheels ─────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

COPY services/sentinel/pyproject.toml ./pyproject.toml

RUN pip install --no-cache-dir build pip-tools

RUN pip install --no-cache-dir \
    --target /build/packages \
    fastapi uvicorn[standard] sqlalchemy[asyncio] asyncpg \
    redis httpx pydantic pydantic-settings python-jose cryptography \
    opentelemetry-sdk opentelemetry-exporter-otlp opentelemetry-instrumentation-fastapi \
    hvac web3 click typer

# Copy source code
COPY services/sentinel/src ./src

# ── Stage 2: minimal runtime ──────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Create non-root user (UID 1001)
RUN addgroup --gid 1001 appgroup && \
    adduser --uid 1001 --gid 1001 --disabled-password --no-create-home \
    --shell /sbin/nologin appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /build/packages /app/packages

# Copy application source
COPY --from=builder /build/src ./src

# Sentinel home directory (persist keys/secrets via named volume)
ENV SENTINEL_HOME=/sentinel-home \
    PYTHONPATH=/app/packages:/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN mkdir -p /sentinel-home && chown appuser:appgroup /sentinel-home
VOLUME /sentinel-home

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health/live')" || exit 1

CMD ["uvicorn", "sentinel.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
