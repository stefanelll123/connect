# ── Stage 1: build wheels ─────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Copy dependency manifests first (layer cache)
COPY services/discovery/pyproject.toml ./pyproject.toml
COPY pyproject.toml ./root-pyproject.toml

# Install build tools
RUN pip install --no-cache-dir build pip-tools

# Install all dependencies into /build/packages
RUN pip install --no-cache-dir \
    --target /build/packages \
    fastapi uvicorn[standard] sqlalchemy[asyncio] asyncpg alembic \
    redis httpx pydantic pydantic-settings python-jose cryptography \
    opentelemetry-sdk opentelemetry-exporter-otlp opentelemetry-instrumentation-fastapi \
    hvac web3

# Copy source code
COPY services/discovery/src ./src

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

# Set Python path to include packages
ENV PYTHONPATH=/app/packages:/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Fix ownership
RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/live')" || exit 1

CMD ["uvicorn", "discovery.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
