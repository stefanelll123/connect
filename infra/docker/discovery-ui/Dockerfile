# ── Stage 1: build React/Vite app ─────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /build

# Copy dependency manifests first (layer cache)
COPY frontend/discovery-ui/package.json frontend/discovery-ui/package-lock.json ./

# Install dependencies (no devDependencies skipped here — Vite is a devDep)
RUN npm ci

# Copy source
COPY frontend/discovery-ui/ .

# Build production bundle
RUN npm run build

# ── Stage 2: nginx serve ──────────────────────────────────────────────────────
FROM nginx:1.25-alpine AS runtime

# Copy custom nginx config
COPY infra/docker/discovery-ui/nginx.conf /etc/nginx/nginx.conf

# Copy built dist
COPY --from=builder /build/dist /usr/share/nginx/html

# Create non-root user and fix permissions
RUN addgroup -g 1001 nginx-group && \
    adduser -u 1001 -G nginx-group -D -H -s /sbin/nologin nginx-user && \
    chown -R nginx-user:nginx-group /usr/share/nginx/html && \
    # nginx needs write access to these directories when run as non-root
    mkdir -p /var/cache/nginx /var/log/nginx /var/run && \
    chown -R nginx-user:nginx-group /var/cache/nginx /var/log/nginx /var/run && \
    chmod -R 755 /var/cache/nginx /var/log/nginx /var/run

USER nginx-user

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/ || exit 1
