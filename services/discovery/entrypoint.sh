#!/bin/sh
set -e

echo "Running Alembic migrations..."
cd /app
alembic upgrade head

echo "Starting Discovery Service..."
exec uvicorn discovery.main:app --host 0.0.0.0 --port 8000
