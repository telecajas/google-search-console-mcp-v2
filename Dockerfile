FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data

# Environment variables
ENV PORT=8000
ENV DATABASE_PATH=/app/data/gsc_tokens.db

# Railway assigns PORT dynamically - don't hardcode it
# The CMD uses the PORT env var that Railway provides

# Run with gunicorn, binding to Railway's PORT
CMD gunicorn gsc_server_remote:app -w 2 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:${PORT:-8000}
