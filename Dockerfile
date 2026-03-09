FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data

# Make start script executable
RUN chmod +x start.sh

# Environment variables
ENV PORT=8000
ENV DATABASE_PATH=/app/data/gsc_tokens.db

# Run with start.sh which handles PORT expansion
CMD ["sh", "start.sh"]
