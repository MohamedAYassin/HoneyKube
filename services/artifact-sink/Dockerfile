# Artifact Sink Service Dockerfile
FROM python:3.12-slim

LABEL maintainer="HoneyKube" \
      description="Logging and artifact storage service" \
      version="1.0"

WORKDIR /app

# Install dependencies
COPY services/artifact-sink/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared modules
COPY shared /app/shared

# Copy application code
COPY services/artifact-sink/main.py .

# Create directories and non-root user
RUN useradd -r -s /bin/false honeypot && \
    mkdir -p /logs /artifacts && \
    chown -R honeypot:honeypot /app /logs /artifacts

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LISTEN_PORT=8083 \
    LOG_DIR=/logs \
    ARTIFACT_DIR=/artifacts

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${LISTEN_PORT}/_health')"

USER honeypot

EXPOSE 8083

VOLUME ["/logs", "/artifacts"]

CMD ["python", "main.py"]
