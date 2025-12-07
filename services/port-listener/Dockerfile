# Port Listener Service Dockerfile
FROM python:3.12-slim

LABEL maintainer="HoneyKube" \
      description="Port listener honeypot service" \
      version="1.0"

# Set working directory
WORKDIR /app

# Install dependencies
COPY services/port-listener/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared modules
COPY shared /app/shared

# Copy application code
COPY services/port-listener/main.py .

# Copy all fingerprint configs
COPY config/fingerprints /config/fingerprints

# Create non-root user
RUN useradd -r -s /bin/false honeypot && \
    chown -R honeypot:honeypot /app /config

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LISTEN_PORT=8080 \
    FINGERPRINT_PATH=/config/fingerprint.yaml \
    SCANNER_DETECTOR_URL=http://scanner-detector:8081 \
    LLM_PLANNER_URL=http://llm-planner:8082 \
    ARTIFACT_SINK_URL=http://artifact-sink:8083

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${LISTEN_PORT}/_health')"

USER honeypot

EXPOSE ${LISTEN_PORT}

CMD ["python", "main.py"]
