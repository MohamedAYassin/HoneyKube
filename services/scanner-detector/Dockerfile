# Scanner Detector Service Dockerfile
FROM python:3.12-slim

LABEL maintainer="HoneyKube" \
      description="Scanner detection microservice" \
      version="1.0"

WORKDIR /app

# Install dependencies
COPY services/scanner-detector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared modules
COPY shared /app/shared

# Copy application code
COPY services/scanner-detector/main.py .

# Create non-root user
RUN useradd -r -s /bin/false honeypot && \
    chown -R honeypot:honeypot /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LISTEN_PORT=8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${LISTEN_PORT}/_health')"

USER honeypot

EXPOSE 8081

CMD ["python", "main.py"]
