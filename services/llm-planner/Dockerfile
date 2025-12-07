# LLM Planner Service Dockerfile
FROM python:3.12-slim

LABEL maintainer="HoneyKube" \
      description="LLM response planner using OpenRouter" \
      version="2.0"

WORKDIR /app

# Install dependencies
COPY services/llm-planner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared modules
COPY shared /app/shared

# Copy application code
COPY services/llm-planner/main.py .

# Create non-root user
RUN useradd -r -s /bin/false honeypot && \
    chown -R honeypot:honeypot /app

# Environment variables with defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LISTEN_PORT=8082 \
    LLM_MODEL=google/gemini-2.0-flash-001 \
    OPENROUTER_BASE_URL=https://openrouter.ai/api/v1 \
    LLM_TEMPERATURE=0.7 \
    LLM_MAX_TOKENS=4096 \
    REQUEST_TIMEOUT=30 \
    MAX_RETRIES=3

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${LISTEN_PORT}/_health')"

USER honeypot

EXPOSE 8082

CMD ["python", "main.py"]
