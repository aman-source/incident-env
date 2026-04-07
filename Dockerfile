FROM python:3.11-slim-bookworm

WORKDIR /app

# Install system deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl && \
    rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy environment code
COPY incident_env/ ./incident_env/

# Set Python path so imports work
ENV PYTHONPATH="/app:$PYTHONPATH"
ENV PORT=7860
ENV HOST=0.0.0.0

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

CMD ["uvicorn", "incident_env.server.app:app", "--host", "0.0.0.0", "--port", "7860"]
