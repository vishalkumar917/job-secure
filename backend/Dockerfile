# Backend image: FastAPI + Volatility 3. Build context is the repository root
# (rules/, yara_rules/ and sample_data/ are baked in).
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged user: Volatility parses untrusted input, so it never runs as root.
RUN useradd --create-home --uid 10001 app
WORKDIR /app

COPY backend/requirements.txt backend/requirements-optional.txt ./
RUN pip install -r requirements.txt -r requirements-optional.txt

COPY backend/app ./app
COPY rules /app/rules
COPY yara_rules /app/yara_rules
COPY sample_data /app/sample_data

RUN mkdir -p /data /symbols /home/app/.cache/volatility3 \
    && chown -R app:app /data /symbols /home/app/.cache \
    && chmod -R a-w /app/rules /app/yara_rules /app/sample_data

ENV DATA_DIR=/data \
    RULES_DIR=/app/rules \
    YARA_RULES_DIR=/app/yara_rules \
    SAMPLE_DATA_DIR=/app/sample_data

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=5 CMD curl -fsS http://localhost:8000/api/health || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
