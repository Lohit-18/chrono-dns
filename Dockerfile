# =============================================================================
#  Chrono-DNS — multi-stage image
#  Stage 1 builds wheels, stage 2 is a slim runtime with a non-root user.
# =============================================================================
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml ./
RUN pip wheel --wheel-dir /wheels -r requirements.txt asyncpg>=0.29


# -----------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="Chrono-DNS" \
      org.opencontainers.image.description="ML-driven DNS security gateway & threat intelligence engine" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    CHRONODNS_LISTEN_HOST=0.0.0.0 \
    CHRONODNS_API_HOST=0.0.0.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        dnsutils curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 chrono

WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels /wheels/* && rm -rf /wheels

COPY --chown=chrono:chrono . .
RUN pip install --no-deps -e . && mkdir -p data models data/logs \
    && chown -R chrono:chrono /app

USER chrono

EXPOSE 5353/udp 5353/tcp 8088/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import chronodns; from chronodns.config import get_config; get_config()" || exit 1

ENTRYPOINT ["python", "-m", "chronodns"]
CMD ["serve"]
