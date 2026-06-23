# Multi-stage build for the reachable-cve webhook server.
# Stage 1 builds wheels with the C extensions tree-sitter needs.
# Stage 2 is a slim runtime with git (for cloning PR heads) and tini (signals).

FROM python:3.12-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc g++ git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY src ./src
RUN pip install --no-cache-dir --user --upgrade pip \
    && pip install --no-cache-dir --user .

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates tini curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 rcve
USER rcve
WORKDIR /home/rcve
COPY --from=builder --chown=rcve:rcve /root/.local /home/rcve/.local
ENV PATH=/home/rcve/.local/bin:$PATH \
    RCVE_LOG_JSON=1 \
    REACHABLE_CVE_CACHE_DIR=/home/rcve/.cache/reachable-cve
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8080/healthz || exit 1
ENTRYPOINT ["tini", "--"]
CMD ["uvicorn", "reachable_cve.server:app", "--host", "0.0.0.0", "--port", "8080"]
