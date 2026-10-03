# Multi-stage lightweight OCI container for Tanuki
FROM python:3.10-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE* ./
COPY tanuki/ ./tanuki/

RUN pip install --no-cache-dir build && \
    python -m build --wheel --no-isolation

FROM python:3.10-slim AS runner

WORKDIR /app

RUN useradd -u 10001 -U -M -s /usr/sbin/nologin tanuki

COPY --from=builder /app/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

USER tanuki

ENTRYPOINT ["tanuki"]
CMD ["doctor"]
