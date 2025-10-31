FROM python:3.11-alpine AS builder

RUN apk add --no-cache curl build-base libffi-dev \
    && curl -LsSf https://astral.sh/uv/install.sh | sh

WORKDIR /app
COPY pyproject.toml uv.lock* ./
RUN ~/.local/bin/uv venv && ~/.local/bin/uv sync --frozen


FROM python:3.11-slim AS runtime

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

COPY --from=builder /app/.venv /app/.venv
COPY src/ ./src/
COPY pyproject.toml ./

RUN groupadd -r appuser && useradd -r -g appuser appuser \
    && chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["/app/.venv/bin/python", "src/hatiyar/main.py"]
