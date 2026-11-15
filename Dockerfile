# syntax=docker/dockerfile:1.7
FROM python:3.13-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY pyproject.toml setup.py MANIFEST.in README.md LICENSE ./
COPY src ./src
COPY schemas ./schemas
RUN python -m pip wheel --no-deps --wheel-dir /wheels .

FROM python:3.13-slim AS runtime

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/decisionlock

RUN groupadd --system --gid 10001 decisionlock \
    && useradd --system --uid 10001 --gid decisionlock --create-home --home-dir /home/decisionlock decisionlock

COPY --from=builder /wheels /wheels
RUN WHEEL="$(find /wheels -type f -name 'decisionlock-*.whl' -print -quit)" \
    && test -n "$WHEEL" \
    && python -m pip install "${WHEEL}[http]" \
    && rm -rf /wheels

USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["decisionlock"]
CMD ["--help"]
