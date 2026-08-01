# syntax=docker/dockerfile:1.7
FROM python:3.13-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY pyproject.toml setup.py MANIFEST.in README.md LICENSE SECURITY.md ./
COPY src ./src
COPY schemas ./schemas
RUN python -m pip wheel --no-deps --wheel-dir /wheels .

FROM python:3.13-slim AS runtime

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/agentguard

RUN groupadd --system --gid 10001 agentguard \
    && useradd --system --uid 10001 --gid agentguard --create-home --home-dir /home/agentguard agentguard

COPY --from=builder /wheels /wheels
RUN python -m pip install /wheels/*.whl \
    && rm -rf /wheels

USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["agentguard"]
CMD ["--help"]
