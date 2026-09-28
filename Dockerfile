# Node supplies the bundled WebMssdk runners (live/IM frontierSign, Shop BSID).
FROM node:22-bookworm-slim AS node

FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    NODE_ENV=production

COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv
COPY --from=node /usr/local/bin/node /usr/local/bin/node

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY api ./api
COPY builder ./builder
COPY signing ./signing
COPY reverse/tiktok_shop_bsid/env ./reverse/tiktok_shop_bsid/env
COPY static ./static
COPY utils ./utils
COPY demo.py README.md ./

# The runners execute vendor JavaScript; never run them as root.
RUN useradd --system --uid 10001 app
USER app

ENV PATH="/app/.venv/bin:$PATH"
CMD ["python", "-c", "import api, builder, signing; print('TikTok APIs image ready')"]
