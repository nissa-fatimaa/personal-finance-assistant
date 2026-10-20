# syntax=docker/dockerfile:1.7
# Personal Finance Assistant (Finwise) - production image.
# Stage 1 builds the React UI; stage 2 is a slim Python runtime that serves the API
# and the built UI from the same origin (no CORS needed).

############################
# Stage 1: frontend build  #
############################
FROM node:22-bookworm-slim AS frontend
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend ./frontend
RUN npm run build            # writes to /build/app/static

############################
# Stage 2: Python runtime  #
############################
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

# tesseract + poppler-utils power receipt/bill OCR (app/receipts.py); the app
# degrades to "unreadable" without them, so they are installed for full features.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      tesseract-ocr=5.3.0-* poppler-utils=22.12.0-* \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY alembic.ini ./
COPY app ./app
COPY migrations ./migrations
COPY scripts ./scripts
COPY tests ./tests
COPY db ./db
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Replace any stale committed UI with the freshly built one.
RUN rm -rf ./app/static
COPY --from=frontend /build/app/static ./app/static

RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh \
 && useradd --system --uid 10001 --home-dir /srv/app --shell /usr/sbin/nologin pfa \
 && chown -R root:root /srv/app && chmod -R a+rX /srv/app
USER pfa

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/health',timeout=4)" || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["serve"]
