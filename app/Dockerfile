# Digest réel résolu depuis Docker Hub et SHA-256 du manifest vérifié ; base-image.json.
FROM python:3.11-alpine3.24@sha256:d9368b3a5ac59afea7b5d4f2e2aea0941dbf9fdee9c369c5bec00b98244bc929 AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY requirements.lock ./
# La venv ne contient aucun pip/setuptools/wheel ; seulement les dépendances runtime.
RUN python -m venv --without-pip /opt/venv \
    && python -m pip --python /opt/venv install --require-hashes --only-binary=:all: -r requirements.lock

FROM python:3.11-alpine3.24@sha256:d9368b3a5ac59afea7b5d4f2e2aea0941dbf9fdee9c369c5bec00b98244bc929 AS runtime
LABEL org.opencontainers.image.title="secure-api" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.description="Azure Zero Trust FastAPI reference service"
ENV PATH="/opt/venv/bin:$PATH" PYTHONPATH="/app/src" \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=0 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN addgroup -S -g 10001 appgroup \
    && adduser -S -D -H -u 10001 -G appgroup -s /sbin/nologin appuser \
    && rm -rf /usr/local/lib/python3.11/site-packages/pip* \
        /usr/local/lib/python3.11/site-packages/setuptools* \
        /usr/local/lib/python3.11/site-packages/wheel* /root/.cache
COPY --from=builder /opt/venv /opt/venv
# Root owns application/dependencies; appuser cannot overwrite executable code.
COPY src/ /app/src/
WORKDIR /app
USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
# Configuration explicite APP_ENV=production + Entra à fournir pour la production.
# Sans configuration : mode local, endpoint secure indisponible (503), jamais anonyme.
CMD ["python", "-m", "secure_api.main"]
