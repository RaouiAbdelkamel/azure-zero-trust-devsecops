# Digest réel résolu depuis Docker Hub et SHA-256 du manifest vérifié ; base-image.json.
FROM python:3.11-slim-bookworm@sha256:0a310eeecf4e1f5a0743f9a6520c90c88d089c903ca5fd283f501e3a805f5f89 AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY requirements.lock ./
# La venv ne contient aucun pip/setuptools/wheel ; seulement les dépendances runtime.
RUN python -m venv --without-pip /opt/venv \
    && python -m pip --python /opt/venv install --require-hashes --only-binary=:all: -r requirements.lock

FROM python:3.11-slim-bookworm@sha256:0a310eeecf4e1f5a0743f9a6520c90c88d089c903ca5fd283f501e3a805f5f89 AS runtime
LABEL org.opencontainers.image.title="secure-api" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.description="Azure Zero Trust FastAPI reference service"
ENV PATH="/opt/venv/bin:$PATH" PYTHONPATH="/app/src" \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=0 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN groupadd --system --gid 10001 appgroup \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin appuser \
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
