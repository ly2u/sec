FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends minisign=0.12-1 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r requirements.lock \
    && groupadd --gid 10001 secwatch \
    && useradd --uid 10001 --gid 10001 --no-create-home secwatch
COPY pyproject.toml alembic.ini .dockerignore /app/
COPY apps /app/apps
COPY collector /app/collector
COPY migrations /app/migrations
COPY deploy /app/deploy
COPY tests /app/tests
COPY keys /app/keys
COPY rules /app/rules
RUN pip install --no-cache-dir --no-deps --no-build-isolation .
RUN mkdir -p /bundles && chown 10001:10001 /bundles
USER 10001:10001
CMD ["uvicorn", "apps.server.main:app", "--host", "0.0.0.0", "--port", "8000"]
