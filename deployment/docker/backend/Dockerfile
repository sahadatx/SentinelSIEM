FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# --------------------------------------------------------------------------
# SentinelSIEM runtime user
# --------------------------------------------------------------------------

RUN groupadd \
        --system \
        --gid 10001 \
        siem \
    && useradd \
        --system \
        --uid 10001 \
        --gid siem \
        --create-home \
        --home-dir /home/siem \
        siem

WORKDIR /app

# --------------------------------------------------------------------------
# Python project metadata
# --------------------------------------------------------------------------

COPY pyproject.toml README.md LICENSE ./

# --------------------------------------------------------------------------
# SentinelSIEM application source
#
# This includes:
#   backend/app/
#   backend/app/storage/migrations/*.sql
# --------------------------------------------------------------------------

COPY alembic.ini ./
COPY alembic ./alembic

COPY backend ./backend

# --------------------------------------------------------------------------
# Install application
# --------------------------------------------------------------------------

RUN python -m pip install --upgrade pip \
    && python -m pip install . \
    && chown -R siem:siem /app

# --------------------------------------------------------------------------
# Drop root privileges
# --------------------------------------------------------------------------

USER siem

EXPOSE 8000

# --------------------------------------------------------------------------
# Application health check
# --------------------------------------------------------------------------

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=20s \
    --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('SIEM_API_PORT', '8000') + '/health/live', timeout=3)"

# --------------------------------------------------------------------------
# Default SentinelSIEM API process
# --------------------------------------------------------------------------

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]