FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system --gid 10002 siem-worker \
    && useradd --system --uid 10002 --gid siem-worker --create-home --home-dir /home/siem-worker siem-worker

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY backend ./backend

RUN python -m pip install --upgrade pip \
    && python -m pip install . \
    && chown -R siem-worker:siem-worker /app

USER siem-worker

# Set WORKER_COMMAND to an actual worker entrypoint from the live repository.
ENTRYPOINT ["/bin/sh", "-c"]
CMD ["exec ${WORKER_COMMAND:?WORKER_COMMAND must be set to a real worker entrypoint}"]
