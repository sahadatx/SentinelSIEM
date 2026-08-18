FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system --gid 10003 siem-collector \
    && useradd \
        --system \
        --uid 10003 \
        --gid siem-collector \
        --create-home \
        --home-dir /home/siem-collector \
        siem-collector

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY backend ./backend
COPY plugins ./plugins

RUN python -m pip install --upgrade pip \
    && python -m pip install . \
    && chown -R siem-collector:siem-collector /app

USER siem-collector

ENTRYPOINT ["siem", "collector"]