# ============================================================================
# SentinelSIEM Frontend
# Build stage
# ============================================================================

FROM node:22-alpine AS build

WORKDIR /app

COPY frontend/package.json frontend/package-lock.json ./

RUN npm ci

COPY frontend/ ./

RUN npm run build


# ============================================================================
# SentinelSIEM Frontend
# Runtime stage
# ============================================================================

FROM nginx:1.27-alpine AS runtime

# --------------------------------------------------------------------------
# Static frontend
# --------------------------------------------------------------------------

COPY --from=build /app/dist /usr/share/nginx/html

# --------------------------------------------------------------------------
# Nginx configuration
# --------------------------------------------------------------------------

COPY deployment/nginx/nginx.conf /etc/nginx/nginx.conf

# --------------------------------------------------------------------------
# Runtime entrypoint
# --------------------------------------------------------------------------

COPY deployment/docker/frontend/entrypoint.sh /usr/local/bin/sentinelsiem-frontend-entrypoint

RUN chmod 0755 /usr/local/bin/sentinelsiem-frontend-entrypoint \
    && mkdir -p \
        /tmp/nginx \
        /tmp/nginx/client_temp \
        /tmp/nginx/proxy_temp \
        /tmp/nginx/fastcgi_temp \
        /tmp/nginx/uwsgi_temp \
        /tmp/nginx/scgi_temp \
        /run/nginx \
    && chown -R nginx:nginx \
        /usr/share/nginx/html \
        /tmp/nginx \
        /run/nginx \
    && chmod -R 0555 /usr/share/nginx/html \
    && chmod 0755 /tmp/nginx \
    && chmod 0755 /run/nginx

# --------------------------------------------------------------------------
# Security
# --------------------------------------------------------------------------

USER nginx

EXPOSE 8080

# --------------------------------------------------------------------------
# Healthcheck
# --------------------------------------------------------------------------

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=15s \
    --retries=3 \
    CMD wget \
        --no-verbose \
        --tries=1 \
        --spider \
        http://127.0.0.1:8080/health \
        || exit 1

# --------------------------------------------------------------------------
# Runtime
# --------------------------------------------------------------------------

ENTRYPOINT ["/usr/local/bin/sentinelsiem-frontend-entrypoint"]

CMD ["nginx", "-g", "daemon off;"]
