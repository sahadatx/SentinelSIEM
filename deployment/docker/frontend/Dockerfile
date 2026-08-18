FROM node:22-alpine AS build

WORKDIR /app

COPY frontend/package.json frontend/package-lock.json ./

RUN npm ci

COPY frontend/ ./

RUN npm run build


FROM nginx:1.27-alpine AS runtime

COPY --from=build /app/dist /usr/share/nginx/html

COPY deployment/nginx/nginx.conf /etc/nginx/nginx.conf

RUN mkdir -p \
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

USER nginx

EXPOSE 8080

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=15s \
    --retries=3 \
    CMD wget --no-verbose --tries=1 --spider \
        http://127.0.0.1:8080/health || exit 1

CMD ["nginx", "-g", "daemon off;"]