#!/bin/sh
set -eu

NGINX_TMP_DIR="/tmp/nginx"

mkdir -p \
    "${NGINX_TMP_DIR}" \
    "${NGINX_TMP_DIR}/client_temp" \
    "${NGINX_TMP_DIR}/proxy_temp" \
    "${NGINX_TMP_DIR}/fastcgi_temp" \
    "${NGINX_TMP_DIR}/uwsgi_temp" \
    "${NGINX_TMP_DIR}/scgi_temp"

chmod 0755 "${NGINX_TMP_DIR}"

chmod 0700 \
    "${NGINX_TMP_DIR}/client_temp" \
    "${NGINX_TMP_DIR}/proxy_temp" \
    "${NGINX_TMP_DIR}/fastcgi_temp" \
    "${NGINX_TMP_DIR}/uwsgi_temp" \
    "${NGINX_TMP_DIR}/scgi_temp"

exec "$@"
