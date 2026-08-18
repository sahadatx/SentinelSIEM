#!/usr/bin/env sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

ENV_FILE="$PROJECT_ROOT/.env"

BASE_COMPOSE="$PROJECT_ROOT/deployment/docker-compose/docker-compose.yml"
PROD_COMPOSE="$PROJECT_ROOT/deployment/docker-compose/docker-compose.prod.yml"
K8S_DIR="$PROJECT_ROOT/deployment/kubernetes"

printf '%s\n' '[Phase 19] validating deployment artifacts'

###############################################################################
# Helpers
###############################################################################

fail() {
    printf '%s\n' "ERROR: $*" >&2
    exit 1
}

info() {
    printf '%s\n' "$*"
}

###############################################################################
# Required files
###############################################################################

[ -f "$ENV_FILE" ] || fail ".env file not found: $ENV_FILE"
[ -f "$BASE_COMPOSE" ] || fail "base docker compose file not found: $BASE_COMPOSE"
[ -f "$PROD_COMPOSE" ] || fail "production docker compose file not found: $PROD_COMPOSE"
[ -d "$K8S_DIR" ] || fail "Kubernetes deployment directory not found: $K8S_DIR"

###############################################################################
# Environment / secret validation
###############################################################################

require_env_value() {
    key=$1

    value=$(
        grep -E "^${key}=" "$ENV_FILE" \
            | head -n 1 \
            | cut -d '=' -f 2- \
            || true
    )

    if [ -z "$value" ]; then
        fail "required variable $key is missing"
    fi

    case "$value" in
        REPLACE_WITH_*|"")
            fail "required variable $key still contains a placeholder"
            ;;
    esac
}

require_env_value "SIEM_AUTH_SECRET_KEY"
require_env_value "POSTGRES_PASSWORD"
require_env_value "REDIS_PASSWORD"
require_env_value "OPENSEARCH_INITIAL_ADMIN_PASSWORD"

auth_secret=$(
    grep -E '^SIEM_AUTH_SECRET_KEY=' "$ENV_FILE" \
        | head -n 1 \
        | cut -d '=' -f 2-
)

if [ "${#auth_secret}" -lt 32 ]; then
    unset auth_secret
    fail "SIEM_AUTH_SECRET_KEY must contain at least 32 characters"
fi

unset auth_secret

if grep -nE \
    '^SIEM_(DATABASE_URL|AUTH_SECRET_KEY|REDIS_URL)=.*REPLACE_WITH_' \
    "$ENV_FILE" >/dev/null 2>&1
then
    fail "one or more security/connection variables still contain placeholders"
fi

info 'OK: required production secrets are configured'

###############################################################################
# Docker Compose validation
###############################################################################

if command -v docker >/dev/null 2>&1; then
    docker compose \
        --env-file "$ENV_FILE" \
        -f "$BASE_COMPOSE" \
        config >/dev/null

    info 'OK: base docker compose configuration'

    docker compose \
        --env-file "$ENV_FILE" \
        -f "$BASE_COMPOSE" \
        -f "$PROD_COMPOSE" \
        config >/dev/null

    info 'OK: merged production docker compose configuration'
else
    info 'SKIP: docker not installed'
fi

###############################################################################
# Kubernetes manifest inventory
###############################################################################

EXPECTED_K8S_FILES="
backend.yaml
collectors.yaml
configmap.yaml
frontend.yaml
ingress.yaml
namespace.yaml
opensearch.yaml
postgres.yaml
redis.yaml
secrets.yaml
worker.yaml
"

for filename in $EXPECTED_K8S_FILES; do
    filepath="$K8S_DIR/$filename"

    [ -f "$filepath" ] || fail "required Kubernetes manifest missing: $filepath"

    [ -s "$filepath" ] || fail "Kubernetes manifest is empty: $filepath"
done

###############################################################################
# Kubernetes local YAML validation
#
# This validation intentionally does NOT depend on a Kubernetes cluster.
# It parses the manifests directly with PyYAML and checks the minimum
# Kubernetes object structure.
###############################################################################

PYTHON_BIN=""

if command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
else
    fail "Python is required for local Kubernetes manifest validation"
fi

if ! "$PYTHON_BIN" -c "import yaml" >/dev/null 2>&1; then
    fail "PyYAML is required for local Kubernetes manifest validation"
fi

"$PYTHON_BIN" - "$K8S_DIR" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

import yaml


REQUIRED_FILES = {
    "backend.yaml",
    "collectors.yaml",
    "configmap.yaml",
    "frontend.yaml",
    "ingress.yaml",
    "namespace.yaml",
    "opensearch.yaml",
    "postgres.yaml",
    "redis.yaml",
    "secrets.yaml",
    "worker.yaml",
}

required_fields = {"apiVersion", "kind", "metadata"}

k8s_dir = Path(sys.argv[1])

actual_files = {
    path.name
    for path in k8s_dir.glob("*.yaml")
    if path.is_file()
}

missing_files = REQUIRED_FILES - actual_files

if missing_files:
    raise SystemExit(
        "missing expected Kubernetes manifests: "
        + ", ".join(sorted(missing_files))
    )

for path in sorted(k8s_dir.glob("*.yaml")):
    if path.name not in REQUIRED_FILES:
        continue

    text = path.read_text(encoding="utf-8")

    if not text.strip():
        raise SystemExit(f"empty Kubernetes manifest: {path}")

    if any(
        marker in text
        for marker in ("<<<<<<<", "=======", ">>>>>>>")
    ):
        raise SystemExit(
            f"merge-conflict marker found in Kubernetes manifest: {path}"
        )

    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise SystemExit(
            f"invalid YAML in {path}: {exc}"
        ) from exc

    if not documents:
        raise SystemExit(f"no YAML documents found in {path}")

    for index, document in enumerate(documents, start=1):
        if document is None:
            raise SystemExit(
                f"empty YAML document {index} in {path}"
            )

        if not isinstance(document, dict):
            raise SystemExit(
                f"document {index} in {path} is not a YAML mapping"
            )

        missing = required_fields - document.keys()

        if missing:
            raise SystemExit(
                f"document {index} in {path} is missing: "
                + ", ".join(sorted(missing))
            )

        metadata = document.get("metadata")

        if not isinstance(metadata, dict):
            raise SystemExit(
                f"document {index} in {path} has invalid metadata"
            )

        name = metadata.get("name")

        if not name:
            raise SystemExit(
                f"document {index} in {path} has no metadata.name"
            )

print(
    f"OK: Kubernetes local YAML validation "
    f"({len(REQUIRED_FILES)} manifests)"
)
PY

###############################################################################
# Kubernetes cluster validation
#
# Important:
# - No current context => skip, do not fail.
# - kubectl installed but cluster unavailable => skip live validation.
# - A configured and reachable cluster => perform server-side dry run.
###############################################################################

if command -v kubectl >/dev/null 2>&1; then
    CURRENT_CONTEXT=$(kubectl config current-context 2>/dev/null || true)

    if [ -z "$CURRENT_CONTEXT" ]; then
        info 'SKIP: Kubernetes live validation (no current-context configured)'
    else
        if kubectl cluster-info >/dev/null 2>&1; then
            info "INFO: Kubernetes context detected: $CURRENT_CONTEXT"

            live_validation_failed=0

            for file in \
                "$K8S_DIR/backend.yaml" \
                "$K8S_DIR/collectors.yaml" \
                "$K8S_DIR/configmap.yaml" \
                "$K8S_DIR/frontend.yaml" \
                "$K8S_DIR/ingress.yaml" \
                "$K8S_DIR/namespace.yaml" \
                "$K8S_DIR/opensearch.yaml" \
                "$K8S_DIR/postgres.yaml" \
                "$K8S_DIR/redis.yaml" \
                "$K8S_DIR/secrets.yaml" \
                "$K8S_DIR/worker.yaml"
            do
                if ! kubectl apply \
                    --dry-run=server \
                    -f "$file" >/dev/null
                then
                    printf '%s\n' \
                        "ERROR: Kubernetes live validation failed: $file" \
                        >&2
                    live_validation_failed=1
                fi
            done

            if [ "$live_validation_failed" -ne 0 ]; then
                exit 1
            fi

            info 'OK: Kubernetes live-cluster validation'
        else
            info 'SKIP: Kubernetes live validation (cluster unreachable or unavailable)'
        fi
    fi
else
    info 'SKIP: kubectl not installed'
fi

###############################################################################
# Completion
###############################################################################

printf '%s\n' ''
printf '%s\n' 'Phase 19 deployment artifact validation completed.'
printf '%s\n' 'Status: PASS (artifact/local validation completed)'