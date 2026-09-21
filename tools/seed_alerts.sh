#!/usr/bin/env bash

set -euo pipefail

# ============================================================================
# SentinelSIEM — Alert Seeder
#
# Flow:
#   SECURITY_EVENT
#        ↓
#   TCP Collector :1514
#        ↓
#   Redis
#        ↓
#   Ingestion Worker
#        ↓
#   Parser / Normalizer
#        ↓
#   Detection Engine
#        ↓
#   Alert Manager
#        ↓
#   OpenSearch
#
# Purpose:
#   Create a varied alert dataset for the Alerts UI.
# ============================================================================

API_URL="${API_URL:-http://127.0.0.1:8001}"
COLLECTOR_HOST="${COLLECTOR_HOST:-127.0.0.1}"
COLLECTOR_PORT="${COLLECTOR_PORT:-1514}"
NC_TIMEOUT="${NC_TIMEOUT:-3}"

SLEEP_BETWEEN_EVENTS="${SLEEP_BETWEEN_EVENTS:-0.15}"
POLL_ATTEMPTS="${POLL_ATTEMPTS:-20}"
POLL_DELAY="${POLL_DELAY:-0.5}"

TMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT


# ============================================================================
# COLORS
# ============================================================================

if [[ -t 1 ]]; then
    CYAN="\033[36m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    RED="\033[31m"
    RESET="\033[0m"
else
    CYAN=""
    GREEN=""
    YELLOW=""
    RED=""
    RESET=""
fi


# ============================================================================
# HELPERS
# ============================================================================

log() {
    printf "%b\n" "${CYAN}[seed]${RESET} $*"
}

success() {
    printf "%b\n" "${GREEN}[ ok ]${RESET} $*"
}

warn() {
    printf "%b\n" "${YELLOW}[warn]${RESET} $*"
}

fail() {
    printf "%b\n" "${RED}[fail]${RESET} $*" >&2
}


require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        fail "Required command not found: $1"
        exit 1
    }
}


send_event() {
    local event="$1"

    printf '%s\n' "$event" \
        | timeout "$NC_TIMEOUT" nc \
            "$COLLECTOR_HOST" \
            "$COLLECTOR_PORT" \
            >/dev/null 2>&1 || true

    sleep "$SLEEP_BETWEEN_EVENTS"
}


api_get_alerts() {
    curl -fsS \
        --connect-timeout 3 \
        --max-time 10 \
        "${API_URL}/api/v1/alerts"
}


get_alert_ids() {
    api_get_alerts \
        | python -c '
import json
import sys

data = json.load(sys.stdin)

for item in data.get("items", []):
    alert_id = item.get("alert_id")
    if alert_id:
        print(alert_id)
'
}


get_alert_records() {
    api_get_alerts \
        | python -c '
import json
import sys

data = json.load(sys.stdin)

for item in data.get("items", []):
    print(json.dumps({
        "alert_id": item.get("alert_id"),
        "rule_id": item.get("rule_id"),
        "status": item.get("status"),
        "severity": item.get("severity"),
        "assignee": item.get("assignee"),
        "ownership_group": item.get("ownership_group"),
    }))
'
}


wait_for_alerts() {
    local minimum="$1"
    local attempt=1
    local total=0

    log "Waiting for detection engine to create alerts..."

    while (( attempt <= POLL_ATTEMPTS )); do
        total="$(
            api_get_alerts 2>/dev/null \
                | python -c '
import json
import sys

try:
    data = json.load(sys.stdin)
    print(int(data.get("pagination", {}).get("total", 0)))
except Exception:
    print(0)
' 2>/dev/null || echo 0
        )"

        if (( total >= minimum )); then
            success "Alert count reached ${total}."
            return 0
        fi

        printf "  attempt %02d/%02d — alerts: %s\n" \
            "$attempt" \
            "$POLL_ATTEMPTS" \
            "$total"

        sleep "$POLL_DELAY"
        ((attempt += 1))
    done

    warn "Alert count did not reach ${minimum}; continuing with available alerts."
}


transition_alert() {
    local alert_id="$1"
    local target_status="$2"
    local reason="$3"

    curl -fsS \
        --connect-timeout 3 \
        --max-time 10 \
        -X POST \
        "${API_URL}/api/v1/alerts/${alert_id}/transition" \
        -H 'Content-Type: application/json' \
        -d "$(python - "$target_status" "$reason" <<'PY'
import json
import sys

print(json.dumps({
    "status": sys.argv[1],
    "reason": sys.argv[2],
}))
PY
)" >/dev/null
}


assign_alert() {
    local alert_id="$1"
    local assignee="$2"
    local ownership_group="$3"

    curl -fsS \
        --connect-timeout 3 \
        --max-time 10 \
        -X PATCH \
        "${API_URL}/api/v1/alerts/${alert_id}/assignment" \
        -H 'Content-Type: application/json' \
        -d "$(python - "$assignee" "$ownership_group" <<'PY'
import json
import sys

print(json.dumps({
    "assignee": sys.argv[1],
    "ownership_group": sys.argv[2],
}))
PY
)" >/dev/null
}


# ============================================================================
# PRE-FLIGHT
# ============================================================================

require_command curl
require_command nc
require_command timeout
require_command python


log "SentinelSIEM alert seeder"
log "API       : ${API_URL}"
log "Collector : ${COLLECTOR_HOST}:${COLLECTOR_PORT}"

printf "\n"


# ============================================================================
# SERVICE CHECK
# ============================================================================

if ! curl -fsS \
    --connect-timeout 3 \
    --max-time 5 \
    "${API_URL}/api/v1/alerts" \
    >/dev/null 2>&1; then

    fail "Alerts API is not reachable: ${API_URL}/api/v1/alerts"
    exit 1
fi

success "Alerts API reachable."


if ! timeout 2 bash -c \
    "</dev/tcp/${COLLECTOR_HOST}/${COLLECTOR_PORT}" \
    >/dev/null 2>&1; then

    warn "TCP collector ${COLLECTOR_HOST}:${COLLECTOR_PORT} could not be verified."
    warn "Events will still be attempted."
else
    success "TCP collector reachable."
fi


printf "\n"


# ============================================================================
# BASELINE
# ============================================================================

BASELINE_TOTAL="$(
    api_get_alerts \
        | python -c '
import json
import sys

data = json.load(sys.stdin)
print(int(data.get("pagination", {}).get("total", 0)))
'
)"

log "Existing alerts: ${BASELINE_TOTAL}"
printf "\n"


# ============================================================================
# 1. BRUTE-FORCE / SUSPICIOUS LOGIN EVENTS
# ============================================================================

log "Generating authentication alerts..."


send_event \
'SECURITY_EVENT action=login outcome=failure severity=high category=authentication username=attacker source_ip=10.10.10.50 destination_ip=10.10.10.20 process=sshd protocol=tcp source_port=45001 destination_port=22'

send_event \
'SECURITY_EVENT action=login outcome=failure severity=critical category=authentication username=admin source_ip=10.10.10.51 destination_ip=10.10.10.20 process=sshd protocol=tcp source_port=45002 destination_port=22'

send_event \
'SECURITY_EVENT action=login outcome=failure severity=medium category=authentication username=root source_ip=10.10.10.52 destination_ip=10.10.10.20 process=sshd protocol=tcp source_port=45003 destination_port=22'

send_event \
'SECURITY_EVENT action=login outcome=failure severity=high category=authentication username=svc-backup source_ip=10.10.10.53 destination_ip=10.10.10.21 process=sshd protocol=tcp source_port=45004 destination_port=22'

send_event \
'SECURITY_EVENT action=login outcome=failure severity=medium category=authentication username=analyst source_ip=10.10.10.54 destination_ip=10.10.10.22 process=sshd protocol=tcp source_port=45005 destination_port=22'

send_event \
'SECURITY_EVENT action=login outcome=success severity=info category=authentication username=admin source_ip=10.10.20.10 destination_ip=10.10.10.20 process=sshd protocol=tcp source_port=45100 destination_port=22'

send_event \
'SECURITY_EVENT action=login outcome=success severity=low category=authentication username=soc-analyst-01 source_ip=10.10.20.11 destination_ip=10.10.10.20 process=sshd protocol=tcp source_port=45101 destination_port=22'


# ============================================================================
# 2. PORT SCAN / NETWORK EVENTS
# ============================================================================

log "Generating network detection events..."


send_event \
'SECURITY_EVENT action=network_connection outcome=allowed severity=medium category=network source_ip=10.20.30.50 destination_ip=10.20.30.20 source_port=51001 destination_port=21 protocol=tcp process=nmap'

send_event \
'SECURITY_EVENT action=network_connection outcome=allowed severity=medium category=network source_ip=10.20.30.50 destination_ip=10.20.30.20 source_port=51002 destination_port=22 protocol=tcp process=nmap'

send_event \
'SECURITY_EVENT action=network_connection outcome=allowed severity=medium category=network source_ip=10.20.30.50 destination_ip=10.20.30.20 source_port=51003 destination_port=23 protocol=tcp process=nmap'

send_event \
'SECURITY_EVENT action=network_connection outcome=allowed severity=high category=network source_ip=10.20.30.50 destination_ip=10.20.30.20 source_port=51004 destination_port=80 protocol=tcp process=nmap'

send_event \
'SECURITY_EVENT action=network_connection outcome=allowed severity=high category=network source_ip=10.20.30.50 destination_ip=10.20.30.20 source_port=51005 destination_port=443 protocol=tcp process=nmap'

send_event \
'SECURITY_EVENT action=network_connection outcome=blocked severity=high category=network source_ip=10.20.30.51 destination_ip=10.20.30.20 source_port=51006 destination_port=3389 protocol=tcp process=masscan'


# ============================================================================
# 3. MALWARE EVENTS
# ============================================================================

log "Generating malware events..."


send_event \
'SECURITY_EVENT action=file_modify outcome=blocked severity=critical category=malware username=malware-test source_ip=10.30.40.10 destination_ip=10.30.40.20 process=malware-agent command=quarantine'

send_event \
'SECURITY_EVENT action=process_start outcome=blocked severity=critical category=malware username=malware-test source_ip=10.30.40.11 destination_ip=10.30.40.20 process=malicious.exe command=execute'

send_event \
'SECURITY_EVENT action=process_start outcome=failure severity=high category=malware username=sandbox source_ip=10.30.40.12 destination_ip=10.30.40.20 process=trojan-test command=execute'


# ============================================================================
# 4. PRIVILEGE ESCALATION EVENTS
# ============================================================================

log "Generating privilege-escalation events..."


send_event \
'SECURITY_EVENT action=privilege_escalation outcome=success severity=critical category=authorization username=attacker source_ip=10.40.50.10 destination_ip=10.40.50.20 process=sudo command=su-root'

send_event \
'SECURITY_EVENT action=privilege_escalation outcome=allowed severity=high category=authorization username=operator source_ip=10.40.50.11 destination_ip=10.40.50.20 process=sudo command=systemctl'

send_event \
'SECURITY_EVENT action=privilege_escalation outcome=denied severity=high category=authorization username=guest source_ip=10.40.50.12 destination_ip=10.40.50.20 process=sudo command=su-root'


# ============================================================================
# 5. WEB ATTACK EVENTS
# ============================================================================

log "Generating web-security events..."


send_event \
'SECURITY_EVENT action=command_execution outcome=blocked severity=high category=web username=web-attacker source_ip=10.50.60.10 destination_ip=10.50.60.20 process=nginx command=sql-injection'

send_event \
'SECURITY_EVENT action=network_connection outcome=blocked severity=critical category=web username=web-attacker source_ip=10.50.60.11 destination_ip=10.50.60.20 process=nginx protocol=tcp destination_port=443'

send_event \
'SECURITY_EVENT action=file_access outcome=denied severity=high category=web username=web-attacker source_ip=10.50.60.12 destination_ip=10.50.60.20 process=nginx command=path-traversal'


# ============================================================================
# 6. FILE / SYSTEM SECURITY EVENTS
# ============================================================================

log "Generating file/system security events..."


send_event \
'SECURITY_EVENT action=file_access outcome=allowed severity=low category=file username=analyst source_ip=10.60.70.10 destination_ip=10.60.70.20 process=fileserver'

send_event \
'SECURITY_EVENT action=file_modify outcome=success severity=medium category=file username=developer source_ip=10.60.70.11 destination_ip=10.60.70.20 process=editor'

send_event \
'SECURITY_EVENT action=file_access outcome=denied severity=high category=file username=guest source_ip=10.60.70.12 destination_ip=10.60.70.20 process=fileserver'

send_event \
'SECURITY_EVENT action=process_start outcome=success severity=info category=process username=admin source_ip=10.60.70.13 destination_ip=10.60.70.20 process=backup-agent'

send_event \
'SECURITY_EVENT action=process_stop outcome=success severity=low category=process username=operator source_ip=10.60.70.14 destination_ip=10.60.70.20 process=legacy-agent'


# ============================================================================
# 7. POLICY / ACCOUNT EVENTS
# ============================================================================

log "Generating policy/account events..."


send_event \
'SECURITY_EVENT action=account_change outcome=success severity=medium category=authorization username=admin source_ip=10.70.80.10 destination_ip=10.70.80.20 process=user-management'

send_event \
'SECURITY_EVENT action=account_change outcome=denied severity=high category=authorization username=attacker source_ip=10.70.80.11 destination_ip=10.70.80.20 process=user-management'

send_event \
'SECURITY_EVENT action=policy_change outcome=success severity=medium category=system username=admin source_ip=10.70.80.12 destination_ip=10.70.80.20 process=policy-manager'


# ============================================================================
# WAIT FOR DETECTION PIPELINE
# ============================================================================

EXPECTED_MINIMUM=$((BASELINE_TOTAL + 1))

printf "\n"

wait_for_alerts "$EXPECTED_MINIMUM"

printf "\n"


# ============================================================================
# ASSIGNMENT
#
# Assignment is done against persisted alert IDs so the Assignee and
# Ownership Group dropdowns have real backend values.
# ============================================================================

log "Applying analyst assignments..."

mapfile -t ALERT_RECORDS < <(
    get_alert_records
)

if (( ${#ALERT_RECORDS[@]} == 0 )); then
    warn "No persisted alerts available for assignment."
else
    ASSIGNEES=(
        "soc-analyst-01"
        "soc-analyst-02"
        "soc-analyst-03"
        "tier-2-analyst"
        "incident-response"
    )

    GROUPS=(
        "SOC"
        "SOC"
        "SOC"
        "Tier-2"
        "Incident Response"
    )

    assignment_index=0

    for record in "${ALERT_RECORDS[@]}"; do
        alert_id="$(
            python -c '
import json
import sys

item = json.loads(sys.argv[1])
print(item.get("alert_id", ""))
' "$record"
        )"

        [[ -z "$alert_id" ]] && continue

        assignee_index=$((assignment_index % ${#ASSIGNEES[@]}))

        assignee="${ASSIGNEES[$assignee_index]}"
        group="${GROUPS[$assignee_index]}"

        if assign_alert \
            "$alert_id" \
            "$assignee" \
            "$group"; then

            success "Assigned ${alert_id:0:8}... → ${assignee} / ${group}"
        else
            warn "Could not assign ${alert_id:0:8}..."
        fi

        ((assignment_index += 1))
    done
fi


# ============================================================================
# LIFECYCLE VARIETY
#
# Apply valid lifecycle transitions to the first few persisted alerts.
# ============================================================================

printf "\n"

log "Applying alert lifecycle states..."

mapfile -t ALERT_IDS < <(
    get_alert_ids
)

if (( ${#ALERT_IDS[@]} >= 1 )); then
    if transition_alert \
        "${ALERT_IDS[0]}" \
        "acknowledged" \
        "Seeded alert acknowledged for dashboard testing."; then

        success "Alert ${ALERT_IDS[0]:0:8}... → acknowledged"
    fi
fi

if (( ${#ALERT_IDS[@]} >= 2 )); then
    if transition_alert \
        "${ALERT_IDS[1]}" \
        "investigating" \
        "Seeded alert moved to analyst investigation."; then

        success "Alert ${ALERT_IDS[1]:0:8}... → investigating"
    fi
fi

if (( ${#ALERT_IDS[@]} >= 3 )); then
    if transition_alert \
        "${ALERT_IDS[2]}" \
        "acknowledged" \
        "Seeded alert acknowledged before escalation."; then

        if transition_alert \
            "${ALERT_IDS[2]}" \
            "escalated" \
            "Seeded high-priority alert escalated."; then

            success "Alert ${ALERT_IDS[2]:0:8}... → escalated"
        fi
    fi
fi

if (( ${#ALERT_IDS[@]} >= 4 )); then
    if transition_alert \
        "${ALERT_IDS[3]}" \
        "acknowledged" \
        "Seeded alert acknowledged."; then

        if transition_alert \
            "${ALERT_IDS[3]}" \
            "resolved" \
            "Seeded alert resolved for lifecycle testing."; then

            success "Alert ${ALERT_IDS[3]:0:8}... → resolved"
        fi
    fi
fi

if (( ${#ALERT_IDS[@]} >= 5 )); then
    if transition_alert \
        "${ALERT_IDS[4]}" \
        "suppressed" \
        "Seeded alert suppressed for dashboard testing."; then

        success "Alert ${ALERT_IDS[4]:0:8}... → suppressed"
    fi
fi


# ============================================================================
# FINAL STATISTICS
# ============================================================================

printf "\n"

log "Fetching final alert statistics..."

FINAL_RESPONSE="$(
    api_get_alerts
)"

python - "$FINAL_RESPONSE" <<'PY'
import json
import sys

data = json.loads(sys.argv[1])

items = data.get("items", [])
pagination = data.get("pagination", {})

total = int(pagination.get("total", len(items)))

statuses = {}
severities = {}
rules = {}
assignees = {}
sources = {}

for alert in items:
    status = alert.get("status")
    severity = alert.get("severity")
    rule = alert.get("rule_id")
    assignee = alert.get("assignee")
    source = alert.get("source_type")

    if status:
        statuses[status] = statuses.get(status, 0) + 1

    if severity:
        severities[severity] = severities.get(severity, 0) + 1

    if rule:
        rules[rule] = rules.get(rule, 0) + 1

    if assignee:
        assignees[assignee] = assignees.get(assignee, 0) + 1

    if source:
        sources[source] = sources.get(source, 0) + 1


print()
print("============================================================")
print(" SentinelSIEM — Alert Seeder Result")
print("============================================================")
print(f" Total Alerts : {total}")
print()

print(" Status:")
for key in sorted(statuses):
    print(f"   {key:<18} {statuses[key]}")

print()
print(" Severity:")
for key in sorted(severities):
    print(f"   {key:<18} {severities[key]}")

print()
print(" Rules:")
for key in sorted(rules):
    print(f"   {key:<32} {rules[key]}")

print()
print(" Assignees:")
if assignees:
    for key in sorted(assignees):
        print(f"   {key:<24} {assignees[key]}")
else:
    print("   none")

print()
print(" Sources:")
for key in sorted(sources):
    print(f"   {key:<18} {sources[key]}")

print("============================================================")
PY

printf "\n"

success "Alert seeding completed."
log "Open Alerts UI and refresh the page."
