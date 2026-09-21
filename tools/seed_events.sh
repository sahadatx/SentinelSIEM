#!/usr/bin/env bash

set -u

# ============================================================
# SentinelSIEM Event Seeder
# ============================================================

API_URL="${API_URL:-http://localhost:8001}"
COLLECTOR_HOST="${COLLECTOR_HOST:-127.0.0.1}"
COLLECTOR_PORT="${COLLECTOR_PORT:-1514}"
NC_TIMEOUT="${NC_TIMEOUT:-3}"

# ============================================================
# Helpers
# ============================================================

send_event() {
    local event="$1"

    printf '%s\n' "${event}" |
        timeout "${NC_TIMEOUT}" nc \
            "${COLLECTOR_HOST}" \
            "${COLLECTOR_PORT}" \
            >/dev/null 2>&1 || true
}

send_batch() {
    local name="$1"
    shift

    echo "[+] Sending ${name}..."

    local event

    for event in "$@"; do
        send_event "${event}"
    done
}

# ============================================================
# Linux Authentication Events
# ============================================================

LINUX_AUTH_EVENTS=(
    'Sep 07 10:00:01 sentinel sshd[1001]: Failed password for invalid user attacker from 10.10.10.20 port 45231 ssh2'
    'Sep 07 10:00:02 sentinel sshd[1002]: Failed password for root from 10.10.10.21 port 45232 ssh2'
    'Sep 07 10:00:03 sentinel sshd[1003]: Failed password for admin from 10.10.10.22 port 45233 ssh2'
    'Sep 07 10:00:04 sentinel sshd[1004]: Accepted password for sahadat from 10.10.10.10 port 45234 ssh2'
    'Sep 07 10:00:05 sentinel sshd[1005]: Accepted password for analyst from 10.10.10.11 port 45235 ssh2'
    'Sep 07 10:00:06 sentinel sshd[1006]: Invalid user hacker from 10.10.10.23 port 45236'
    'Sep 07 10:00:07 sentinel sshd[1007]: Invalid user scanner from 10.10.10.24 port 45237'
    'Sep 07 10:00:08 sentinel sshd[1008]: pam_unix(sshd:session): session opened for user sahadat'
    'Sep 07 10:00:09 sentinel sshd[1009]: pam_unix(sshd:session): session closed for user sahadat'
)

# ============================================================
# Generic Security Events
#
# Required fields:
#
#   action
#   outcome
#   severity
#   category
#
# Optional fields:
#
#   username
#   source_ip
#   destination_ip
#   source_port
#   destination_port
#   protocol
#   process
#   command
# ============================================================

GENERIC_SECURITY_EVENTS=(

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    'SECURITY_EVENT action=login outcome=success severity=info category=authentication username=admin source_ip=10.10.1.10 destination_ip=10.10.1.100 source_port=45100 destination_port=22 protocol=ssh process=sshd'

    'SECURITY_EVENT action=login outcome=failure severity=high category=authentication username=attacker source_ip=10.10.1.20 destination_ip=10.10.1.100 source_port=45101 destination_port=22 protocol=ssh process=sshd'

    'SECURITY_EVENT action=logout outcome=success severity=info category=authentication username=admin source_ip=10.10.1.10 destination_ip=10.10.1.100 protocol=ssh process=sshd'

    # --------------------------------------------------------
    # Authorization
    # --------------------------------------------------------

    'SECURITY_EVENT action=account_change outcome=allowed severity=medium category=authorization username=admin process=user-manager command=modify-account'

    'SECURITY_EVENT action=account_change outcome=denied severity=high category=authorization username=guest process=user-manager command=modify-account'

    'SECURITY_EVENT action=privilege_escalation outcome=blocked severity=critical category=authorization username=attacker process=sudo command=sudo-admin'

    # --------------------------------------------------------
    # File
    # --------------------------------------------------------

    'SECURITY_EVENT action=file_access outcome=allowed severity=low category=file username=analyst source_ip=10.10.2.10 process=cat command=cat-/etc/hosts'

    'SECURITY_EVENT action=file_access outcome=denied severity=medium category=file username=guest source_ip=10.10.2.11 process=cat command=cat-/etc/shadow'

    'SECURITY_EVENT action=file_modify outcome=success severity=medium category=file username=developer source_ip=10.10.2.12 process=vim command=modify-config'

    'SECURITY_EVENT action=file_modify outcome=error severity=high category=file username=service process=backup command=restore-file'

    # --------------------------------------------------------
    # Process
    # --------------------------------------------------------

    'SECURITY_EVENT action=process_start outcome=success severity=info category=process username=operator process=systemd command=start-nginx'

    'SECURITY_EVENT action=process_start outcome=blocked severity=high category=process username=malicious process=malware command=execute-payload'

    'SECURITY_EVENT action=process_stop outcome=success severity=low category=process username=operator process=systemctl command=stop-worker'

    'SECURITY_EVENT action=command_execution outcome=success severity=medium category=process username=developer process=bash command=deploy-app'

    'SECURITY_EVENT action=command_execution outcome=denied severity=high category=process username=guest process=bash command=rm-sensitive-data'

    # --------------------------------------------------------
    # Network
    # --------------------------------------------------------

    'SECURITY_EVENT action=network_connection outcome=allowed severity=info category=network username=service source_ip=10.10.3.10 destination_ip=8.8.8.8 source_port=50000 destination_port=53 protocol=udp process=resolver'

    'SECURITY_EVENT action=network_connection outcome=blocked severity=high category=network username=scanner source_ip=10.10.3.20 destination_ip=10.10.3.100 source_port=50001 destination_port=22 protocol=tcp process=nmap command=scan-ssh'

    'SECURITY_EVENT action=network_connection outcome=denied severity=medium category=network username=guest source_ip=10.10.3.21 destination_ip=10.10.3.100 source_port=50002 destination_port=443 protocol=tcp process=curl'

    # --------------------------------------------------------
    # Web
    # --------------------------------------------------------

    'SECURITY_EVENT action=login outcome=denied severity=medium category=web username=webuser source_ip=10.10.4.10 destination_ip=10.10.4.100 destination_port=443 protocol=https process=nginx command=web-login'

    'SECURITY_EVENT action=command_execution outcome=blocked severity=critical category=web username=hacker source_ip=10.10.4.20 destination_ip=10.10.4.100 destination_port=443 protocol=https process=nginx command=command-injection'

    # --------------------------------------------------------
    # System
    # --------------------------------------------------------

    'SECURITY_EVENT action=policy_change outcome=success severity=high category=system username=sysadmin process=policy-manager command=update-firewall-policy'

    'SECURITY_EVENT action=policy_change outcome=error severity=high category=system username=operator process=policy-manager command=reload-policy'

    # --------------------------------------------------------
    # Malware
    # --------------------------------------------------------

    'SECURITY_EVENT action=process_start outcome=blocked severity=critical category=malware username=malicious source_ip=10.10.5.10 process=trojan command=execute-trojan'

    'SECURITY_EVENT action=file_modify outcome=denied severity=critical category=malware username=malicious source_ip=10.10.5.11 process=ransomware command=encrypt-file'

    # --------------------------------------------------------
    # Cloud
    # --------------------------------------------------------

    'SECURITY_EVENT action=account_change outcome=allowed severity=medium category=cloud username=cloudadmin process=cloud-api command=create-user'

    'SECURITY_EVENT action=account_change outcome=denied severity=high category=cloud username=unknown process=cloud-api command=create-admin'

    # --------------------------------------------------------
    # Other
    # --------------------------------------------------------

    'SECURITY_EVENT action=policy_change outcome=unknown severity=low category=other username=monitoring process=security-agent command=policy-check'

    'SECURITY_EVENT action=network_connection outcome=error severity=medium category=other username=service process=network-agent command=connection-check'
)

# ============================================================
# Send Linux Authentication Events
# ============================================================

send_batch \
    "Linux authentication events" \
    "${LINUX_AUTH_EVENTS[@]}"

# ============================================================
# Send Generic Security Events
# ============================================================

send_batch \
    "generic security events" \
    "${GENERIC_SECURITY_EVENTS[@]}"

# ============================================================
# Allow:
#
# TCP Collector
#     ↓
# Redis
#     ↓
# Worker
#     ↓
# OpenSearch
#
# to settle before querying the API.
# ============================================================

echo
echo "[+] Waiting for ingestion pipeline..."

sleep 5

# ============================================================
# Filter Options
# ============================================================

echo
echo "============================================================"
echo "Event Filter Options"
echo "============================================================"

FILTER_RESPONSE="$(
    curl \
        --silent \
        --show-error \
        --fail \
        --connect-timeout 5 \
        --max-time 10 \
        "${API_URL}/api/v1/events/filter-options" \
        2>/dev/null
)" || FILTER_RESPONSE=""

if [[ -n "${FILTER_RESPONSE}" ]]; then

    printf '%s\n' "${FILTER_RESPONSE}" |
        python -c '
import json
import sys

data = json.load(sys.stdin)

for key in (
    "sources",
    "users",
    "actions",
    "outcomes",
    "severities",
    "categories",
):
    values = data.get(key, [])

    print(f"{key}:")

    for value in values:
        print(f"  - {value}")
'

else

    echo "[!] Could not retrieve filter options."
    echo "    Check that FastAPI is running on ${API_URL}"

fi

# ============================================================
# Event Statistics
# ============================================================

echo
echo "============================================================"
echo "Event Statistics"
echo "============================================================"

EVENT_RESPONSE="$(
    curl \
        --silent \
        --show-error \
        --fail \
        --connect-timeout 5 \
        --max-time 10 \
        "${API_URL}/api/v1/events?page=1&page_size=1" \
        2>/dev/null
)" || EVENT_RESPONSE=""

if [[ -n "${EVENT_RESPONSE}" ]]; then

    printf '%s\n' "${EVENT_RESPONSE}" |
        python -c '
import json
import sys

data = json.load(sys.stdin)

print("Total events:", data.get("total", 0))
print("Page size:   ", data.get("page_size", 0))
print("Page:        ", data.get("page", 0))
'

else

    echo "[!] Could not retrieve event statistics."
    echo "    Check that FastAPI is running on ${API_URL}"

fi

# ============================================================
# Complete
# ============================================================

echo
echo "============================================================"
echo "Seed Complete"
echo "============================================================"
echo
echo "Collector : ${COLLECTOR_HOST}:${COLLECTOR_PORT}"
echo "API       : ${API_URL}"
echo
