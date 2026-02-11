#!/bin/sh
# =============================================================================
# Ironpost Demo - Normal Log Generator
# =============================================================================
# This script generates realistic normal system logs to demonstrate
# Ironpost's log collection and parsing capabilities.
#
# Usage:
#   ./generate-logs.sh [ironpost_host] [syslog_port]
#
# Requirements:
#   - Alpine/busybox compatible (uses 'sh' not 'bash')
#   - netcat (nc) for UDP syslog transmission

set -e

# Configuration
IRONPOST_HOST="${1:-ironpost}"
SYSLOG_PORT="${2:-1514}"
SLEEP_INTERVAL="${3:-5}"

echo "Starting Ironpost demo log generator..."
echo "Target: ${IRONPOST_HOST}:${SYSLOG_PORT}"
echo "Interval: ${SLEEP_INTERVAL} seconds"
echo ""

# Counter for sequence numbers
COUNTER=0

# Function to send syslog message
# Args: $1=priority, $2=hostname, $3=process, $4=message
send_log() {
    PRIORITY="$1"
    HOSTNAME="$2"
    PROCESS="$3"
    MESSAGE="$4"
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
    SYSLOG_MSG="<${PRIORITY}>1 ${TIMESTAMP} ${HOSTNAME} ${PROCESS} - - - ${MESSAGE}"

    echo "${SYSLOG_MSG}" | nc -u -w1 "${IRONPOST_HOST}" "${SYSLOG_PORT}"
}

# Main loop - generate various normal log patterns
while true; do
    COUNTER=$((COUNTER + 1))

    # Successful SSH login
    send_log 14 "webserver01" "sshd" "Accepted publickey for admin from 192.168.1.100 port 54321 ssh2"

    # Successful web request
    send_log 30 "webserver01" "nginx" "GET /index.html 200 1234 bytes sent to 192.168.1.200"

    # System service status
    send_log 38 "webserver01" "systemd" "Service nginx.service: status=running uptime=12h"

    # Cron job execution
    send_log 46 "webserver01" "cron" "Job completed successfully: /usr/local/bin/backup.sh"

    # Database query
    send_log 30 "dbserver01" "postgres" "Query executed in 45ms: SELECT * FROM users WHERE id=123"

    # User session
    send_log 38 "appserver01" "login" "User session started: user=alice tty=pts/0 from=192.168.1.150"

    # Firewall allow
    send_log 30 "gateway01" "iptables" "ACCEPT: IN=eth0 OUT=eth1 SRC=192.168.1.100 DST=10.0.0.50 PROTO=TCP DPT=443"

    # DNS query
    send_log 30 "gateway01" "dnsmasq" "query[A] api.example.com from 192.168.1.100"

    echo "[$(date -u +"%Y-%m-%d %H:%M:%S")] Batch #${COUNTER} sent (8 normal logs)"

    sleep "${SLEEP_INTERVAL}"
done
