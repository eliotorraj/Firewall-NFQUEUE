#!/usr/bin/env bash
set -u

# Real smoke test for NFQUEUE + mark/CONNMARK.
#
# It does everything automatically:
# 1. cleans old project rules;
# 2. starts ./firewall in the background;
# 3. installs iptables rules limited to 127.0.0.1:80 and :23;
# 4. opens a local HTTP server on port 80;
# 5. generates real traffic toward 80 and 23;
# 6. prints logs and counters;
# 7. cleans processes and rules even on Ctrl+C/error.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1

# PIDs of temporary processes started by the script.
FW_PID=""
HTTP_PID=""

if [ "${EUID}" -ne 0 ]; then
    echo "Run as root: sudo ./scripts/fw_mark_smoke_test.sh" >&2
    exit 1
fi

if [ ! -x ./firewall ]; then
    echo "Missing ./firewall. Build it first with: make firewall" >&2
    exit 1
fi

if ! command -v nc >/dev/null 2>&1; then
    echo "nc not found. Install netcat before running this smoke test." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found. It is used only to open a local TCP/80 server." >&2
    exit 1
fi

cleanup() {
    set +e

    # First close the test HTTP server, if it started.
    if [ -n "$HTTP_PID" ]; then
        kill "$HTTP_PID" 2>/dev/null
        wait "$HTTP_PID" 2>/dev/null
    fi

    # Stop the firewall with SIGINT so it exits the loop and calls cleanup.
    if [ -n "$FW_PID" ]; then
        kill -INT "$FW_PID" 2>/dev/null
        wait "$FW_PID" 2>/dev/null
    fi

    # Always remove the iptables chains created for the test.
    ./scripts/fw_mark_cleanup.sh >/dev/null 2>&1
}

# Ensures cleanup on normal exit, error, Ctrl+C, or TERM.
trap cleanup EXIT INT TERM

# Test artifacts: process stdout/stderr and firewall logs.
mkdir -p build
rm -f firewall.log build/mark_*.out build/mark_*.err

# Start from a clean iptables state, even if a previous test was interrupted.
./scripts/fw_mark_cleanup.sh >/dev/null 2>&1

# Start the userspace firewall. It must stay alive while NFQUEUE is installed.
./firewall > build/mark_firewall.out 2> build/mark_firewall.err &
FW_PID=$!
sleep 1

# If the firewall exits immediately, permissions/queue/libnetfilter are probably missing.
if ! kill -0 "$FW_PID" 2>/dev/null; then
    echo "Firewall exited before the smoke test started." >&2
    cat build/mark_firewall.err >&2
    exit 1
fi

# Install rules to send only ports 80 and 23 to queue 0.
./scripts/fw_mark_setup.sh 80 23 > build/mark_setup.out

# Port 80: open a real server so the ACCEPT flow can complete.
# This helps observe CONNMARK reuse on subsequent packets.
python3 -m http.server 80 --bind 127.0.0.1 --directory . > build/mark_http.out 2> build/mark_http.err &
HTTP_PID=$!
sleep 1

if ! kill -0 "$HTTP_PID" 2>/dev/null; then
    echo "Local HTTP server on 127.0.0.1:80 failed to start." >&2
    cat build/mark_http.err >&2
    exit 1
fi

# Generate real traffic:
# - HTTP toward 80 must be RULE_ALLOW;
# - TCP connect toward 23 must be RULE_DROP.
printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | timeout 3 nc 127.0.0.1 80 >/dev/null 2>&1 || true
timeout 3 nc -zv 127.0.0.1 23 >/dev/null 2>&1 || true

# Give NFQUEUE/log/iptables counters time to update.
sleep 1

# Save mark state after the traffic.
./scripts/fw_mark_status.sh > build/mark_status.out

# Readable output for debugging.
echo "=== firewall output ==="
cat build/mark_firewall.out

echo
echo "=== firewall log ==="
cat firewall.log

echo
echo "=== mark counters ==="
cat build/mark_status.out

if ! grep -q "DPORT=80 PROTO=6 DECISION=ACCEPT REASON=RULE_ALLOW" firewall.log; then
    echo "Expected one TCP/80 RULE_ALLOW decision in firewall.log." >&2
    exit 1
fi

if ! grep -q "DPORT=23 PROTO=6 DECISION=DROP REASON=RULE_DROP" firewall.log; then
    echo "Expected one TCP/23 RULE_DROP decision in firewall.log." >&2
    exit 1
fi

# Note: on dropped SYN packets, some retransmissions may still re-enter
# NFQUEUE because the flow is not confirmed in conntrack.
# The most important behavior to observe is:
# - CONNMARK save > 0 in FW_POSTROUTING;
# - mark 0x1 ACCEPT in FW_OUTPUT for packets from the allowed flow.
echo
echo "Smoke test completed. Check FW_OUTPUT/FW_POSTROUTING counters above for mark reuse."
