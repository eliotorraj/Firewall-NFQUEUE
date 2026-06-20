#!/usr/bin/env bash
set -u

# Real smoke test for NFQUEUE + mark/CONNMARK.
#
# It automates the full flow:
# 1. clean old project rules;
# 2. start ./firewall in the background;
# 3. install TCP iptables rules limited to 127.0.0.1:80 and :23;
# 4. open a local HTTP server on port 80;
# 5. generate real traffic to ports 80 and 23;
# 6. print logs and counters;
# 7. clean processes and rules even on Ctrl+C/error.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1

# PIDs of temporary processes started by the script.
FW_PID=""
HTTP_PID=""
CLEANUP_DONE=0

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

stop_process() {
    pid="$1"
    first_signal="$2"

    if [ -z "$pid" ]; then
        return 0
    fi

    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null
        return 0
    fi

    kill "-$first_signal" "$pid" 2>/dev/null

    for _ in 1 2 3 4 5; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null
            return 0
        fi
        sleep 0.1
    done

    kill -TERM "$pid" 2>/dev/null

    for _ in 1 2 3 4 5; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null
            return 0
        fi
        sleep 0.1
    done

    kill -KILL "$pid" 2>/dev/null
}

cleanup() {
    set +e

    if [ "$CLEANUP_DONE" -eq 1 ]; then
        return
    fi
    CLEANUP_DONE=1
    trap - EXIT INT TERM

    # Stop the test HTTP server first, if it was started.
    stop_process "$HTTP_PID" TERM

    # Stop the firewall with SIGINT; force exit if it remains blocked in recv().
    stop_process "$FW_PID" INT

    # Always remove iptables chains created for the test.
    ./scripts/fw_mark_cleanup.sh >/dev/null 2>&1
}

# Guarantee cleanup on normal exit, error, Ctrl+C or TERM.
trap cleanup EXIT INT TERM

# Test artifacts: process stdout/stderr and firewall log.
mkdir -p build
rm -f firewall.log build/mark_*.out build/mark_*.err

# Start from a clean iptables state, even if a previous test was interrupted.
./scripts/fw_mark_cleanup.sh >/dev/null 2>&1

# Start the userspace firewall. It must stay alive while NFQUEUE is installed.
./firewall firewall.conf > build/mark_firewall.out 2> build/mark_firewall.err &
FW_PID=$!
sleep 1

# If the firewall exits immediately, permissions/queue/libnetfilter may be missing.
if ! kill -0 "$FW_PID" 2>/dev/null; then
    echo "Firewall exited before the smoke test started." >&2
    cat build/mark_firewall.err >&2
    exit 1
fi

# Install rules that send only TCP/80 and TCP/23 to queue 0.
./scripts/fw_mark_setup.sh -p tcp -d 127.0.0.1 80 23 > build/mark_setup.out

# Port 80: open a real server so the ACCEPT flow can complete.
# This helps show CONNMARK reuse on later packets.
python3 -m http.server 80 --bind 127.0.0.1 --directory . > build/mark_http.out 2> build/mark_http.err &
HTTP_PID=$!
sleep 1

if ! kill -0 "$HTTP_PID" 2>/dev/null; then
    echo "Local HTTP server on 127.0.0.1:80 failed to start." >&2
    cat build/mark_http.err >&2
    exit 1
fi

# Generate real traffic:
# - HTTP to 80 must be RULE_ALLOW;
# - TCP connect to 23 must be RULE_DROP.
printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | timeout 3 nc 127.0.0.1 80 >/dev/null 2>&1 || true
timeout 1 nc -zv 127.0.0.1 23 >/dev/null 2>&1 || true

# Give NFQUEUE/log/iptables counters time to update.
sleep 1

# Save mark state after traffic generation.
./scripts/fw_mark_status.sh > build/mark_status.out

# Readable debug output.
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

# Note: for dropped SYN packets, some retransmissions may still re-enter
# NFQUEUE because the flow is not confirmed in conntrack.
# The most important behavior to observe is:
# - CONNMARK save > 0 in FW_POSTROUTING;
# - mark 0x1 ACCEPT in FW_OUTPUT for packets of the allowed flow.
echo
echo "Smoke test completed. Check FW_OUTPUT/FW_POSTROUTING counters above for mark reuse."
