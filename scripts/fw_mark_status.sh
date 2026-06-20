#!/usr/bin/env bash
set -u

# Print mangle table rules and counters.
# Use this script after each test to understand the flow:
# - FW_OUTPUT / NFQUEUE shows how many packets entered userspace.
# - FW_OUTPUT / mark 0x1 or 0x2 shows how many packets were handled
#   using a decision already saved in CONNMARK.
# - FW_POSTROUTING / CONNMARK save shows how many packet marks were
#   saved into conntrack entries.

IPTABLES=${IPTABLES:-iptables}

if [ "${EUID}" -ne 0 ]; then
    echo "Run as root: sudo ./scripts/fw_mark_status.sh" >&2
    exit 1
fi

echo "=== mangle rules ==="
# Compact form, useful to understand exactly how to recreate/remove rules.
"$IPTABLES" -t mangle -S

echo
echo "=== FW_OUTPUT counters ==="
# Counters for the chain where restore-mark and the optional NFQUEUE jump happen.
"$IPTABLES" -t mangle -L FW_OUTPUT -v -n --line-numbers 2>/dev/null || true

echo
echo "=== FW_POSTROUTING counters ==="
# Counters for the chain where marks are saved and the final verdict is applied.
"$IPTABLES" -t mangle -L FW_POSTROUTING -v -n --line-numbers 2>/dev/null || true
