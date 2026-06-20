#!/usr/bin/env bash
set -eu

# Setup script for iptables rules using NFQUEUE together with marks.
#
# Desired flow:
# 1. OUTPUT intercepts only the selected test ports and jumps to FW_OUTPUT.
# 2. FW_OUTPUT restores any CONNMARK already saved on the flow.
# 3. If the mark is already PASS/DROP, decide immediately in the kernel.
# 4. If there is no mark, send the packet to NFQUEUE.
# 5. The C program returns NF_ACCEPT with FW_MARK_PASS=0x1 or FW_MARK_DROP=0x2.
# 6. FW_POSTROUTING saves the packet mark in CONNMARK and applies ACCEPT/DROP.
#
# If protocol, destination or port set changes between tests, run
# fw_mark_cleanup.sh first to remove old OUTPUT jumps.

# Allow using a different iptables binary if needed:
#   IPTABLES=iptables-legacy sudo ./scripts/fw_mark_setup.sh -p tcp 80 23
IPTABLES=${IPTABLES:-iptables}

# The queue must match the one created by nfq_create_queue(..., 0, ...).
QUEUE_NUM=${QUEUE_NUM:-0}

# Protocol and destination are configurable from the CLI.
PROTO=tcp
DST_IP=""

usage() {
    echo "Usage: sudo $0 [-p tcp|udp] [-d dst_ip] port [port...]" >&2
    echo "Examples:" >&2
    echo "  sudo $0 -p tcp -d 127.0.0.1 80 23" >&2
}

while getopts "p:d:h" opt; do
    case "$opt" in
        p)
            PROTO="$OPTARG"
            ;;
        d)
            DST_IP="$OPTARG"
            ;;
        h)
            usage
            exit 0
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

shift $((OPTIND - 1))
PORTS=("$@")

# Ports passed as arguments limit the traffic sent to NFQUEUE.
# No default ports are installed: the caller must choose the test.
if [ "$PROTO" != "tcp" ] && [ "$PROTO" != "udp" ]; then
    echo "Invalid protocol: $PROTO. Use tcp or udp." >&2
    exit 1
fi

if [ "${#PORTS[@]}" -eq 0 ]; then
    usage
    exit 1
fi

for port in "${PORTS[@]}"; do
    case "$port" in
        ''|*[!0-9]*)
            echo "Invalid port: $port" >&2
            exit 1
            ;;
    esac

    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo "Invalid port: $port" >&2
        exit 1
    fi
done

DST_ARGS=()
if [ -n "$DST_IP" ]; then
    DST_ARGS=(-d "$DST_IP")
fi

if [ "${EUID}" -ne 0 ]; then
    echo "Run as root: sudo $0 [-p tcp|udp] [-d dst_ip] port [port...]" >&2
    exit 1
fi

# Enable conntrack accounting if the kernel exposes it.
# This is not the mark mechanism itself, but makes conntrack entries easier to inspect.
if [ -e /proc/sys/net/netfilter/nf_conntrack_acct ]; then
    sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null || \
        echo "Warning: unable to enable nf_conntrack_acct; continuing." >&2
else
    echo "Warning: nf_conntrack_acct is not available; continuing without conntrack accounting." >&2
fi

# Create custom chains in the mangle table.
# If they already exist, do not fail: flush them immediately after.
"$IPTABLES" -t mangle -N FW_OUTPUT 2>/dev/null || true
"$IPTABLES" -t mangle -N FW_POSTROUTING 2>/dev/null || true
"$IPTABLES" -t mangle -F FW_OUTPUT
"$IPTABLES" -t mangle -F FW_POSTROUTING

# Hook OUTPUT to our chain only for the requested protocol/ports.
for port in "${PORTS[@]}"; do
    if ! "$IPTABLES" -t mangle -C OUTPUT -p "$PROTO" "${DST_ARGS[@]}" --dport "$port" -j FW_OUTPUT 2>/dev/null; then
        "$IPTABLES" -t mangle -I OUTPUT 1 -p "$PROTO" "${DST_ARGS[@]}" --dport "$port" -j FW_OUTPUT
    fi
done

# POSTROUTING is where the packet mark set by NFQUEUE is saved into CONNMARK
# and where the final verdict is applied.
if ! "$IPTABLES" -t mangle -C POSTROUTING -j FW_POSTROUTING 2>/dev/null; then
    "$IPTABLES" -t mangle -I POSTROUTING 1 -j FW_POSTROUTING
fi

# FW_OUTPUT: first try to restore an already saved decision.
"$IPTABLES" -t mangle -A FW_OUTPUT -j CONNMARK --restore-mark

# If restore-mark set 0x1, the flow was already allowed:
# skip NFQUEUE and accept immediately.
"$IPTABLES" -t mangle -A FW_OUTPUT -m mark --mark 0x1 -j ACCEPT

# If restore-mark set 0x2, the flow was already rejected:
# drop directly in the kernel.
"$IPTABLES" -t mangle -A FW_OUTPUT -m mark --mark 0x2 -j DROP

# If no cached decision exists, send the packet to userspace.
# --queue-bypass prevents freezes if ./firewall is not running: in that case
# the kernel lets the packet pass instead of waiting forever for a verdict.
"$IPTABLES" -t mangle -A FW_OUTPUT -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass

# FW_POSTROUTING: here the packet has returned from NFQUEUE with mark 0x1/0x2.
# Save the packet mark into CONNMARK so later packets from the same flow can be
# handled in FW_OUTPUT without returning to userspace.
"$IPTABLES" -t mangle -A FW_POSTROUTING -m mark ! --mark 0x0 -j CONNMARK --save-mark

# ACCEPT decisions return from NFQUEUE with mark 0x1.
# DROP decisions return from NFQUEUE with mark 0x2: they are saved and then dropped here.
"$IPTABLES" -t mangle -A FW_POSTROUTING -m mark --mark 0x2 -j DROP
"$IPTABLES" -t mangle -A FW_POSTROUTING -m mark --mark 0x1 -j ACCEPT

# Print rules and counters right after setup: useful for debugging.
"$(dirname "$0")/fw_mark_status.sh"
