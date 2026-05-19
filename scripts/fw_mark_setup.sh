#!/usr/bin/env bash
set -eu

# Setup script for iptables rules that use NFQUEUE together with marks.
#
# Desired flow:
# 1. OUTPUT intercepts only the test ports and jumps to FW_OUTPUT.
# 2. FW_OUTPUT restores any CONNMARK already saved on the flow.
# 3. If the mark is already PASS/DROP, the kernel decides immediately.
# 4. If there is no mark, the packet is sent to NFQUEUE.
# 5. The C program assigns FW_MARK_PASS=0x1 or FW_MARK_DROP=0x2.
# 6. POSTROUTING saves that packet mark into CONNMARK and applies ACCEPT/DROP.

# Allows a different iptables binary to be used, if needed:
#   IPTABLES=iptables-legacy sudo ./scripts/fw_mark_setup.sh
IPTABLES=${IPTABLES:-iptables}

# The queue must match the one created by nfq_create_queue(..., 0, ...).
QUEUE_NUM=${QUEUE_NUM:-0}

# In local tests, only loopback is intercepted. It can be changed with:
#   DST_IP=192.168.1.10 sudo ./scripts/fw_mark_setup.sh 80 23
DST_IP=${DST_IP:-127.0.0.1}

# Ports passed as arguments limit the traffic sent to NFQUEUE.
# Without arguments, the two useful project ports are used: HTTP and TELNET.
PORTS=("$@")

if [ "${EUID}" -ne 0 ]; then
    echo "Run as root: sudo ./scripts/fw_mark_setup.sh [ports...]" >&2
    exit 1
fi

if [ "${#PORTS[@]}" -eq 0 ]; then
    PORTS=(80 23)
fi

# Enables conntrack accounting as requested by the professor.
# This is not the mark mechanism itself, but it makes conntrack entries more observable.
sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null

# Create custom chains in the mangle table.
# If they already exist, do not fail: flush them immediately afterward to start clean.
"$IPTABLES" -t mangle -N FW_OUTPUT 2>/dev/null || true
"$IPTABLES" -t mangle -N FW_POSTROUTING 2>/dev/null || true
"$IPTABLES" -t mangle -F FW_OUTPUT
"$IPTABLES" -t mangle -F FW_POSTROUTING

# Attach OUTPUT to our chain only for the requested ports.
# This avoids the issue seen with VSCode/WSL: not all loopback TCP traffic
# is sent to NFQUEUE, only the traffic we want to test.
for port in "${PORTS[@]}"; do
    if ! "$IPTABLES" -t mangle -C OUTPUT -p tcp -d "$DST_IP" --dport "$port" -j FW_OUTPUT 2>/dev/null; then
        "$IPTABLES" -t mangle -I OUTPUT 1 -p tcp -d "$DST_IP" --dport "$port" -j FW_OUTPUT
    fi
done

# POSTROUTING is where the packet mark set by NFQUEUE is saved
# into the connection/flow CONNMARK.
if ! "$IPTABLES" -t mangle -C POSTROUTING -j FW_POSTROUTING 2>/dev/null; then
    "$IPTABLES" -t mangle -I POSTROUTING 1 -j FW_POSTROUTING
fi

# FW_OUTPUT: first try to restore an already saved decision.
"$IPTABLES" -t mangle -A FW_OUTPUT -j CONNMARK --restore-mark

# If restore-mark set 0x1, the flow had already been allowed:
# skip NFQUEUE and accept immediately.
"$IPTABLES" -t mangle -A FW_OUTPUT -m mark --mark 0x1 -j ACCEPT

# If restore-mark set 0x2, the flow had already been rejected:
# drop directly in the kernel.
"$IPTABLES" -t mangle -A FW_OUTPUT -m mark --mark 0x2 -j DROP

# If there was no cached decision, send the packet to userspace.
# --queue-bypass avoids freezes if ./firewall is not running: in that case
# the kernel lets the packet pass instead of waiting forever for a verdict.
"$IPTABLES" -t mangle -A FW_OUTPUT -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass

# FW_POSTROUTING: here the packet has returned from NFQUEUE with mark 0x1/0x2.
# Save the packet mark into CONNMARK, so subsequent packets from the same
# flow can be handled in FW_OUTPUT without returning to userspace.
"$IPTABLES" -t mangle -A FW_POSTROUTING -m mark ! --mark 0x0 -j CONNMARK --save-mark

# Apply the actual verdict after saving the mark.
# In the C code, DROP decisions also return as NF_ACCEPT + MARK_DROP specifically to get here.
"$IPTABLES" -t mangle -A FW_POSTROUTING -m mark --mark 0x2 -j DROP
"$IPTABLES" -t mangle -A FW_POSTROUTING -m mark --mark 0x1 -j ACCEPT

# Print rules and counters immediately after setup: useful for debugging.
"$(dirname "$0")/fw_mark_status.sh"
