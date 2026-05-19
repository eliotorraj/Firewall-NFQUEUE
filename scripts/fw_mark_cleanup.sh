#!/usr/bin/env bash
set -u

# Removes only the chains created by our mark scripts.
# It does not globally flush the mangle table, making it safer on a machine
# that may have other iptables rules unrelated to the project.

# Allows overrides, for example:
#   IPTABLES=iptables-legacy sudo ./scripts/fw_mark_cleanup.sh
IPTABLES=${IPTABLES:-iptables}

if [ "${EUID}" -ne 0 ]; then
    echo "Run as root: sudo ./scripts/fw_mark_cleanup.sh" >&2
    exit 1
fi

delete_jumps_to() {
    local chain=$1
    local target=$2
    local rules

    # A custom chain cannot be deleted while a built-in chain
    # jumps into it. Here we look for all rules like:
    #   -A OUTPUT ... -j FW_OUTPUT
    # and convert them into:
    #   -D OUTPUT ... -j FW_OUTPUT
    # Repeat in a loop to handle any duplicates.
    while true; do
        mapfile -t rules < <("$IPTABLES" -t mangle -S "$chain" 2>/dev/null | grep -- " -j $target")
        [ "${#rules[@]}" -eq 0 ] && break

        for rule in "${rules[@]}"; do
            # Here we deliberately expand the rule into iptables arguments.
            # shellcheck disable=SC2086
            "$IPTABLES" -t mangle ${rule/-A /-D }
        done
    done
}

# First detach the custom chains from the kernel entry points.
delete_jumps_to OUTPUT FW_OUTPUT
delete_jumps_to POSTROUTING FW_POSTROUTING

# Then flush and delete the chains. Errors are ignored to keep
# the script idempotent: it can be run even if the chains do not exist.
"$IPTABLES" -t mangle -F FW_OUTPUT 2>/dev/null || true
"$IPTABLES" -t mangle -F FW_POSTROUTING 2>/dev/null || true
"$IPTABLES" -t mangle -X FW_OUTPUT 2>/dev/null || true
"$IPTABLES" -t mangle -X FW_POSTROUTING 2>/dev/null || true

# Final state: if everything is clean, you should see only the built-in policies.
"$IPTABLES" -t mangle -S
