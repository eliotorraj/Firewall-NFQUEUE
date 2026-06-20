#!/usr/bin/env bash
set -u

# Remove only the chains created by the project mark scripts.
# Do not flush the whole mangle table: this is safer on machines that may have
# unrelated iptables rules.

# Allow overriding the iptables binary, for example:
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

    # A custom chain cannot be deleted while a built-in chain jumps to it.
    # Here we find rules such as:
    #   -A OUTPUT ... -j FW_OUTPUT
    # and convert them into:
    #   -D OUTPUT ... -j FW_OUTPUT
    # Repeat in a loop to handle possible duplicates.
    while true; do
        mapfile -t rules < <("$IPTABLES" -t mangle -S "$chain" 2>/dev/null | grep -- " -j $target")
        [ "${#rules[@]}" -eq 0 ] && break

        for rule in "${rules[@]}"; do
            # Intentionally expand the rule into iptables arguments here.
            # shellcheck disable=SC2086
            if ! "$IPTABLES" -t mangle ${rule/-A /-D }; then
                echo "Warning: unable to delete rule: $rule" >&2
                return 1
            fi
        done
    done
}

# First disconnect custom chains from kernel entry points.
delete_jumps_to OUTPUT FW_OUTPUT
delete_jumps_to POSTROUTING FW_POSTROUTING

# Then flush and delete the chains. Errors are ignored to keep the script
# idempotent: it can be run even if the chains do not exist.
"$IPTABLES" -t mangle -F FW_OUTPUT 2>/dev/null || true
"$IPTABLES" -t mangle -F FW_POSTROUTING 2>/dev/null || true
"$IPTABLES" -t mangle -X FW_OUTPUT 2>/dev/null || true
"$IPTABLES" -t mangle -X FW_POSTROUTING 2>/dev/null || true

# Final state: if cleanup succeeded, only built-in policies should remain.
"$IPTABLES" -t mangle -S
