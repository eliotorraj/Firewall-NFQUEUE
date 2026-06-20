# NFQUEUE Userspace Firewall

## Introduction

This project implements a userspace firewall based on Netfilter NFQUEUE. It combines classic packet filtering through NFQUEUE with data structures studied during the course, in particular Leaky Bucket and HyperLogLog.

The Leaky Bucket module provides a simple rate-limiting mechanism for source hosts that generate too many events in a short time window. Each source IP has an associated bucket. The bucket grows when packets from that source reach the decision engine and gradually leaks tokens over time. When the number of tokens exceeds the configured threshold, the traffic is considered excessive and the decision engine classifies the packet as `DROP`.

HyperLogLog is used as a lightweight monitoring structure to estimate the number of distinct source IP addresses observed by the firewall. This provides a compact indicator of possible distributed anomalies, such as floods coming from many different hosts, without storing the full list of observed IPs. HyperLogLog does not directly affect the `ACCEPT`/`DROP` decision: it is probabilistic, estimates cardinality, and does not identify the individual hosts involved. For this reason it is used for monitoring and logging only.

The firewall also uses Netfilter packet marks and `CONNMARK`. The userspace callback does not return `NF_DROP` directly. Instead, it always returns `NF_ACCEPT` and assigns a different packet mark depending on the logical decision:

- `FW_MARK_PASS` for packets classified as accepted;
- `FW_MARK_DROP` for packets classified as dropped.

Later, `iptables` rules in the `mangle` table use these marks to apply the final kernel-side `ACCEPT` or `DROP`. This design allows accepted flows to be cached through conntrack and avoids sending every packet of an already classified flow back to userspace.

For accepted flows, the packet continues through the network stack, conntrack confirms the connection, the `CONNMARK` is saved correctly, and later packets belonging to the same flow can bypass NFQUEUE. In this project, a flow is identified by the five-tuple:

```text
<source IP, destination IP, source port, destination port, protocol>
```

For flows classified as dropped, the packet receives the drop mark and the effective `DROP` is applied by `iptables` later in the kernel path. However, this behavior depends on the lifecycle of the conntrack entry. If the first packet of a flow is dropped before the connection is fully confirmed by the kernel, the related conntrack state may not become persistent. In that case, the mark is not necessarily reused by later packets of the same flow.

As a consequence, this implementation reliably caches accepted flows through `CONNMARK`, while drop-flow caching is more limited and depends on conntrack confirmation. A future version could improve the drop path by using a dedicated kernel deny cache, such as an `ipset` or an `nftables` set, updated by the userspace firewall after a drop decision.

---

## System Architecture

The firewall is split into the following modules:

| Module         | Responsibility                                      |
| -------------- | --------------------------------------------------- |
| `nfqueue_core` | Communication with NFQUEUE                          |
| `parser`       | Extraction of relevant fields from IPv4 packets     |
| `rules`        | Loading and matching firewall rules                 |
| `decision`     | Main firewall decision engine                       |
| `rate_limit`   | Leaky Bucket based traffic control                  |
| `hyperloglog`  | Estimation of distinct source IP addresses          |
| `logging`      | Event and decision logging through the decision code |

Packet processing flow:

1. The kernel forwards selected packets to NFQUEUE.
2. The firewall receives the packet in userspace.
3. The parser extracts the relevant fields:
   - source and destination IP;
   - protocol;
   - TCP/UDP ports.
4. The decision engine:
   - updates HyperLogLog statistics;
   - applies static firewall rules;
   - applies rate limiting where appropriate;
   - returns the logical decision.
5. The NFQUEUE callback sends the verdict and packet mark back to the kernel.
6. The kernel-side mark rules save the mark in `CONNMARK` and apply the final action.

This modular structure makes the project easier to extend and keeps responsibilities separated.

---

## NFQUEUE Usage

NFQUEUE is a Netfilter component that transfers selected packets from kernel space to userspace.

In this project, `iptables` rules send only the traffic of interest to queue `0`. The rules should not be added manually: `fw_mark_setup.sh` installs the NFQUEUE rules and the required `mangle` chains for packet marks and `CONNMARK`.

Example: intercept local TCP traffic to port 80:

```bash
sudo ./scripts/fw_mark_setup.sh -p tcp -d 127.0.0.1 80
```

Only the selected traffic is analyzed by the firewall; all other traffic follows the normal kernel path.

---

## Packet Parsing

The `parser` module handles IPv4 packets and extracts:

- source IP;
- destination IP;
- protocol;
- source port and destination port for TCP/UDP.

Supported protocols:

- TCP;
- UDP;
- ICMP.

The shared packet representation is:

```c
typedef struct {
    char src_ip[16];
    char dst_ip[16];
    int src_port;
    int dst_port;
    int protocol;
} packet_t;
```

The parser validates the IPv4 header and the minimum TCP/UDP header length. IPv6 is not supported. If parsing fails, the current `handle_packet()` implementation uses a fail-open behavior and accepts the packet, avoiding accidental traffic loss in this educational prototype. A stricter firewall could instead drop malformed or unsupported packets.

---

## Firewall Rules

Firewall rules are defined in `firewall.conf` with the following format:

```text
ACTION SRC_IP DST_IP SRC_PORT DST_PORT PROTOCOL
```

Example:

```text
DROP ANY ANY ANY 23 TCP
ALLOW ANY ANY ANY 80 TCP
```

Rules are evaluated sequentially. The first matching rule determines the action.

Supported fields:

- specific IPv4 addresses;
- `ANY` wildcard;
- TCP, UDP and ICMP protocols;
- TCP/UDP ports or `ANY`.

---

## Rate Limiting With Leaky Bucket

The project implements a simple Leaky Bucket rate limiter.

For each source IP, the firewall stores:

- the current token count;
- the last update timestamp.

Each event observed by the decision engine adds one token to the source IP bucket. Time removes tokens according to the configured leak rate. If the bucket exceeds the configured threshold, the packet is classified as excessive and dropped by the decision engine.

Configuration values are currently compile-time constants in `include/rate_limit.h`:

- `RATE_LIMIT_MAX_TOKENS`;
- `RATE_LIMIT_LEAK_RATE`;
- `MAX_BUCKETS`.

Because accepted flows can be cached by `CONNMARK`, later packets from an already accepted flow usually do not return to userspace. In that case, the rate limiter approximates a limit on new flow attempts per source IP. Dropped flows are less efficient because a first-packet drop may not create a persistent conntrack entry, so retransmissions can still reach the decision engine.

---

## Source IP Estimation With HyperLogLog

The `hyperloglog` module estimates the number of distinct source IP addresses observed by the firewall.

HyperLogLog is a probabilistic data structure that estimates cardinality using fixed, compact memory.

In this project:

- each source IP is converted into a hash;
- the hash selects and updates one HLL register;
- the estimated cardinality is periodically computed by the decision engine and written to `firewall.log`.

Configuration values are compile-time constants in `include/hyperloglog.h`:

- `HLL_P`, the number of bits used to select a register;
- `HLL_M`, the number of registers.

The current implementation uses one global HLL. It is useful for global monitoring, but it does not identify which internal host is receiving traffic from many sources. A more advanced design could maintain one HLL per protected destination IP and apply a time window.

---

## Packet Mark And CONNMARK

The firewall uses Netfilter packet marks to attach the userspace decision to the current packet and, when possible, to the related conntrack flow.

Defined marks:

```text
FW_MARK_PASS = 0x1
FW_MARK_DROP = 0x2
```

Flow:

1. `FW_OUTPUT` tries to restore a previously saved decision with `CONNMARK --restore-mark`.
2. If the restored mark is `0x1`, the packet is accepted directly by the kernel.
3. If the restored mark is `0x2`, the packet is dropped directly by the kernel.
4. If no cached decision exists, the packet is sent to NFQUEUE.
5. The userspace firewall returns `NF_ACCEPT` with packet mark `0x1` or `0x2`.
6. `FW_POSTROUTING` saves the packet mark with `CONNMARK --save-mark` and applies the final `ACCEPT` or `DROP`.

This mechanism reduces userspace overhead for flows that conntrack can reliably associate with a previous decision.

When UDP traffic is blocked, it is normal to see multiple log lines even if packets are correctly dropped. The client can generate retransmissions or new queries with different source ports, and UDP does not have a persistent connection lifecycle like TCP. To verify blocking behavior, check both the client result, such as a timeout, and the `FW_POSTROUTING` counters for the `mark 0x2 DROP` rule.

---

## Requirements

On Ubuntu/WSL:

```bash
sudo apt update
sudo apt install build-essential libnetfilter-queue-dev iptables netcat-openbsd python3
```

---

## Build And Run

Build the firewall:

```bash
make firewall
```

After building, two components are required:

1. the userspace firewall process;
2. the `iptables` rules that decide which packets are sent to NFQUEUE.

Use two terminals.

Terminal 1, userspace firewall:

```bash
sudo ./firewall firewall.conf
```

Terminal 2, Netfilter rules:

```bash
sudo ./scripts/fw_mark_cleanup.sh
sudo ./scripts/fw_mark_setup.sh -p <protocol> -d <dst_ip> [ports...]
```

The setup script requires at least one port. It does not install default ports. Protocol and destination can be selected for each test.

Example:

```bash
sudo ./scripts/fw_mark_setup.sh -p tcp -d 127.0.0.1 80 23 443
```

Before changing protocol, destination or port set, run `fw_mark_cleanup.sh` to remove previous jumps.

The setup script configures:

- NFQUEUE rules;
- packet marks and `CONNMARK`;
- required `mangle` chains.

Show rules and counters:

```bash
sudo ./scripts/fw_mark_status.sh
```

Remove all rules created by the scripts:

```bash
sudo ./scripts/fw_mark_cleanup.sh
```

---

## Testing

The project includes an automated smoke test:

```bash
make firewall
sudo ./scripts/fw_mark_smoke_test.sh
```

The script:

1. starts the firewall;
2. configures the `iptables` rules;
3. starts a local HTTP server on port 80;
4. generates real traffic to ports 80 and 23;
5. verifies the expected firewall behavior.

Expected behavior:

- HTTP traffic to port 80 must be accepted;
- Telnet-like traffic to port 23 must be blocked.

At the end, the script prints:

- firewall logs;
- rule counters;
- Netfilter mark state.

The smoke test can take a few seconds because the port 23 check generates a TCP attempt that is dropped. The kernel may retransmit a few SYN packets before the attempt times out, so seeing multiple `DROP` log lines with the same source port is normal.

---

## Recommended Tests

### TCP ACCEPT Test With Mark Reuse

This test verifies that allowed TCP traffic is analyzed in userspace at the beginning of the connection and that later packets can be handled by the kernel through `CONNMARK`.

Terminal 1:

```bash
make firewall
sudo ./firewall firewall.conf
```

Terminal 2:

```bash
sudo ./scripts/fw_mark_cleanup.sh
sudo ./scripts/fw_mark_setup.sh -p tcp -d 127.0.0.1 80
sudo python3 -m http.server 80 --bind 127.0.0.1
```

Terminal 3:

```bash
curl http://127.0.0.1/
curl http://127.0.0.1/
curl http://127.0.0.1/
sudo ./scripts/fw_mark_status.sh
```

Expected result:

- all `curl` commands receive an HTTP response;
- `firewall.log` contains `ACCEPT` decisions for TCP traffic to port 80;
- `FW_OUTPUT / NFQUEUE` increases for the first packets analyzed in userspace;
- `FW_OUTPUT / mark 0x1 ACCEPT` increases, showing kernel-side accepted packets;
- `FW_POSTROUTING / mark 0x1 ACCEPT` increases, showing that the `PASS` mark was applied and saved.

### UDP DROP Test

This test verifies that UDP traffic blocked by the rules is marked with `FW_MARK_DROP` and dropped in `FW_POSTROUTING`.

Terminal 1:

```bash
make firewall
sudo ./firewall firewall.conf
```

Terminal 2:

```bash
sudo ./scripts/fw_mark_cleanup.sh
sudo ./scripts/fw_mark_setup.sh -p udp -d <dns_server_ip> 53
host <domain> <dns_server_ip>
sudo ./scripts/fw_mark_status.sh
```

Expected result:

- `host` times out or receives no answer;
- `firewall.log` contains `DROP` decisions for UDP packets to port 53;
- `FW_POSTROUTING / mark 0x2 DROP` increases, showing that packets marked as dropped were discarded by the kernel.

With UDP, multiple log lines are normal: the client can generate retransmissions or new queries with different source ports. This does not mean that packets were accepted. The important checks are the client-side timeout and the `mark 0x2 DROP` counters.

---

## Debug

Show `mangle` rules:

```bash
sudo iptables -t mangle -S
```

Show chain counters:

```bash
sudo iptables -t mangle -L FW_OUTPUT -v -n --line-numbers
sudo iptables -t mangle -L FW_POSTROUTING -v -n --line-numbers
```

---

## Authors

- Federico Guastella
- Marco Tavani
- Elio Torraj
