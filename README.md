# Userspace Firewall with NFQUEUE

## Introduction

This project implements a userspace firewall in C for Linux systems, based on the Netfilter NFQUEUE subsystem.
Its goal is to intercept IP packets selected by the kernel, analyze them in userspace, and apply custom filtering policies.

In addition to traditional filtering, the firewall integrates two traffic analysis mechanisms:

* a rate limiting system based on the Leaky Bucket algorithm;
* an estimate of the number of distinct source IP addresses using HyperLogLog.

---

# System Architecture

The firewall is divided into the following main modules:

| Module         | Purpose                                          |
| -------------- | ------------------------------------------------ |
| `nfqueue_core` | NFQUEUE communication handling                   |
| `parser`       | Extraction of information from IPv4 packets      |
| `rules`        | Loading and checking firewall rules              |
| `decision`     | Firewall decision engine                         |
| `rate_limit`   | Traffic control through Leaky Bucket             |
| `hyperloglog`  | Estimation of distinct source IP addresses       |
| `logging`      | Recording of events and decisions                |

Processing flow:

1. The kernel forwards selected packets to an NFQUEUE queue.
2. The firewall receives the packet in userspace.
3. The parser extracts the relevant information:

   * source and destination IP addresses;
   * protocol;
   * TCP/UDP ports.
   
4. The decision engine:

   * updates HyperLogLog statistics;
   * checks traffic limits;
   * applies firewall rules;
   * produces the final verdict.
   
5. The result is returned to the kernel.

This structure makes the project easier to extend and keeps responsibilities clearly separated across modules.

---

# Using NFQUEUE

NFQUEUE is a Netfilter component that allows packets to be transferred from the kernel to userspace.
In this project it is used to delegate the final decision on intercepted packets to the userspace firewall.

The `iptables` rules send only the traffic of interest to queue `0`.

Example:

```bash
iptables -t mangle -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
```

This way, only TCP traffic destined for port 80 is analyzed by the firewall.

---

# Packet Parsing

The `parser` module analyzes IPv4 packets and supports the following protocols:

* TCP
* UDP
* ICMP

The extracted information is stored in the shared structure:

```
struct packet_info {
    char src_ip[16];
    char dst_ip[16];
    int src_port;
    int dst_port;
    int protocol;
};
```

During parsing, validity checks are performed on the IPv4 and TCP/UDP headers.
Malformed packets are discarded before reaching the decision engine.

---

# Rule Management

Firewall rules are defined in the `firewall.conf` file using this format:

```text
ACTION SRC_IP DST_IP SRC_PORT DST_PORT PROTOCOL
```

Example:

```text
DROP ANY ANY ANY 23 TCP
ALLOW ANY ANY ANY 80 TCP
```

Rules are evaluated sequentially.
The first matching rule determines the final decision.

Supported values:

* specific IPv4 addresses;
* wildcard `ANY`;
* TCP, UDP, and ICMP protocols.

---

# Rate Limiting with Leaky Bucket

To limit possible flood attacks, the project implements a rate limiting system based on the Leaky Bucket algorithm.

For each source IP address, the firewall keeps:

* the number of accumulated requests;
* the timestamp of the last update.

When traffic exceeds the configured threshold, the packet can be classified as suspicious and handled by the decision engine.

This approach makes it possible to limit anomalous traffic without immediately blocking legitimate connections.

---

# IP Estimation with HyperLogLog

The `hyperloglog` module is used to estimate the number of distinct source IP addresses observed by the firewall.

HyperLogLog is a probabilistic data structure that estimates cardinality while using little memory.

In this project:

* each source IP address is converted into a hash;
* the hash updates a specific register in the structure;
* the estimated cardinality is computed periodically by the decision engine.

This approach makes it possible to monitor traffic efficiently even with a large number of hosts.

---

# Packet Marks and CONNMARK

The firewall uses Netfilter packet marks to associate a decision with flows that have already been analyzed.

Two main marks are defined:

```text
FW_MARK_PASS = 0x1
FW_MARK_DROP = 0x2
```

The mechanism works as follows:

1. an unmarked packet enters NFQUEUE;
2. the firewall decides whether to allow or block the traffic;
3. the mark is saved in conntrack through `CONNMARK`;
4. subsequent packets from the same flow are handled directly by the kernel.

This mechanism reduces the number of packets sent to userspace and lowers the firewall's overall overhead.

---
## Requirements

On Ubuntu/WSL:

```bash
sudo apt update
sudo apt install build-essential libnetfilter-queue-dev iptables netcat-openbsd python3
```

---

# Build and Run

To build the project:

```bash
make firewall
```

The program must be run with root privileges:

```bash
sudo ./firewall
```

To intercept traffic, install the `iptables` rules provided by the project scripts.

Example:

```bash
sudo ./scripts/fw_mark_setup.sh 80 23
```

The script configures:

* NFQUEUE rules;
* packet marks and CONNMARK;
* the `mangle` chains required by the test.

To view rules and counters:

```bash
sudo ./scripts/fw_mark_status.sh
```

To remove all created rules:

```bash
sudo ./scripts/fw_mark_cleanup.sh
```

---

# Testing

The project includes an automated smoke test:

```bash
make firewall
sudo ./scripts/fw_mark_smoke_test.sh
```

The script:

1. starts the firewall;
2. automatically configures the `iptables` rules;
3. creates a local HTTP server on port 80;
4. generates real traffic toward ports 80 and 23;
5. verifies the firewall's expected behavior.

Specifically:

* HTTP traffic toward port 80 must be accepted;
* Telnet traffic toward port 23 must be blocked.

At the end, the script shows:

* firewall logs;
* rule counters;
* Netfilter mark status.

---

# Debug

To view the `mangle` rules:

```bash
sudo iptables -t mangle -S
```

To view chain counters:

```bash
sudo iptables -t mangle -L FW_OUTPUT -v -n --line-numbers
sudo iptables -t mangle -L FW_POSTROUTING -v -n --line-numbers
```
---

# Authors

* Federico Guastella
* Marco Tavani
* Elio Torraj
