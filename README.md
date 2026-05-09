# NFQUEUE Userspace Firewall

Firewall userspace in C basato su NFQUEUE. Il programma riceve pacchetti dal kernel, li parsa, applica regole statiche caricate da file, aggiorna HyperLogLog, controlla il rate limit con Leaky Bucket e restituisce un verdict tramite NFQUEUE.

Il progetto usa anche i packet mark e `CONNMARK` per salvare la decisione sui flussi gestiti dal kernel.

## Requisiti

Su Ubuntu/WSL:

```bash
sudo apt update
sudo apt install build-essential libnetfilter-queue-dev iptables netcat-openbsd python3
```

Il firewall deve essere eseguito con privilegi root per aprire NFQUEUE:

```bash
sudo ./firewall
```

## Build

```bash
cd ~/NFQUEUE_UserSpace_Firewall
make firewall
```

Il binario generato e' `./firewall`.

## Configurazione Regole

Le regole statiche sono in [firewall.conf](firewall.conf).

Formato:

```text
ACTION SRC_IP DST_IP SRC_PORT DST_PORT PROTOCOL
```

Valori supportati:

```text
ACTION:   ALLOW, DROP
IP:       IPv4 oppure ANY
PORT:     0-65535 oppure ANY
PROTOCOL: TCP, UDP, ICMP oppure ANY
```

Esempio:

```text
DROP 192.168.1.100 ANY ANY ANY ANY
DROP ANY ANY ANY 23 TCP
DROP ANY ANY ANY ANY UDP
ALLOW ANY ANY ANY 80 TCP
```

Le regole vengono valutate in ordine: la prima regola che matcha decide. Per questo i `DROP` piu' specifici devono stare prima degli `ALLOW` generici.

## Test Automatici

```bash
make test
```

I test controllano:

- parsing pacchetti IPv4/TCP
- rigetto di pacchetti malformati
- caricamento regole da `firewall.conf`
- priorita' dei `DROP`
- default policy
- rate limit
- HyperLogLog
- integrazione `main -> parser -> decision engine`

Risultato atteso:

```text
Assertions: 268
Result: PASSED
```

## Avvio Naturale Del Firewall

Terminale 1:

```bash
cd ~/NFQUEUE_UserSpace_Firewall
make firewall
sudo ./firewall
```

Terminale 2, abilita le regole iptables con mark/CONNMARK:

```bash
cd ~/NFQUEUE_UserSpace_Firewall
sudo ./scripts/fw_mark_setup.sh 80 23
```

Questo manda a NFQUEUE solo il traffico TCP verso `127.0.0.1` sulle porte `80` e `23`.

Per vedere regole e contatori:

```bash
sudo ./scripts/fw_mark_status.sh
```

Per rimuovere tutte le regole create dagli script:

```bash
sudo ./scripts/fw_mark_cleanup.sh
```

## Smoke Test Reale

Lo smoke test avvia il firewall, configura iptables, apre un server locale su porta `80`, genera traffico reale su `80` e `23`, stampa log e contatori, poi pulisce tutto.

```bash
make firewall
sudo ./scripts/fw_mark_smoke_test.sh
```

Nel log dovresti vedere almeno:

```text
DPORT=80 PROTO=6 DECISION=ACCEPT REASON=RULE_ALLOW
DPORT=23 PROTO=6 DECISION=DROP REASON=RULE_DROP
```

Nota: sui SYN droppati verso porta `23`, alcune ritrasmissioni possono comunque tornare in NFQUEUE perche' il flusso TCP non viene confermato in conntrack. Per i flussi accettati, invece, il riuso del `CONNMARK` e' visibile nei contatori.

## Packet Mark E CONNMARK

Il codice usa:

```text
FW_MARK_PASS = 0x1
FW_MARK_DROP = 0x2
```

Il flusso e':

```text
OUTPUT -> FW_OUTPUT
FW_OUTPUT -> CONNMARK --restore-mark
mark 0x1 -> ACCEPT
mark 0x2 -> DROP
nessun mark -> NFQUEUE
NFQUEUE/userspace -> nfq_set_verdict2(..., mark)
POSTROUTING -> CONNMARK --save-mark
mark 0x2 -> DROP
mark 0x1 -> ACCEPT
```

Il programma C non usa `NF_DROP` diretto per i pacchetti droppati logicamente. Restituisce `NF_ACCEPT` con `FW_MARK_DROP`, cosi' iptables puo' salvare il mark nel conntrack e poi droppare il pacchetto.

## Debug Rapido

Vedere regole mangle:

```bash
sudo iptables -t mangle -S
```

Vedere contatori:

```bash
sudo iptables -t mangle -L FW_OUTPUT -v -n --line-numbers
sudo iptables -t mangle -L FW_POSTROUTING -v -n --line-numbers
```

Pulizia completa delle regole del progetto:

```bash
sudo ./scripts/fw_mark_cleanup.sh
```

Se la shell si blocca dopo una regola NFQUEUE, apri un nuovo terminale e pulisci:

```bash
wsl -d Ubuntu --user root -- bash -lc "cd /home/elioe/NFQUEUE_UserSpace_Firewall && ./scripts/fw_mark_cleanup.sh"
```

## File Principali

```text
src/main.c             avvio, caricamento regole, init NFQUEUE
src/nfqueue_core.c     callback NFQUEUE, verdict e packet mark
src/parser.c           parser IPv4/TCP/UDP/ICMP
src/decision.c         workflow HLL -> regole -> rate limit -> default policy
src/rules.c            caricamento e matching regole da firewall.conf
src/rate_limit.c       Leaky Bucket per IP sorgente
src/hyperloglog.c      stima IP sorgenti unici
scripts/               setup/status/cleanup/smoke test iptables mark
tests/test_firewall.c  test automatici
```
