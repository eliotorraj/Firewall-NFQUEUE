#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decision.h"
#include "hyperloglog.h"
#include "nfqueue_core.h"
#include "parser.h"

int firewall_main(void);

static int failures = 0;
static int assertions = 0;

static packet_handler_cb captured_cb = NULL;
static int captured_verdicts[16];
static int captured_count = 0;

static void expect_true(int condition, const char *test, const char *message)
{
    assertions++;
    if (!condition) {
        failures++;
        printf("[FAIL] %s: %s\n", test, message);
    }
}

static void expect_int_eq(int actual, int expected, const char *test, const char *message)
{
    assertions++;
    if (actual != expected) {
        failures++;
        printf("[FAIL] %s: %s (expected=%d actual=%d)\n",
               test, message, expected, actual);
    }
}

static void expect_str_eq(const char *actual, const char *expected, const char *test, const char *message)
{
    assertions++;
    if (strcmp(actual, expected) != 0) {
        failures++;
        printf("[FAIL] %s: %s (expected=%s actual=%s)\n",
               test, message, expected, actual);
    }
}

static size_t build_ipv4_packet(uint8_t *buf,
                                size_t cap,
                                const char *src_ip,
                                const char *dst_ip,
                                uint8_t protocol,
                                uint16_t src_port,
                                uint16_t dst_port,
                                uint8_t ihl_words)
{
    size_t ip_header_len = (size_t)ihl_words * 4u;
    size_t transport_len = (protocol == 6 || protocol == 17) ? 4u : 0u;
    size_t total_len = ip_header_len + transport_len;
    uint16_t net_total_len;
    uint16_t net_src_port;
    uint16_t net_dst_port;

    if (cap < total_len || ihl_words > 15) {
        return 0;
    }

    memset(buf, 0, cap);
    buf[0] = (uint8_t)((4u << 4) | ihl_words);
    net_total_len = htons((uint16_t)total_len);
    memcpy(buf + 2, &net_total_len, sizeof(net_total_len));
    buf[8] = 64;
    buf[9] = protocol;

    if (inet_pton(AF_INET, src_ip, buf + 12) != 1) {
        return 0;
    }
    if (inet_pton(AF_INET, dst_ip, buf + 16) != 1) {
        return 0;
    }

    if (protocol == 6 || protocol == 17) {
        net_src_port = htons(src_port);
        net_dst_port = htons(dst_port);
        memcpy(buf + ip_header_len, &net_src_port, sizeof(net_src_port));
        memcpy(buf + ip_header_len + 2, &net_dst_port, sizeof(net_dst_port));
    }

    return total_len;
}

int nfqueue_init(packet_handler_cb cb)
{
    captured_cb = cb;
    return 0;
}

void nfqueue_run(void)
{
    uint8_t packet[64];
    size_t len;

    if (!captured_cb) {
        return;
    }

    len = build_ipv4_packet(packet, sizeof(packet),
                            "10.0.0.10", "10.0.0.1", 6, 41234, 80, 5);
    captured_verdicts[captured_count++] = captured_cb(packet, (int)len);
}

void nfqueue_cleanup(void)
{
}

static packet_t make_packet(const char *src_ip, const char *dst_ip, int protocol, int src_port, int dst_port)
{
    packet_t pkt;

    memset(&pkt, 0, sizeof(pkt));
    snprintf(pkt.src_ip, sizeof(pkt.src_ip), "%s", src_ip);
    snprintf(pkt.dst_ip, sizeof(pkt.dst_ip), "%s", dst_ip);
    pkt.protocol = protocol;
    pkt.src_port = src_port;
    pkt.dst_port = dst_port;

    return pkt;
}

static void reset_decision_state(const char *config_file)
{
    decision_cleanup();
    remove("firewall.log");
    expect_int_eq(rules_init(config_file), RULES_OK, "test setup", "rules_init should load config");
    decision_init();
}

static void finish_decision_state(void)
{
    decision_cleanup();
    remove("firewall.log");
}

static void write_invalid_config(void)
{
    FILE *fp = fopen("build/invalid_rules.conf", "w");

    if (!fp) {
        perror("build/invalid_rules.conf");
        exit(2);
    }

    fprintf(fp, "# valid rule\n");
    fprintf(fp, "ALLOW ANY ANY ANY 80 TCP\n");
    fprintf(fp, "# invalid broad allow: must not become ANY\n");
    fprintf(fp, "ALLOW ANY ANY ANY ANY SCTP\n");
    fprintf(fp, "# invalid port: must be skipped\n");
    fprintf(fp, "ALLOW ANY ANY ANY notaport TCP\n");
    fprintf(fp, "# valid drop\n");
    fprintf(fp, "DROP ANY ANY ANY 23 TCP\n");
    fclose(fp);
}

static void test_main_uses_config_and_decision_engine(void)
{
    const char *test = "main uses config and decision engine";
    int before = failures;

    captured_cb = NULL;
    captured_count = 0;
    remove("firewall.log");

    expect_int_eq(firewall_main(), 0, test, "firewall_main should exit cleanly with fake NFQUEUE");
    expect_int_eq(captured_count, 1, test, "fake NFQUEUE should inject one HTTP packet");
    if (captured_count == 1) {
        expect_int_eq(captured_verdicts[0], DECISION_ACCEPT, test,
                      "TCP/80 must be accepted by firewall.conf RULE_ALLOW");
    }

    finish_decision_state();

    if (failures == before) {
        printf("[PASS] %s\n", test);
    }
}

static void test_parser_valid_tcp_packet(void)
{
    const char *test = "parser extracts IPv4 TCP fields";
    int before = failures;
    uint8_t packet[64];
    packet_t parsed;
    size_t len = build_ipv4_packet(packet, sizeof(packet),
                                   "10.1.2.3", "10.9.8.7", 6, 12345, 443, 5);

    expect_true(len > 0, test, "packet builder should produce a TCP packet");
    expect_int_eq(parse_packet(packet, (int)len, &parsed), 1, test, "valid TCP packet should parse");
    expect_str_eq(parsed.src_ip, "10.1.2.3", test, "source IP should be parsed");
    expect_str_eq(parsed.dst_ip, "10.9.8.7", test, "destination IP should be parsed");
    expect_int_eq(parsed.protocol, 6, test, "protocol should be TCP");
    expect_int_eq(parsed.src_port, 12345, test, "source port should be parsed");
    expect_int_eq(parsed.dst_port, 443, test, "destination port should be parsed");

    if (failures == before) {
        printf("[PASS] %s\n", test);
    }
}

static void test_parser_rejects_malformed_packets(void)
{
    const char *test = "parser rejects malformed packets";
    int before = failures;
    uint8_t packet[64];
    packet_t parsed;
    size_t len;
    uint16_t bad_total_len;

    len = build_ipv4_packet(packet, sizeof(packet), "10.0.0.1", "10.0.0.2", 6, 1000, 80, 5);
    expect_int_eq(parse_packet(packet, 22, &parsed), 0, test, "truncated TCP header should fail");

    len = build_ipv4_packet(packet, sizeof(packet), "10.0.0.1", "10.0.0.2", 6, 1000, 80, 4);
    expect_true(len > 0, test, "builder should still produce the malformed IHL packet");
    expect_int_eq(parse_packet(packet, (int)len, &parsed), 0, test, "IHL smaller than 5 should fail");

    len = build_ipv4_packet(packet, sizeof(packet), "10.0.0.1", "10.0.0.2", 6, 1000, 80, 5);
    bad_total_len = htons(16);
    memcpy(packet + 2, &bad_total_len, sizeof(bad_total_len));
    expect_int_eq(parse_packet(packet, (int)len, &parsed), 0, test,
                  "IP total length smaller than header length should fail");

    expect_int_eq(parse_packet(NULL, (int)len, &parsed), 0, test, "NULL data should fail");
    expect_int_eq(parse_packet(packet, (int)len, NULL), 0, test, "NULL output packet should fail");
    expect_int_eq(parse_packet(packet, -1, &parsed), 0, test, "negative packet length should fail");

    if (failures == before) {
        printf("[PASS] %s\n", test);
    }
}

static void test_decision_static_rules_and_default_policy(void)
{
    const char *test = "decision applies config rules and default policy";
    int before = failures;
    decision_result_t res;
    packet_t http;
    packet_t telnet;
    packet_t udp;
    packet_t https;
    packet_t blocked_http;

    reset_decision_state("firewall.conf");

    http = make_packet("10.0.0.20", "10.0.0.1", 6, 50000, 80);
    res = decide(&http);
    expect_int_eq(res.decision, DECISION_ACCEPT, test, "TCP/80 should match RULE_ALLOW");

    telnet = make_packet("10.0.0.21", "10.0.0.1", 6, 50000, 23);
    res = decide(&telnet);
    expect_int_eq(res.decision, DECISION_DROP, test, "TCP/23 should match RULE_DROP");

    udp = make_packet("10.0.0.22", "10.0.0.1", 17, 50000, 53);
    res = decide(&udp);
    expect_int_eq(res.decision, DECISION_DROP, test, "UDP should match RULE_DROP");

    https = make_packet("10.0.0.23", "10.0.0.1", 6, 50000, 443);
    res = decide(&https);
    expect_int_eq(res.decision, DECISION_DROP, test, "unmatched TCP/443 should use default DROP policy");

    blocked_http = make_packet("192.168.1.100", "10.0.0.1", 6, 51000, 80);
    res = decide(&blocked_http);
    expect_int_eq(res.decision, DECISION_DROP, test,
                  "blocked source IP must be dropped before generic TCP/80 allow");

    finish_decision_state();

    if (failures == before) {
        printf("[PASS] %s\n", test);
    }
}

static void test_invalid_config_rules_are_skipped(void)
{
    const char *test = "invalid config rules are skipped";
    int before = failures;
    packet_t tcp443;
    packet_t http;
    packet_t telnet;
    decision_result_t res;

    write_invalid_config();
    reset_decision_state("build/invalid_rules.conf");

    tcp443 = make_packet("10.0.0.30", "10.0.0.1", 6, 52000, 443);
    res = decide(&tcp443);
    expect_int_eq(res.decision, DECISION_DROP, test,
                  "invalid SCTP allow must not become protocol ANY");

    http = make_packet("10.0.0.31", "10.0.0.1", 6, 52000, 80);
    res = decide(&http);
    expect_int_eq(res.decision, DECISION_ACCEPT, test, "valid TCP/80 allow should still load");

    telnet = make_packet("10.0.0.32", "10.0.0.1", 6, 52000, 23);
    res = decide(&telnet);
    expect_int_eq(res.decision, DECISION_DROP, test, "valid TCP/23 drop should still load");

    finish_decision_state();

    if (failures == before) {
        printf("[PASS] %s\n", test);
    }
}

static void test_rule_drop_short_circuits_rate_limit(void)
{
    const char *test = "RULE_DROP short-circuits before rate limit";
    int before = failures;
    packet_t telnet = make_packet("10.0.0.40", "10.0.0.1", 6, 53000, 23);
    packet_t http = make_packet("10.0.0.40", "10.0.0.1", 6, 53000, 80);
    decision_result_t res;

    reset_decision_state("firewall.conf");

    for (int i = 0; i < 25; i++) {
        res = decide(&telnet);
        expect_int_eq(res.decision, DECISION_DROP, test, "TCP/23 flood should be dropped by rule");
    }

    res = decide(&http);
    expect_int_eq(res.decision, DECISION_ACCEPT, test,
                  "prior RULE_DROP packets must not consume rate-limit tokens for later HTTP allow");

    finish_decision_state();

    if (failures == before) {
        printf("[PASS] %s\n", test);
    }
}

static void test_rate_limit_blocks_http_flood_after_threshold(void)
{
    const char *test = "rate limit blocks HTTP flood after threshold";
    int before = failures;
    packet_t http = make_packet("10.0.0.50", "10.0.0.1", 6, 54000, 80);
    decision_result_t res;

    reset_decision_state("firewall.conf");

    for (int i = 0; i < 10; i++) {
        res = decide(&http);
        expect_int_eq(res.decision, DECISION_ACCEPT, test, "first ten HTTP packets should fit the bucket");
    }

    res = decide(&http);
    expect_int_eq(res.decision, DECISION_DROP, test, "eleventh immediate HTTP packet should exceed the bucket");

    finish_decision_state();

    if (failures == before) {
        printf("[PASS] %s\n", test);
    }
}

static void test_hll_tracks_unique_ips_and_duplicates(void)
{
    const char *test = "HyperLogLog tracks unique IPs and ignores duplicates";
    int before = failures;
    int cardinality;
    char ip[16];

    hll_init();
    for (int i = 0; i < 100; i++) {
        snprintf(ip, sizeof(ip), "10.10.0.%d", i + 1);
        expect_int_eq(hll_add_ip(ip), HLL_OK, test, "unique IPv4 address should be accepted");
    }

    cardinality = hll_get_cardinality();
    expect_true(cardinality >= 80 && cardinality <= 125, test,
                "100 unique IPs should estimate inside a realistic HLL tolerance window");

    hll_init();
    for (int i = 0; i < 100; i++) {
        expect_int_eq(hll_add_ip("203.0.113.10"), HLL_OK, test,
                      "duplicate IPv4 address should be accepted");
    }

    cardinality = hll_get_cardinality();
    expect_true(cardinality >= 1 && cardinality <= 2, test,
                "100 copies of the same IP should still estimate roughly one unique IP");

    if (failures == before) {
        printf("[PASS] %s\n", test);
    }
}

int main(void)
{
    test_main_uses_config_and_decision_engine();
    test_parser_valid_tcp_packet();
    test_parser_rejects_malformed_packets();
    test_decision_static_rules_and_default_policy();
    test_invalid_config_rules_are_skipped();
    test_rule_drop_short_circuits_rate_limit();
    test_rate_limit_blocks_http_flood_after_threshold();
    test_hll_tracks_unique_ips_and_duplicates();

    printf("\nAssertions: %d\n", assertions);
    if (failures != 0) {
        printf("Result: FAILED (%d issue%s found)\n", failures, failures == 1 ? "" : "s");
        return 1;
    }

    printf("Result: PASSED\n");
    return 0;
}
