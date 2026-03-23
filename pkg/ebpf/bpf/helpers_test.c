// helpers_test.c — Userspace unit tests for eBPF helper functions.
// Compile and run: gcc -Wall -Werror -o /tmp/helpers_test helpers_test.c && /tmp/helpers_test

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "helpers.h"

static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(fn)                                                           \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  %-55s", #fn);                                                    \
    fn();                                                                      \
    tests_passed++;                                                            \
    printf("PASS\n");                                                          \
  } while (0)

// ============================================================================
// parse_http_host
// ============================================================================

static void test_parse_host_basic(void) {
  const char *data = "GET / HTTP/1.1\r\nHost: example.com\r\n";
  char host[MAX_HOST_LEN] = {0};
  __u32 len = parse_http_host(data, (__u32)strlen(data), host, MAX_HOST_LEN);
  assert(len == 11);
  assert(memcmp(host, "example.com", 11) == 0);
}

static void test_parse_host_with_port(void) {
  const char *data = "Host: example.com:8080\r\n";
  char host[MAX_HOST_LEN] = {0};
  __u32 len = parse_http_host(data, (__u32)strlen(data), host, MAX_HOST_LEN);
  assert(len == 11);
  assert(memcmp(host, "example.com", 11) == 0);
}

static void test_parse_host_short(void) {
  const char *data = "Host: a.b\r\n";
  char host[MAX_HOST_LEN] = {0};
  __u32 len = parse_http_host(data, (__u32)strlen(data), host, MAX_HOST_LEN);
  assert(len == 3);
  assert(memcmp(host, "a.b", 3) == 0);
}

static void test_parse_host_missing(void) {
  const char *data = "GET / HTTP/1.1\r\nContent-Type: text/html\r\n";
  char host[MAX_HOST_LEN] = {0};
  __u32 len = parse_http_host(data, (__u32)strlen(data), host, MAX_HOST_LEN);
  assert(len == 0);
}

static void test_parse_host_near_boundary(void) {
  // Place "Host: ab" at the end of a 256-byte buffer.
  // "Host: " starts at 248, host value at 254.
  char data[MAX_DATA_SIZE];
  memset(data, 'X', sizeof(data));
  memcpy(&data[248], "Host: ab", 8);
  char host[MAX_HOST_LEN] = {0};
  __u32 len = parse_http_host(data, MAX_DATA_SIZE, host, MAX_HOST_LEN);
  assert(len == 2);
  assert(host[0] == 'a' && host[1] == 'b');
}

static void test_parse_host_empty_value(void) {
  const char *data = "Host: \r\n";
  char host[MAX_HOST_LEN] = {0};
  __u32 len = parse_http_host(data, (__u32)strlen(data), host, MAX_HOST_LEN);
  assert(len == 0);
}

static void test_parse_host_truncated(void) {
  // Host value longer than MAX_HOST_LEN (32) is truncated.
  char data[256];
  memset(data, 0, sizeof(data));
  memcpy(data, "Host: ", 6);
  memset(&data[6], 'a', 40); // 40 chars of 'a'
  memcpy(&data[46], "\r\n", 2);
  char host[MAX_HOST_LEN] = {0};
  __u32 len = parse_http_host(data, 48, host, MAX_HOST_LEN);
  assert(len == MAX_HOST_LEN);
  for (int i = 0; i < MAX_HOST_LEN; i++)
    assert(host[i] == 'a');
}

static void test_parse_host_data_len_clamped(void) {
  // data_len > MAX_DATA_SIZE is clamped — host beyond 256 bytes not found.
  char data[300];
  memset(data, 'X', sizeof(data));
  // Place "Host: ok\r\n" at byte 260, beyond MAX_DATA_SIZE.
  memcpy(&data[260], "Host: ok\r\n", 10);
  char host[MAX_HOST_LEN] = {0};
  __u32 len = parse_http_host(data, 300, host, MAX_HOST_LEN);
  assert(len == 0);
}

// ============================================================================
// hosts_match
// ============================================================================

static void test_hosts_match_exact(void) {
  char a[MAX_HOST_LEN] = {0};
  char b[MAX_HOST_LEN] = {0};
  memcpy(a, "example.com", 11);
  memcpy(b, "example.com", 11);
  assert(hosts_match(a, b) == 1);
}

static void test_hosts_match_differ_first(void) {
  char a[MAX_HOST_LEN] = {0};
  char b[MAX_HOST_LEN] = {0};
  memcpy(a, "example.com", 11);
  memcpy(b, "fxample.com", 11);
  assert(hosts_match(a, b) == 0);
}

static void test_hosts_match_differ_last_byte(void) {
  char a[MAX_HOST_LEN] = {0};
  char b[MAX_HOST_LEN] = {0};
  memcpy(a, "example.com", 11);
  memcpy(b, "example.com", 11);
  a[MAX_HOST_LEN - 1] = 'x';
  assert(hosts_match(a, b) == 0);
}

static void test_hosts_match_both_empty(void) {
  char a[MAX_HOST_LEN] = {0};
  char b[MAX_HOST_LEN] = {0};
  assert(hosts_match(a, b) == 1);
}

static void test_hosts_match_different_lengths(void) {
  char a[MAX_HOST_LEN] = {0};
  char b[MAX_HOST_LEN] = {0};
  memcpy(a, "example.com", 11);
  memcpy(b, "example.com.au", 14);
  assert(hosts_match(a, b) == 0);
}

// ============================================================================
// clamp_write_len
// ============================================================================

static void test_clamp_one(void) { assert(clamp_write_len(1) == 1); }

static void test_clamp_max(void) { assert(clamp_write_len(128) == 128); }

static void test_clamp_zero_wraps(void) {
  // Underflow: (0-1) & 127 + 1 = 0xFFFFFFFF & 127 + 1 = 127 + 1 = 128
  assert(clamp_write_len(0) == 128);
}

static void test_clamp_overflow_wraps(void) {
  // (129-1) & 127 + 1 = 128 & 127 + 1 = 0 + 1 = 1
  assert(clamp_write_len(129) == 1);
}

static void test_clamp_exhaustive(void) {
  for (__u32 i = 1; i <= SECRET_MAX_LEN; i++) {
    assert(clamp_write_len(i) == i);
  }
}

// ============================================================================
// is_kloak_prefix
// ============================================================================

static void test_prefix_valid(void) {
  assert(is_kloak_prefix("kloak:abc") == 1);
}

static void test_prefix_wrong_colon(void) {
  assert(is_kloak_prefix("kloak;abc") == 0);
}

static void test_prefix_uppercase(void) {
  assert(is_kloak_prefix("Kloak:abc") == 0);
}

static void test_prefix_wrong_char(void) {
  assert(is_kloak_prefix("kloal:abc") == 0);
}

static void test_prefix_exact_six(void) {
  assert(is_kloak_prefix("kloak:") == 1);
}

// ============================================================================
// ipv4_to_mapped
// ============================================================================

static void test_ipv4_to_mapped_basic(void) {
  __u8 out[16] = {0};
  __u8 v4[4] = {1, 2, 3, 4};
  ipv4_to_mapped(out, v4);
  // bytes 0-9 must be zero
  for (int i = 0; i < 10; i++) assert(out[i] == 0);
  // bytes 10-11 must be 0xff
  assert(out[10] == 0xff && out[11] == 0xff);
  // bytes 12-15 must be the IPv4 address
  assert(out[12] == 1 && out[13] == 2 && out[14] == 3 && out[15] == 4);
}

static void test_ipv4_to_mapped_loopback(void) {
  __u8 out[16] = {0};
  __u8 v4[4] = {127, 0, 0, 1};
  ipv4_to_mapped(out, v4);
  assert(out[10] == 0xff && out[11] == 0xff);
  assert(out[12] == 127 && out[13] == 0 && out[14] == 0 && out[15] == 1);
}

static void test_ipv4_to_mapped_zeros(void) {
  __u8 out[16];
  // Fill with non-zero to confirm all bytes are set
  memset(out, 0xAB, 16);
  __u8 v4[4] = {0, 0, 0, 0};
  ipv4_to_mapped(out, v4);
  for (int i = 0; i < 10; i++) assert(out[i] == 0);
  assert(out[10] == 0xff && out[11] == 0xff);
  assert(out[12] == 0 && out[13] == 0 && out[14] == 0 && out[15] == 0);
}

// ============================================================================
// dns_skip_name
// ============================================================================

// Simple label: \x03api\x06stripe\x03com\x00
static void test_dns_skip_name_simple(void) {
  const char pkt[] = "\x03" "api" "\x06" "stripe" "\x03" "com" "\x00";
  __u32 pkt_len = (__u32)sizeof(pkt) - 1; // exclude C string null
  __u32 result = dns_skip_name(pkt, pkt_len, 0);
  // 1+3 + 1+6 + 1+3 + 1 = 16 bytes total
  assert(result == 16);
}

// Compressed pointer: first two bytes = 0xC0 0x0C
static void test_dns_skip_name_compressed(void) {
  const char pkt[] = "\xC0\x0C" "extra";
  __u32 pkt_len = (__u32)sizeof(pkt) - 1;
  __u32 result = dns_skip_name(pkt, pkt_len, 0);
  assert(result == 2); // compressed pointer is always exactly 2 bytes
}

// Root label: single null byte
static void test_dns_skip_name_root(void) {
  const char pkt[] = "\x00";
  __u32 result = dns_skip_name(pkt, 1, 0);
  assert(result == 1);
}

// Out-of-bounds: offset at end of packet
static void test_dns_skip_name_oob(void) {
  const char pkt[] = "\x03" "abc";
  // pkt_len == 4, label says 3 bytes but offset=0 → next = 0+1+3 = 4, then
  // loop continues, offset=4 >= pkt_len=4 → return 0
  __u32 result = dns_skip_name(pkt, 4, 0);
  // After consuming the label (offset moves to 4), loop tries to read pkt[4]
  // which is out of bounds → return 0
  assert(result == 0);
}

// Reserved bits (0x40xx) → error
static void test_dns_skip_name_reserved_bits(void) {
  const char pkt[] = "\x40\x03" "abc";
  __u32 result = dns_skip_name(pkt, 5, 0);
  assert(result == 0);
}

// ============================================================================
// dns_decode_qname
// ============================================================================

// Single label: \x07example\x00 → "example"
static void test_dns_decode_simple(void) {
  const char pkt[] = "\x07" "example" "\x00";
  __u32 pkt_len = (__u32)sizeof(pkt) - 1;
  char host[MAX_HOST_LEN] = {0};
  __u32 len = dns_decode_qname(pkt, pkt_len, 0, host, MAX_HOST_LEN);
  assert(len == 7);
  assert(memcmp(host, "example", 7) == 0);
}

// Three labels: \x03api\x06stripe\x03com\x00 → "api.stripe.com"
static void test_dns_decode_multi_label(void) {
  const char pkt[] = "\x03" "api" "\x06" "stripe" "\x03" "com" "\x00";
  __u32 pkt_len = (__u32)sizeof(pkt) - 1;
  char host[MAX_HOST_LEN] = {0};
  __u32 len = dns_decode_qname(pkt, pkt_len, 0, host, MAX_HOST_LEN);
  assert(len == 14); // "api.stripe.com"
  assert(memcmp(host, "api.stripe.com", 14) == 0);
}

// Output truncation: small host_max clips result
static void test_dns_decode_truncate(void) {
  const char pkt[] = "\x03" "api" "\x06" "stripe" "\x03" "com" "\x00";
  __u32 pkt_len = (__u32)sizeof(pkt) - 1;
  char host[8] = {0}; // only 8 bytes
  __u32 len = dns_decode_qname(pkt, pkt_len, 0, host, 8);
  assert(len <= 8);
  // First 3 bytes should be "api"
  assert(memcmp(host, "api", 3) == 0);
}

// Root zone (single null byte) → empty result
static void test_dns_decode_root(void) {
  const char pkt[] = "\x00";
  char host[MAX_HOST_LEN] = {0};
  __u32 len = dns_decode_qname(pkt, 1, 0, host, MAX_HOST_LEN);
  assert(len == 0);
}

// Out-of-bounds offset → returns 0 without crashing
static void test_dns_decode_oob(void) {
  const char pkt[] = "\x05" "hello"; // missing null terminator, label runs to end
  __u32 pkt_len = (__u32)sizeof(pkt) - 1;
  char host[MAX_HOST_LEN] = {0};
  // offset already past packet length
  __u32 len = dns_decode_qname(pkt, pkt_len, pkt_len + 10, host, MAX_HOST_LEN);
  assert(len == 0);
}

// ============================================================================
// main
// ============================================================================

int main(void) {
  printf("parse_http_host:\n");
  RUN_TEST(test_parse_host_basic);
  RUN_TEST(test_parse_host_with_port);
  RUN_TEST(test_parse_host_short);
  RUN_TEST(test_parse_host_missing);
  RUN_TEST(test_parse_host_near_boundary);
  RUN_TEST(test_parse_host_empty_value);
  RUN_TEST(test_parse_host_truncated);
  RUN_TEST(test_parse_host_data_len_clamped);

  printf("hosts_match:\n");
  RUN_TEST(test_hosts_match_exact);
  RUN_TEST(test_hosts_match_differ_first);
  RUN_TEST(test_hosts_match_differ_last_byte);
  RUN_TEST(test_hosts_match_both_empty);
  RUN_TEST(test_hosts_match_different_lengths);

  printf("clamp_write_len:\n");
  RUN_TEST(test_clamp_one);
  RUN_TEST(test_clamp_max);
  RUN_TEST(test_clamp_zero_wraps);
  RUN_TEST(test_clamp_overflow_wraps);
  RUN_TEST(test_clamp_exhaustive);

  printf("is_kloak_prefix:\n");
  RUN_TEST(test_prefix_valid);
  RUN_TEST(test_prefix_wrong_colon);
  RUN_TEST(test_prefix_uppercase);
  RUN_TEST(test_prefix_wrong_char);
  RUN_TEST(test_prefix_exact_six);

  printf("ipv4_to_mapped:\n");
  RUN_TEST(test_ipv4_to_mapped_basic);
  RUN_TEST(test_ipv4_to_mapped_loopback);
  RUN_TEST(test_ipv4_to_mapped_zeros);

  printf("dns_skip_name:\n");
  RUN_TEST(test_dns_skip_name_simple);
  RUN_TEST(test_dns_skip_name_compressed);
  RUN_TEST(test_dns_skip_name_root);
  RUN_TEST(test_dns_skip_name_oob);
  RUN_TEST(test_dns_skip_name_reserved_bits);

  printf("dns_decode_qname:\n");
  RUN_TEST(test_dns_decode_simple);
  RUN_TEST(test_dns_decode_multi_label);
  RUN_TEST(test_dns_decode_truncate);
  RUN_TEST(test_dns_decode_root);
  RUN_TEST(test_dns_decode_oob);

  printf("\n%d/%d tests passed.\n", tests_passed, tests_run);
  return 0;
}
