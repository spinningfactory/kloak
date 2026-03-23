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

  printf("\n%d/%d tests passed.\n", tests_passed, tests_run);
  return 0;
}
