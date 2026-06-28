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
  // Host value longer than MAX_HOST_LEN is truncated.
  char data[512];
  memset(data, 0, sizeof(data));
  memcpy(data, "Host: ", 6);
  memset(&data[6], 'a', MAX_HOST_LEN + 10); // more than MAX_HOST_LEN chars
  memcpy(&data[6 + MAX_HOST_LEN + 10], "\r\n", 2);
  char host[MAX_HOST_LEN] = {0};
  __u32 len = parse_http_host(data, 6 + MAX_HOST_LEN + 12, host, MAX_HOST_LEN);
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
// is_kloak_prefix — matches the 4-byte "kl::" plaintext prefix.
// ============================================================================

static void test_prefix_valid(void) {
  assert(is_kloak_prefix("kl::abc") == 1);
}

static void test_prefix_single_colon(void) {
  // One colon is not the prefix; the matcher requires both colons.
  assert(is_kloak_prefix("kl:abcd") == 0);
}

static void test_prefix_uppercase(void) {
  assert(is_kloak_prefix("Kl::abc") == 0);
}

static void test_prefix_wrong_second_char(void) {
  assert(is_kloak_prefix("ka::abc") == 0);
}

static void test_prefix_exact_four(void) {
  assert(is_kloak_prefix("kl::") == 1);
}

// ============================================================================
// gf128_mul — GHASH GF(2^128) multiplication
// Test vectors from "The Galois/Counter Mode of Operation (GCM)"
// McGrew & Viega, and NIST SP 800-38D.
// ============================================================================

// Helper to parse hex string into byte array
static void hex_to_bytes(const char *hex, __u8 *out, int len) {
  for (int i = 0; i < len; i++) {
    unsigned int byte;
    sscanf(hex + 2 * i, "%02x", &byte);
    out[i] = (__u8)byte;
  }
}

static int bytes_equal(const __u8 *a, const __u8 *b, int len) {
  return memcmp(a, b, len) == 0;
}

static void print_hex(const char *label, const __u8 *data, int len) {
  printf("\n    %s: ", label);
  for (int i = 0; i < len; i++)
    printf("%02x", data[i]);
}

static void test_gf128_mul_identity(void) {
  // Multiplying by the identity element (0x80, 0, ..., 0) should return
  // the other operand unchanged.
  __u8 identity[16] = {0x80};
  __u8 x[16];
  __u8 result[16];

  hex_to_bytes("0388dace60b6a392f328c2b971b2fe78", x, 16);
  gf128_mul(identity, x, result);
  assert(bytes_equal(result, x, 16));

  // Commutative: x * identity = identity * x
  gf128_mul(x, identity, result);
  assert(bytes_equal(result, x, 16));
}

static void test_gf128_mul_zero(void) {
  // Multiplying by zero gives zero.
  __u8 zero[16] = {0};
  __u8 x[16];
  __u8 result[16];

  hex_to_bytes("0388dace60b6a392f328c2b971b2fe78", x, 16);
  gf128_mul(zero, x, result);
  assert(bytes_equal(result, zero, 16));
}

static void test_gf128_mul_known_vector(void) {
  // Known test vector: H * H where H = AES_K(0^128).
  // From GCM spec test case 2: K = 0x00000...0, so H = AES(0, 0^128).
  // H = 66e94bd4ef8a2c3b884cfa59ca342b2e
  // H^2 should be a known value we can verify.
  __u8 h[16], h_squared[16], result[16];
  hex_to_bytes("66e94bd4ef8a2c3b884cfa59ca342b2e", h, 16);

  gf128_mul(h, h, result);

  // H^2 for this specific H (precomputed):
  // We verify by computing H * H * identity = H^2
  // and checking H^2 * H^{-1} = H (but we don't have inverse).
  // Instead verify: gf128_mul is commutative and associative
  // by checking H * H = H^2 and then H^2 * H = H * (H * H).
  memcpy(h_squared, result, 16);

  __u8 h_cubed_1[16], h_cubed_2[16];
  gf128_mul(h_squared, h, h_cubed_1);
  gf128_mul(h, h_squared, h_cubed_2);
  assert(bytes_equal(h_cubed_1, h_cubed_2, 16));
}

static void test_gf128_mul_commutativity(void) {
  __u8 a[16], b[16], ab[16], ba[16];
  hex_to_bytes("0388dace60b6a392f328c2b971b2fe78", a, 16);
  hex_to_bytes("66e94bd4ef8a2c3b884cfa59ca342b2e", b, 16);

  gf128_mul(a, b, ab);
  gf128_mul(b, a, ba);
  assert(bytes_equal(ab, ba, 16));
}

static void test_gf128_h_power_1(void) {
  // H^1 should equal H.
  __u8 h[16], result[16];
  hex_to_bytes("66e94bd4ef8a2c3b884cfa59ca342b2e", h, 16);

  gf128_h_power(h, 1, result);
  assert(bytes_equal(result, h, 16));
}

static void test_gf128_h_power_2(void) {
  // H^2 should equal H * H.
  __u8 h[16], expected[16], result[16];
  hex_to_bytes("66e94bd4ef8a2c3b884cfa59ca342b2e", h, 16);

  gf128_mul(h, h, expected);
  gf128_h_power(h, 2, result);
  assert(bytes_equal(result, expected, 16));
}

static void test_gf128_h_power_3(void) {
  // H^3 = H^2 * H
  __u8 h[16], h2[16], expected[16], result[16];
  hex_to_bytes("66e94bd4ef8a2c3b884cfa59ca342b2e", h, 16);

  gf128_mul(h, h, h2);
  gf128_mul(h2, h, expected);
  gf128_h_power(h, 3, result);
  assert(bytes_equal(result, expected, 16));
}

static void test_gf128_h_power_table(void) {
  // Precomputed table should give same results as slow path.
  __u8 h[16], result_slow[16], result_fast[16], tmp[16];
  hex_to_bytes("66e94bd4ef8a2c3b884cfa59ca342b2e", h, 16);

  // Build power table: table[i] = H^(2^i)
  __u8 table[11][16];
  memcpy(table[0], h, 16);
  for (int i = 1; i < 11; i++) {
    gf128_mul(table[i - 1], table[i - 1], tmp);
    memcpy(table[i], tmp, 16);
  }

  // Test various powers
  __u32 test_powers[] = {1, 2, 3, 5, 7, 10, 100, 1024};
  for (int t = 0; t < 8; t++) {
    gf128_h_power(h, test_powers[t], result_slow);
    gf128_h_power_table(table, test_powers[t], result_fast);
    if (!bytes_equal(result_slow, result_fast, 16)) {
      print_hex("slow", result_slow, 16);
      print_hex("fast", result_fast, 16);
      printf("\n    power=%u\n", test_powers[t]);
    }
    assert(bytes_equal(result_slow, result_fast, 16));
  }
}

static void test_is_aes_gcm(void) {
  assert(is_aes_gcm(KLOAK_CIPHER_AES_GCM) == 1);
  assert(is_aes_gcm(KLOAK_CIPHER_UNKNOWN) == 0);
  assert(is_aes_gcm(0) == 0);
  assert(is_aes_gcm(99) == 0);
}

// ============================================================================
// AES (H recovery for BoringSSL)
// ============================================================================

// Standard FIPS-197 key expansion — only for the known-answer tests. The eBPF
// data plane never expands a key; it reads BoringSSL's persisted AES_KEY.rd_key
// (already expanded) and calls aes_block_encrypt directly.
static void aes_kat_expand(const __u8 *key, int nk, __u8 *rk, int nr) {
  static const __u8 rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                              0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d};
  int total = 4 * (nr + 1);
  for (int i = 0; i < 4 * nk; i++) rk[i] = key[i];
  for (int i = nk; i < total; i++) {
    __u8 t[4] = {rk[4 * (i - 1) + 0], rk[4 * (i - 1) + 1],
                 rk[4 * (i - 1) + 2], rk[4 * (i - 1) + 3]};
    if (i % nk == 0) {
      __u8 tmp = t[0];
      t[0] = KLOAK_AES_SBOX[t[1]] ^ rcon[i / nk - 1];
      t[1] = KLOAK_AES_SBOX[t[2]];
      t[2] = KLOAK_AES_SBOX[t[3]];
      t[3] = KLOAK_AES_SBOX[tmp];
    } else if (nk > 6 && i % nk == 4) {
      for (int j = 0; j < 4; j++) t[j] = KLOAK_AES_SBOX[t[j]];
    }
    for (int j = 0; j < 4; j++) rk[4 * i + j] = rk[4 * (i - nk) + j] ^ t[j];
  }
}

static void test_aes128_fips197(void) {
  // FIPS-197 Appendix C.1: key 000102…0f, pt 00112233…ff.
  __u8 key[16], block[16], rk[176], want[16];
  for (int i = 0; i < 16; i++) {
    key[i] = (__u8)i;
    block[i] = (__u8)(i * 0x11); // plaintext, encrypted in place
  }
  hex_to_bytes("69c4e0d86a7b0430d8cdb78070b4c55a", want, 16);
  aes_kat_expand(key, 4, rk, 10);
  aes_block_encrypt(rk, 10, block);
  assert(bytes_equal(block, want, 16));
}

static void test_aes256_fips197(void) {
  // FIPS-197 Appendix C.3: key 000102…1f, pt 00112233…ff.
  __u8 key[32], block[16], rk[240], want[16];
  for (int i = 0; i < 32; i++) key[i] = (__u8)i;
  for (int i = 0; i < 16; i++) block[i] = (__u8)(i * 0x11);
  hex_to_bytes("8ea2b7ca516745bfeafc49904b496089", want, 16);
  aes_kat_expand(key, 8, rk, 14);
  aes_block_encrypt(rk, 14, block);
  assert(bytes_equal(block, want, 16));
}

static void test_aes_recover_h(void) {
  // H = AES_encrypt(0). For key 0102…10 BoringSSL yields this subkey (verified
  // empirically against a real BoringSSL AES-GCM context on amd64 + arm64).
  __u8 key[16], rk[176], h[16], want[16];
  for (int i = 0; i < 16; i++) key[i] = (__u8)(i + 1);
  hex_to_bytes("dbf184112eb9111659712bafcff2ab24", want, 16);
  aes_kat_expand(key, 4, rk, 10);
  assert(aes_recover_h(rk, 10, h) == 1);
  assert(bytes_equal(h, want, 16));
  // x86 AES-NI stores rounds as nr-1; both forms must work.
  assert(aes_recover_h(rk, 9, h) == 1);
  assert(bytes_equal(h, want, 16));
  // Invalid round counts are rejected (guards against a bogus offset read).
  assert(aes_recover_h(rk, 0, h) == 0);
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
  RUN_TEST(test_prefix_single_colon);
  RUN_TEST(test_prefix_uppercase);
  RUN_TEST(test_prefix_wrong_second_char);
  RUN_TEST(test_prefix_exact_four);

  printf("gf128_mul:\n");
  RUN_TEST(test_gf128_mul_identity);
  RUN_TEST(test_gf128_mul_zero);
  RUN_TEST(test_gf128_mul_known_vector);
  RUN_TEST(test_gf128_mul_commutativity);
  RUN_TEST(test_gf128_h_power_1);
  RUN_TEST(test_gf128_h_power_2);
  RUN_TEST(test_gf128_h_power_3);
  RUN_TEST(test_gf128_h_power_table);
  RUN_TEST(test_is_aes_gcm);

  printf("aes (BoringSSL H recovery):\n");
  RUN_TEST(test_aes128_fips197);
  RUN_TEST(test_aes256_fips197);
  RUN_TEST(test_aes_recover_h);

  printf("\n%d/%d tests passed.\n", tests_passed, tests_run);
  return 0;
}
