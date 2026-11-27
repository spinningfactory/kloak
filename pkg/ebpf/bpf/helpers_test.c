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
// is_kloak_candidate — "kl::" or its HPACK Huffman prefix (eb 45 cb).
// ============================================================================

static void test_candidate_plain(void) {
  assert(is_kloak_candidate((const unsigned char *)"kl::abcd") == 1);
}

static void test_candidate_huffman(void) {
  const unsigned char buf[] = {0xeb, 0x45, 0xcb, 0x12, 0x34, 0x56, 0x78, 0x9a};
  assert(is_kloak_candidate(buf) == 1);
}

static void test_candidate_huffman_partial(void) {
  const unsigned char buf[] = {0xeb, 0x45, 0xca, 0x12};
  assert(is_kloak_candidate(buf) == 0);
}

static void test_candidate_neither(void) {
  assert(is_kloak_candidate((const unsigned char *)"kl:;abcd") == 0);
  assert(is_kloak_candidate((const unsigned char *)"Bearer x") == 0);
}

// ============================================================================
// prescan_num_chunks / prescan_scan_len — the prescan tries every start
// position whose key fits in the write exactly once, so a placeholder in the
// overlap of two chunks is recorded once.
// ============================================================================

static void test_prescan_chunks_tile_positions(void) {
  static unsigned char tried[4 * MAX_DATA_SIZE + 2 * SECRET_KEY_LEN];
  for (__u32 total = 0; total < sizeof(tried); total++) {
    memset(tried, 0, sizeof(tried));
    __u32 chunks = prescan_num_chunks(total);
    for (__u32 c = 0; c < chunks; c++) {
      __u32 offset = c * CHUNK_STRIDE;
      assert(offset < total); // prescan_chunk stops at offset >= total
      __u32 read_len = total - offset;
      if (read_len > MAX_DATA_SIZE)
        read_len = MAX_DATA_SIZE;
      __u32 scan = prescan_scan_len(read_len);
      assert(scan <= CHUNK_STRIDE);
      for (__u32 i = 0; i < scan; i++) {
        assert(i + SECRET_KEY_LEN <= read_len); // the key lies in the chunk
        tried[offset + i]++;
      }
    }
    for (__u32 p = 0; p < total; p++)
      assert(tried[p] == (p + SECRET_KEY_LEN <= total ? 1 : 0));
  }
}

static void test_prescan_scan_len_bounds(void) {
  assert(prescan_scan_len(0) == 0);
  assert(prescan_scan_len(SECRET_KEY_LEN - 1) == 0);
  assert(prescan_scan_len(SECRET_KEY_LEN) == 1);
  assert(prescan_scan_len(MAX_DATA_SIZE) == CHUNK_STRIDE);
  assert(prescan_scan_len(MAX_DATA_SIZE + 100) == CHUNK_STRIDE);
  assert(prescan_num_chunks(0) == 0);
  assert(prescan_num_chunks(1) == 1);
  assert(prescan_num_chunks(CHUNK_STRIDE) == 1);
  assert(prescan_num_chunks(CHUNK_STRIDE + 1) == 2);
}

// ============================================================================
// patch_delta — the XOR delta bpf_xor_path stages for a placeholder
// ============================================================================

#include "hpack_tail_fixtures.h"

static void print_hex(const char *label, const __u8 *data, int len);

static void test_patch_tail_mask(void) {
  assert(patch_tail_mask(0) == 0xff);
  assert(patch_tail_mask(1) == 0xfe);
  assert(patch_tail_mask(5) == 0xe0);
  assert(patch_tail_mask(7) == 0x80);
  for (__u8 p = 0; p < 8; p++)
    assert(patch_tail_mask(p) == (__u8)(0xff << p));
}

// What bpf_xor_path and tc do to the len bytes at off of wire: read the
// placeholder's bytes (bpf_probe_read_user reads SECRET_MAX_LEN of them, past
// the placeholder), turn them into the delta, and XOR it onto the wire.
static void apply_patch(const unsigned char *wire, __u32 wire_len, __u32 off,
                        const unsigned char *real_secret, __u32 len,
                        __u8 pad_bits, unsigned char *out) {
  __u8 buf[SECRET_MAX_LEN] = {0};
  char real[SECRET_MAX_LEN] = {0};
  memcpy(buf, wire + off, wire_len - off);
  memcpy(real, real_secret, len);
  len = clamp_write_len(len);
  patch_delta(buf, real, len, pad_bits);
  memcpy(out, wire, wire_len);
  for (__u32 j = 0; j < len; j++)
    out[off + j] ^= buf[j];
}

// A raw placeholder has no pad bits: the delta is shadow ^ real over all of
// its bytes, and nothing after it changes.
static void test_patch_delta_raw(void) {
  const char *wire = "X-Key: kl::abcdefgh;tail\r\n";
  const char *want = "X-Key: real-value12;tail\r\n";
  unsigned char out[64];
  apply_patch((const unsigned char *)wire, strlen(wire), 7,
              (const unsigned char *)"real-value12", 12, 0, out);
  assert(memcmp(out, want, strlen(want)) == 0);
}

// The delta for every length and pad: buf ^ real over the placeholder's
// bits, 0 over the pad bits of its last byte, and buf unchanged past it. The
// loop covers the whole buffer (for Linux 6.1's verifier), which leaves the
// bytes past len as they are only because real is zero there, as sync
// writes it.
static void test_patch_delta_every_len(void) {
  for (__u32 len = 1; len <= SECRET_MAX_LEN; len++) {
    for (__u8 pad = 0; pad < 8; pad++) {
      __u8 buf[SECRET_MAX_LEN], orig[SECRET_MAX_LEN];
      char real[SECRET_MAX_LEN] = {0};
      for (__u32 j = 0; j < SECRET_MAX_LEN; j++)
        orig[j] = buf[j] = (__u8)(0x5a + 37 * j);
      for (__u32 j = 0; j < len; j++)
        real[j] = (char)(0xc3 ^ (11 * j));
      patch_delta(buf, real, len, pad);
      for (__u32 j = 0; j + 1 < len; j++)
        assert(buf[j] == (__u8)(orig[j] ^ (__u8)real[j]));
      assert(buf[len - 1] ==
             (__u8)((orig[len - 1] ^ (__u8)real[len - 1]) & patch_tail_mask(pad)));
      for (__u32 j = len; j < SECRET_MAX_LEN; j++)
        assert(buf[j] == orig[j]);
    }
  }
}

// spinningfactory/kloak#228 (1.7): for an HPACK-Huffman placeholder, the
// patch must not touch the bits after the placeholder's code, which are the
// next character's when text follows it in the same header value. Every case
// is Go's hpack encoding of prefix + shadow + suffix, which must become that
// of prefix + real + suffix, for every shadow bit length mod 8.
static void test_patch_delta_hpack_tail(void) {
  unsigned pads = 0;
  int unmasked_wrong = 0, short_key_misses = 0;
  for (size_t i = 0; i < sizeof(hpack_tail_cases) / sizeof(hpack_tail_cases[0]); i++) {
    const struct hpack_tail_case *c = &hpack_tail_cases[i];
    const struct hpack_tail_entry *e = &hpack_tail_entries[c->entry];
    pads |= 1u << e->pad_bits;
    assert(c->offset + e->len <= c->len);

    // The prescan's match: Huffman "kl::" on a byte boundary, keyed by the
    // 8 bytes from there.
    __u32 pos = 0;
    while (pos + 3 <= c->len && !is_kloak_prefix_huffman(c->wire + pos))
      pos++;
    assert(pos == c->offset);
    if (memcmp(c->wire + pos, e->key, sizeof(e->key)) != 0) {
      // Only a code of exactly 8 bytes that does not end on a byte boundary:
      // its key's last bits are the padding sync keyed it by, but on the
      // wire, the text after it. No match, the placeholder goes out as is.
      assert(e->len == sizeof(e->key) && e->pad_bits != 0 && c->suffix[0]);
      short_key_misses++;
      continue;
    }

    unsigned char out[HPACK_TAIL_MAX];
    apply_patch(c->wire, c->len, c->offset, e->real_secret, e->len,
                e->pad_bits, out);
    if (memcmp(out, c->want, c->len) != 0) {
      printf("\n    %s: \"%s\" + shadow + \"%s\"", e->shadow, c->prefix, c->suffix);
      print_hex("got ", out, c->len);
      print_hex("want", c->want, c->len);
      printf("\n");
      assert(0);
    }
    // The patch before the fix replaced the bits after the code with the
    // real's EOS padding.
    apply_patch(c->wire, c->len, c->offset, e->real_secret, e->len, 0, out);
    if (memcmp(out, c->want, c->len) != 0)
      unmasked_wrong++;
  }
  assert(pads == 0xff);
  assert(unmasked_wrong > 0);
  assert(short_key_misses > 0);
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

// The bit-serial GF(2^128) multiply (NIST SP 800-38D §6.3, Algorithm 1):
// the reference the GHASH engine's table multiply is checked against. Step i,
// for bit i of a (MSB-first: bit 0 is the MSB of byte 0): z ^= v if the bit
// is set, then v = v * x, a 1-bit right shift that folds the bit shifted out
// of v[15] back in as R = 0xe1 || 0^120. Start with z = 0 and v = b; after
// steps 0..127, z = a * b.
static void gf128_mul_step(const __u8 a[16], __u8 v[16], __u8 z[16], __u32 i) {
  __u8 mask = -(__u8)((a[i >> 3] >> (7 - (i & 7))) & 1);
  __u8 prev = 0;
  for (int j = 0; j < 16; j++) {
    __u8 cur = v[j];
    z[j] ^= cur & mask;
    v[j] = (cur >> 1) | (__u8)(prev << 7);
    prev = cur;
  }
  if (prev & 1)
    v[0] ^= 0xe1;
}

static void gf128_mul(const __u8 a[16], const __u8 b[16], __u8 result[16]) {
  __u8 v[16], z[16];
  memset(z, 0, 16);
  memcpy(v, b, 16);
  for (__u32 i = 0; i < 128; i++)
    gf128_mul_step(a, v, z, i);
  memcpy(result, z, 16);
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

static void test_gf128_mul_gcm_vector(void) {
  // GCM spec test case 2 (K = 0, P = 0^128, IV = 0^96): X1 = C * H, and
  // GHASH = (X1 ^ len(A)||len(C)) * H, which is T ^ E(K, Y0). Checks the
  // reduction too, which the algebraic tests above can't tell apart.
  __u8 h[16], c[16], x1[16], ghash[16], result[16], ws_v[16], ws_z[16];
  hex_to_bytes("66e94bd4ef8a2c3b884cfa59ca342b2e", h, 16);
  hex_to_bytes("0388dace60b6a392f328c2b971b2fe78", c, 16);
  hex_to_bytes("5e2ec746917062882c85b0685353deb7", x1, 16);
  hex_to_bytes("f38cbb1ad69223dcc3457ae5b6b0f885", ghash, 16);

  gf128_mul(c, h, result);
  assert(bytes_equal(result, x1, 16));

  // The steps one by one.
  __builtin_memset(ws_z, 0, 16);
  __builtin_memcpy(ws_v, h, 16);
  __u8 a[16];
  __builtin_memcpy(a, x1, 16);
  a[15] ^= 0x80; // len(A) || len(C) = 0 || 128
  for (__u32 i = 0; i < 128; i++)
    gf128_mul_step(a, ws_v, ws_z, i);
  assert(bytes_equal(ws_z, ghash, 16));
}

static void test_gf128_mul_commutativity(void) {
  __u8 a[16], b[16], ab[16], ba[16];
  hex_to_bytes("0388dace60b6a392f328c2b971b2fe78", a, 16);
  hex_to_bytes("66e94bd4ef8a2c3b884cfa59ca342b2e", b, 16);

  gf128_mul(a, b, ab);
  gf128_mul(b, a, ba);
  assert(bytes_equal(ab, ba, 16));
}

static void test_is_aes_gcm(void) {
  assert(is_aes_gcm(KLOAK_CIPHER_AES_GCM) == 1);
  assert(is_aes_gcm(KLOAK_CIPHER_UNKNOWN) == 0);
  assert(is_aes_gcm(0) == 0);
  assert(is_aes_gcm(99) == 0);
}

// ============================================================================
// tls_record_hdr_kind / tls_appdata_reclen_match (tc_egress record selection)
// ============================================================================

static void test_tls_hdr_appdata(void) {
  const __u8 h[5] = {0x17, 0x03, 0x03, 0x00, 0x42};
  __u32 len = 0;
  assert(tls_record_hdr_kind(h, &len) == TLS_REC_APPDATA);
  assert(len == 0x42);
}

static void test_tls_hdr_appdata_too_short(void) {
  const __u8 h[5] = {0x17, 0x03, 0x03, 0x00, 16};
  __u32 len = 0;
  assert(tls_record_hdr_kind(h, &len) == TLS_REC_INVALID);
}

static void test_tls_hdr_ccs(void) {
  const __u8 ok[5] = {0x14, 0x03, 0x03, 0x00, 0x01};
  const __u8 bad[5] = {0x14, 0x03, 0x03, 0x00, 0x02};
  __u32 len = 0;
  assert(tls_record_hdr_kind(ok, &len) == TLS_REC_SKIPPABLE);
  assert(len == 1);
  assert(tls_record_hdr_kind(bad, &len) == TLS_REC_INVALID);
}

static void test_tls_hdr_handshake_and_alert(void) {
  const __u8 hs[5] = {0x16, 0x03, 0x01, 0x05, 0x9b};
  const __u8 alert[5] = {0x15, 0x03, 0x03, 0x00, 0x02};
  const __u8 hs_short[5] = {0x16, 0x03, 0x03, 0x00, 0x03};
  __u32 len = 0;
  assert(tls_record_hdr_kind(hs, &len) == TLS_REC_SKIPPABLE);
  assert(len == 0x59b);
  assert(tls_record_hdr_kind(alert, &len) == TLS_REC_SKIPPABLE);
  assert(tls_record_hdr_kind(hs_short, &len) == TLS_REC_INVALID);
}

static void test_tls_hdr_rejects_garbage(void) {
  const __u8 bad_type[5] = {0x42, 0x03, 0x03, 0x00, 0x42};
  const __u8 bad_major[5] = {0x17, 0x02, 0x03, 0x00, 0x42};
  const __u8 bad_minor[5] = {0x17, 0x03, 0x04, 0x00, 0x42};
  const __u8 too_long[5] = {0x17, 0x03, 0x03, 0x48, 0x01}; // 18433
  const __u8 max_len[5] = {0x17, 0x03, 0x03, 0x48, 0x00};  // 18432
  __u32 len = 0;
  assert(tls_record_hdr_kind(bad_type, &len) == TLS_REC_INVALID);
  assert(tls_record_hdr_kind(bad_major, &len) == TLS_REC_INVALID);
  assert(tls_record_hdr_kind(bad_minor, &len) == TLS_REC_INVALID);
  assert(tls_record_hdr_kind(too_long, &len) == TLS_REC_INVALID);
  assert(tls_record_hdr_kind(max_len, &len) == TLS_REC_APPDATA);
}

static void test_tls_reclen_match_known_nonce(void) {
  __u32 n = 0xAA;
  assert(tls_appdata_reclen_match(49 + 17, 49, 0, &n) == 1 && n == 0);
  assert(tls_appdata_reclen_match(49 + 24, 49, 0, &n) == 0);
  assert(tls_appdata_reclen_match(49 + 24, 49, 8, &n) == 1 && n == 8);
  assert(tls_appdata_reclen_match(49 + 17, 49, 8, &n) == 0);
}

static void test_tls_reclen_match_unknown_nonce(void) {
  __u32 n = 0xAA;
  assert(tls_appdata_reclen_match(49 + 17, 49, TLS_NONCE_UNKNOWN, &n) == 1 && n == 0);
  assert(tls_appdata_reclen_match(49 + 24, 49, TLS_NONCE_UNKNOWN, &n) == 1 && n == 8);
  // Encrypted TLS 1.3 Finished coalesced ahead of the write must not match.
  assert(tls_appdata_reclen_match(69, 49, TLS_NONCE_UNKNOWN, &n) == 0);
}

static void test_tls_reclen_match_zero_plaintext(void) {
  __u32 n = 0xAA;
  assert(tls_appdata_reclen_match(17, 0, TLS_NONCE_UNKNOWN, &n) == 0);
  assert(n == 0xAA);
}

// tc_record_nonce: a memory-BIO write is only patched into a record that fits.
static void test_tc_record_nonce_matched(void) {
  __u32 n = TLS_NONCE_UNKNOWN;
  assert(tc_record_nonce(1, 0, 0, &n) == 1 && n == 0);
  n = TLS_NONCE_UNKNOWN;
  assert(tc_record_nonce(1, 8, 1, &n) == 1 && n == 8);
}

static void test_tc_record_nonce_memory_bio_no_fit(void) {
  __u32 n = 0;
  assert(tc_record_nonce(0, 0, 0, &n) == 0);
  n = TLS_NONCE_UNKNOWN;
  assert(tc_record_nonce(0, 0, 0, &n) == 0);
}

static void test_tc_record_nonce_anchored_no_fit(void) {
  __u32 n = 0;
  assert(tc_record_nonce(0, 8, 1, &n) == 1 && n == 0); // known: kept
  n = TLS_NONCE_UNKNOWN;
  assert(tc_record_nonce(0, 0, 1, &n) == 1 && n == 8); // unknown: TLS 1.2
}

static void test_tc_patch_fits_tls12(void) {
  // 100 bytes of application data, all of the encrypted part.
  assert(tc_patch_fits(0, 100, 100, 8));
  assert(tc_patch_fits(60, 40, 100, 8)); // ends on the last byte
  assert(!tc_patch_fits(61, 40, 100, 8)); // one byte into the tag
  assert(!tc_patch_fits(0, 101, 100, 8));
  assert(!tc_patch_fits(100, 1, 100, 8));
}

static void test_tc_patch_fits_tls13(void) {
  // 100 encrypted bytes: 99 of data, then the inner content type.
  assert(tc_patch_fits(59, 40, 100, 0)); // ends on the last data byte
  assert(!tc_patch_fits(60, 40, 100, 0)); // over the content type
  assert(!tc_patch_fits(0, 100, 100, 0));
  assert(tc_patch_fits(0, 1, 2, 0));
  assert(!tc_patch_fits(0, 1, 1, 0)); // no data at all
  assert(!tc_patch_fits(0, 1, 0, 0));
}

static void test_tc_patch_fits_edges(void) {
  assert(!tc_patch_fits(0, 0, 100, 8)); // an empty patch
  // off + len wraps 32 bits: still refused.
  assert(!tc_patch_fits(0xFFFFFFF0u, 32, 100, 8));
  assert(!tc_patch_fits(0xFFFFFFF0u, 32, 0xFFFFFFFFu, 8));
  assert(!tc_patch_fits(16, 0xFFFFFFF8u, 0xFFFFFFFFu, 8));
}

static void test_tc_entry_expired(void) {
  const __u64 t0 = 5000000000000ULL;
  assert(!tc_entry_expired(t0, t0, XOR_PENDING_TTL_NS));
  assert(!tc_entry_expired(t0 + XOR_PENDING_TTL_NS, t0, XOR_PENDING_TTL_NS));
  assert(tc_entry_expired(t0 + XOR_PENDING_TTL_NS + 1, t0, XOR_PENDING_TTL_NS));
  assert(!tc_entry_expired(t0 + XOR_PENDING_TTL_NS + 1, t0, TC_PENDING_TTL_NS));
  // An entry stamped after now (another CPU's clock read) is not expired.
  assert(!tc_entry_expired(t0, t0 + 10, XOR_PENDING_TTL_NS));
}

static void test_tc_tag_action(void) {
  const __u64 now = 5000000000000ULL;
  // Tag in this segment: payload [1000, 1100), tag at [1080, 1096).
  assert(tc_tag_action(1000, 100, 1080, now, now) == TC_TAG_PATCH);
  assert(tc_tag_action(1000, 100, 1084, now, now) == TC_TAG_PATCH); // last 16 bytes
  // In a later segment, or a pure ACK before it.
  assert(tc_tag_action(1000, 100, 1100, now, now) == TC_TAG_WAIT);
  assert(tc_tag_action(1000, 0, 1000, now, now) == TC_TAG_WAIT);
  assert(tc_tag_action(1000, 100, 9000, now, now) == TC_TAG_WAIT);
  // Split across this segment and the next.
  assert(tc_tag_action(1000, 100, 1085, now, now) == TC_TAG_DROP);
  // The segment starts past the tag: it left unpatched.
  assert(tc_tag_action(1000, 100, 990, now, now) == TC_TAG_DROP);
  // Expired.
  assert(tc_tag_action(1000, 100, 1080, now, now - TC_PENDING_TTL_NS - 1) == TC_TAG_DROP);
  // Sequence numbers wrap.
  assert(tc_tag_action(0xFFFFFFF0U, 100, 0x00000010U, now, now) == TC_TAG_PATCH);
  assert(tc_tag_action(0x00000010U, 100, 0xFFFFFFF0U, now, now) == TC_TAG_DROP);
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
// gf128_halve_to_h (OpenSSL AVX-512 HashKey_1 / Go H·2 → H)
// ============================================================================

// Literal transcription of ossl_aes_gcm_init_avx512's HashKey_1 precompute
// (crypto/modes/asm/aes-gcm-avx512.pl, OpenSSL 3.1+), starting from
// HashKey = AES_K(0):
//   vpshufb SHUF_MASK         → reverse all 16 bytes
//   vpsllq $1                 → shift each 64-bit lane left by one
//   vpsrlq $63 / vpslldq $8   → carry lane0's MSB into lane1's bit 0
//   vpsrldq $8 / TWOONE / POLY → XOR POLY when lane1's MSB (bit 127) was set
// The result is stored with vmovdqu64, so lane0/lane1 are the slot's
// little-endian low/high 8 bytes — exactly what the BPF probe read sees.
static void vaes_hkey1_forward(const __u8 h[16], __u64 *lo_out, __u64 *hi_out) {
  __u8 s[16];
  for (int i = 0; i < 16; i++)
    s[i] = h[15 - i];
  __u64 lo = 0, hi = 0;
  for (int i = 0; i < 8; i++) {
    lo |= (__u64)s[i] << (8 * i);
    hi |= (__u64)s[8 + i] << (8 * i);
  }
  __u64 carry_out = hi >> 63;
  hi = (hi << 1) | (lo >> 63);
  lo <<= 1;
  if (carry_out) {
    lo ^= 0x0000000000000001ULL;
    hi ^= 0xC200000000000000ULL;
  }
  *lo_out = lo;
  *hi_out = hi;
}

// want_reduced: 1/0 asserts which reduction branch the forward transform
// took (so each branch is provably covered); -1 skips the check.
static void check_hkey1_roundtrip(const __u8 h[16], int want_reduced) {
  __u64 lo, hi;
  __u8 got[16];
  vaes_hkey1_forward(h, &lo, &hi);
  if (want_reduced >= 0)
    assert((int)(lo & 1) == want_reduced);
  gf128_halve_to_h(lo, hi, got);
  if (!bytes_equal(got, h, 16)) {
    print_hex("want", h, 16);
    print_hex("got ", got, 16);
  }
  assert(bytes_equal(got, h, 16));
}

static void test_gf128_halve_to_h_aes_keys(void) {
  __u8 key[32], rk[240], h[16], want[16];

  // NIST GCM test cases 1/2: K = 0^128 → H = 66e94bd4… (MSB clear).
  memset(key, 0, sizeof(key));
  aes_kat_expand(key, 4, rk, 10);
  memset(h, 0, 16);
  aes_block_encrypt(rk, 10, h);
  hex_to_bytes("66e94bd4ef8a2c3b884cfa59ca342b2e", want, 16);
  assert(bytes_equal(h, want, 16));
  check_hkey1_roundtrip(h, 0);

  // K = 01..10 → H = dbf18411… (MSB set → POLY reduction branch).
  for (int i = 0; i < 16; i++)
    key[i] = (__u8)(i + 1);
  aes_kat_expand(key, 4, rk, 10);
  memset(h, 0, 16);
  aes_block_encrypt(rk, 10, h);
  hex_to_bytes("dbf184112eb9111659712bafcff2ab24", want, 16);
  assert(bytes_equal(h, want, 16));
  check_hkey1_roundtrip(h, 1);

  // AES-256, K = 00..1f.
  for (int i = 0; i < 32; i++)
    key[i] = (__u8)i;
  aes_kat_expand(key, 8, rk, 14);
  memset(h, 0, 16);
  aes_block_encrypt(rk, 14, h);
  check_hkey1_roundtrip(h, -1);
}

static void test_gf128_halve_to_h_edges(void) {
  static const char *const hs[] = {
      "80000000000000000000000000000000", // only the bit that triggers reduction
      "00000000000000000000000000000001",
      "00000000000000008000000000000000", // carry across the 64-bit lane boundary
      "00000000000000010000000000000000",
      "ffffffffffffffffffffffffffffffff",
      "7fffffffffffffffffffffffffffffff",
      "0123456789abcdeffedcba9876543210",
  };
  __u8 h[16];
  for (unsigned i = 0; i < sizeof(hs) / sizeof(hs[0]); i++) {
    hex_to_bytes(hs[i], h, 16);
    check_hkey1_roundtrip(h, h[0] >> 7);
  }
}

// ============================================================================
// GHASH engine: table multiply, span tag deltas
// ============================================================================

// xorshift64*: a fixed sequence, so a failure reproduces.
static __u64 rng_state = 0x9E3779B97F4A7C15ULL;
static __u64 rng64(void) {
  rng_state ^= rng_state >> 12;
  rng_state ^= rng_state << 25;
  rng_state ^= rng_state >> 27;
  return rng_state * 0x2545F4914F6CDD1DULL;
}

static void rng_bytes(__u8 *p, __u32 n) {
  for (__u32 i = 0; i < n; i++)
    p[i] = (__u8)(rng64() >> 56);
}

static struct gf128 rng_gf128(void) {
  struct gf128 v = {rng64(), rng64()};
  return v;
}

static int gf_eq(const struct gf128 *a, const struct gf128 *b) {
  return a->hi == b->hi && a->lo == b->lo;
}

static void gf_xor(struct gf128 *a, const struct gf128 *b) {
  a->hi ^= b->hi;
  a->lo ^= b->lo;
}

static void print_gf(const char *label, const struct gf128 *v) {
  printf("\n    %s: %016llx%016llx", label, (unsigned long long)v->hi,
         (unsigned long long)v->lo);
}

// The bit-serial multiply (gf128_mul, checked against the GCM spec's vectors
// above), on the engine's words.
static struct gf128 ref_mul(const struct gf128 *a, const struct gf128 *b) {
  __u8 ab[16], bb[16], rb[16];
  struct gf128 r;
  gf128_store(ab, a);
  gf128_store(bb, b);
  gf128_mul(ab, bb, rb);
  gf128_load(rb, &r);
  return r;
}

static __u64 rem4[16];

static struct gf128 table_mul(const struct gf128 *x, const struct gf128 *h) {
  struct gf128_table t;
  struct gf128 r = *x;
  gf128_table_init(&t, h);
  gf128_table_mul(&r, &t, rem4);
  return r;
}

static void test_gf128_words(void) {
  __u8 b[16], back[16];
  hex_to_bytes("66e94bd4ef8a2c3b884cfa59ca342b2e", b, 16);
  struct gf128 v;
  gf128_load(b, &v);
  assert(v.hi == 0x66e94bd4ef8a2c3bULL && v.lo == 0x884cfa59ca342b2eULL);
  gf128_store(back, &v);
  assert(bytes_equal(b, back, 16));

  // x * x^127 = x^128 = 1 + x + x^2 + x^7; x^0 * x = x.
  struct gf128 top = {0, 1}, one = {1ULL << 63, 0};
  gf128_mulx(&top);
  assert(top.hi == GF128_R && top.lo == 0);
  gf128_mulx(&one);
  assert(one.hi == 1ULL << 62 && one.lo == 0);
}

static void test_gf128_rem4(void) {
  // The reduction constants of the 4-bit method (Shoup; McGrew & Viega).
  static const __u64 want[16] = {0x0000, 0x1C20, 0x3840, 0x2460,
                                 0x7080, 0x6CA0, 0x48C0, 0x54E0,
                                 0xE100, 0xFD20, 0xD940, 0xC560,
                                 0x9180, 0x8DA0, 0xA9C0, 0xB5E0};
  for (int n = 0; n < 16; n++)
    assert(rem4[n] == want[n] << 48);
}

static void test_gf128_table_entries(void) {
  // m[n] = n * H, n read MSB-first: the bit-serial product of H and the
  // element whose first four coefficients are n's bits.
  struct gf128 h = rng_gf128();
  struct gf128_table t;
  gf128_table_init(&t, &h);
  for (__u64 n = 0; n < 16; n++) {
    struct gf128 e = {n << 60, 0};
    struct gf128 want = ref_mul(&e, &h);
    assert(gf_eq(&t.m[n], &want));
  }
}

static void check_table_mul(const struct gf128 *x, const struct gf128 *h) {
  struct gf128 want = ref_mul(x, h), got = table_mul(x, h);
  if (!gf_eq(&want, &got)) {
    print_gf("x   ", x);
    print_gf("h   ", h);
    print_gf("want", &want);
    print_gf("got ", &got);
  }
  assert(gf_eq(&want, &got));
}

static void test_gf128_table_mul(void) {
  // Edge elements: 0, 1, all ones, every single coefficient x^0 .. x^127,
  // and the GCM spec's H values; each against all of them.
  struct gf128 edge[136];
  int n = 0;
  edge[n++] = (struct gf128){0, 0};
  edge[n++] = (struct gf128){~0ULL, ~0ULL};
  for (int i = 0; i < 64; i++) {
    edge[n++] = (struct gf128){1ULL << (63 - i), 0};
    edge[n++] = (struct gf128){0, 1ULL << (63 - i)};
  }
  edge[n++] = (struct gf128){0x66e94bd4ef8a2c3bULL, 0x884cfa59ca342b2eULL};
  edge[n++] = (struct gf128){0xb83b533708bf535dULL, 0x0aa6e52980d53b78ULL};
  for (int i = 0; i < n; i++)
    for (int j = 0; j < n; j++)
      check_table_mul(&edge[i], &edge[j]);

  // Random elements, against the edges and against each other.
  for (int i = 0; i < 20000; i++) {
    struct gf128 x = rng_gf128(), h = rng_gf128();
    check_table_mul(&x, &h);
    check_table_mul(&x, &edge[i % n]);
    check_table_mul(&edge[i % n], &h);
  }

  // GCM spec test case 2: C * H = X1.
  struct gf128 h = {0x66e94bd4ef8a2c3bULL, 0x884cfa59ca342b2eULL};
  struct gf128 c = {0x0388dace60b6a392ULL, 0xf328c2b971b2fe78ULL};
  struct gf128 x1 = table_mul(&c, &h);
  assert(x1.hi == 0x5e2ec74691706288ULL && x1.lo == 0x2c85b0685353deb7ULL);
}

static void test_gf128_mul_by(void) {
  // gf128_mul_by builds y's table in the scratch table it is given, over
  // whatever was there.
  struct gf128_table scratch;
  memset(&scratch, 0x5A, sizeof(scratch));
  for (int i = 0; i < 2000; i++) {
    struct gf128 x = rng_gf128(), y = rng_gf128();
    struct gf128 want = ref_mul(&x, &y), got = x;
    gf128_mul_by(&got, &y, &scratch, rem4);
    assert(gf_eq(&want, &got));
    // Squaring, which builds the H^(2^i) powers: x and y the same element.
    want = ref_mul(&x, &x);
    got = x;
    gf128_mul_by(&got, &x, &scratch, rem4);
    assert(gf_eq(&want, &got));
  }
}

static void test_ghash_span_plan(void) {
  struct ghash_span s;
  // A 24-byte placeholder at offset 2 of a 26-byte ciphertext: blocks 0..1
  // of 2; the length block follows the last one.
  assert(ghash_span_plan(2, 24, 26, &s));
  assert(s.first == 0 && s.count == 2 && s.exp == 1);
  // One byte at the end of block 3 of 10 blocks: 6 blocks and the length
  // block after it.
  assert(ghash_span_plan(63, 1, 160, &s));
  assert(s.first == 3 && s.count == 1 && s.exp == 7);
  // A whole block, then the same byte count one byte later (two blocks).
  assert(ghash_span_plan(16, 16, 33, &s) && s.first == 1 && s.count == 1 && s.exp == 2);
  assert(ghash_span_plan(17, 16, 33, &s) && s.first == 1 && s.count == 2 && s.exp == 1);
  // The largest TLS 1.2 record (no AEAD record is longer): 1151 blocks, the
  // exponent of block 0 at most 1151, 11 bits.
  __u32 ct12 = TLS_MAX_RECORD_LEN - 8 - 16;
  assert(ghash_span_plan(0, 1, ct12, &s) && s.exp == (ct12 + 15) / 16);
  assert(s.exp < (1u << GHASH_POW_BITS));
  assert(ghash_span_plan(0, ct12, ct12, &s) && s.count == (ct12 + 15) / 16 && s.exp == 1);
  assert(ghash_span_plan(0, 1, GHASH_MAX_CT_BLOCKS * 16, &s) &&
         s.exp == GHASH_MAX_CT_BLOCKS);

  // Not hashable: empty, past the ciphertext (at its end, running over it,
  // offsets so large that sec_off + len wraps), too long a record.
  assert(!ghash_span_plan(2, 0, 26, &s));
  assert(!ghash_span_plan(26, 1, 26, &s));
  assert(!ghash_span_plan(3, 24, 26, &s));
  assert(!ghash_span_plan(0, 27, 26, &s));
  assert(!ghash_span_plan(0xFFFFFFF0u, 0x20, 26, &s));
  assert(!ghash_span_plan(2, 0xFFFFFFFFu, 26, &s));
  assert(!ghash_span_plan(0, 1, GHASH_MAX_CT_BLOCKS * 16 + 1, &s));
}

// The bytes of block b under a patch of len bytes at sec_off whose delta
// byte d is delta[d] (the engine's words).
static struct gf128 block_delta_ref(const __u8 *delta, __u32 b, __u32 sec_off,
                                    __u32 len) {
  __u8 out[16] = {0};
  for (__u32 i = 0; i < 16; i++) {
    __u64 pos = (__u64)(b & GHASH_MAX_CT_BLOCKS) * 16 + i;
    if (pos >= sec_off && pos < (__u64)sec_off + len)
      out[i] = delta[pos - sec_off];
  }
  struct gf128 v;
  gf128_load(out, &v);
  return v;
}

static void test_ghash_block_delta64(void) {
  __u8 xor_delta[SECRET_MAX_LEN];
  for (int i = 0; i < SECRET_MAX_LEN; i++)
    xor_delta[i] = (__u8)(i * 37 + 1); // no zero bytes, so a miss shows

  // The inline xor_delta window: every patch at every offset in the first
  // 400 bytes, against every block it can touch and its neighbours, and
  // blocks past 1023 (the old byte-wise gather's 10-bit mask) up to the
  // last one an 11-bit exponent covers, and past it (masked).
  for (__u32 len = 1; len <= SECRET_MAX_LEN; len++) {
    for (__u32 sec_off = 0; sec_off < 400; sec_off++)
      for (__u32 b = 0; b < 35; b++) {
        struct gf128 want = block_delta_ref(xor_delta, b, sec_off, len), got;
        ghash_block_delta64(xor_delta, SECRET_MAX_LEN - 1, b, sec_off, len, &got);
        assert(gf_eq(&want, &got));
      }
    // And offsets so large that a 32-bit sec_off + len wraps.
    static const __u32 offs[] = {16352, 16367, 16368, 16383, 16384, 18400, 32750,
                                 0xFFFFFFFFu - SECRET_MAX_LEN, 0xFFFFFFF0u,
                                 0xFFFFFFFFu};
    static const __u32 blocks[] = {0,    1,    1022, 1023, 1024,       1025,
                                   1150, 2046, 2047, 2048, 0xFFFFFFFFu};
    for (unsigned o = 0; o < sizeof(offs) / sizeof(offs[0]); o++)
      for (unsigned k = 0; k < sizeof(blocks) / sizeof(blocks[0]); k++) {
        struct gf128 want = block_delta_ref(xor_delta, blocks[k], offs[o], len), got;
        ghash_block_delta64(xor_delta, SECRET_MAX_LEN - 1, blocks[k], offs[o], len, &got);
        assert(gf_eq(&want, &got));
      }
  }

  // A ring of two 256-byte chunks (a delta longer than any window): chunk c
  // of the patch's delta at (c * 256) & 511. The ring holds the chunk of a
  // block's first delta byte and the next, which is all of the block's.
  static __u8 delta[8192];
  rng_bytes(delta, sizeof(delta));
  for (int t = 0; t < 4000; t++) {
    __u32 len = 1 + rng64() % 8000;
    __u32 sec_off = rng64() % 20000;
    __u32 first = sec_off / 16, last = (sec_off + len - 1) / 16;
    __u32 b = first + rng64() % (last - first + 1);
    __u8 ring[512];
    memset(ring, 0xEE, sizeof(ring));
    int64_t d0 = (int64_t)b * 16 - sec_off; // the block's first delta byte
    __u32 c = d0 < 0 ? 0 : (__u32)d0 / 256;
    for (__u32 cc = c; cc <= c + 1 && cc * 256 < len; cc++)
      memcpy(ring + (cc * 256) % 512, delta + cc * 256,
             len - cc * 256 < 256 ? len - cc * 256 : 256);
    struct gf128 want = block_delta_ref(delta, b, sec_off, len), got;
    ghash_block_delta64(ring, 511, b, sec_off, len, &got);
    assert(gf_eq(&want, &got));
  }
}

// The engine's H state, as tc's per-connection cache keeps it: H's table and
// H^(2^i) for i < GHASH_POW_BITS (squared with gf128_mul_by, as tc builds
// them).
struct engine_key {
  struct gf128_table ht;
  struct gf128 pow[GHASH_POW_BITS];
};

static void engine_key_init(struct engine_key *k, const struct gf128 *h) {
  struct gf128_table scratch;
  gf128_table_init(&k->ht, h);
  k->pow[0] = *h;
  for (int i = 1; i < GHASH_POW_BITS; i++) {
    k->pow[i] = k->pow[i - 1];
    gf128_mul_by(&k->pow[i], &k->pow[i - 1], &scratch, rem4);
  }
}

// The tag delta of a patch, step by step as tc_ghash_update's callbacks run
// it: one ghash_horner_step per block of the span, one ghash_pow_step per
// exponent bit. delta is a window of win_mask + 1 bytes (see
// ghash_block_delta64). Returns 0 when ghash_span_plan refuses the patch.
static int engine_span_delta(const struct engine_key *k, const __u8 *delta,
                             __u32 win_mask, __u32 sec_off, __u32 len,
                             __u32 ct_len, struct gf128 *out) {
  struct ghash_span s;
  if (!ghash_span_plan(sec_off, len, ct_len, &s))
    return 0;
  struct gf128 acc = {0, 0};
  for (__u32 i = 0; i < s.count; i++) {
    struct gf128 d;
    ghash_block_delta64(delta, win_mask, s.first + i, sec_off, len, &d);
    ghash_horner_step(&acc, &d, &k->ht, rem4);
  }
  struct gf128_table scratch;
  for (__u32 bit = 0; bit < GHASH_POW_BITS; bit++)
    ghash_pow_step(&acc, s.exp, bit, &k->pow[bit], &scratch, rem4);
  *out = acc;
  return 1;
}

// H^1 .. H^GHASH_MAX_CT_BLOCKS+1 by repeated bit-serial multiplication.
static struct gf128 ref_pow[GHASH_MAX_CT_BLOCKS + 2];

static void ref_pow_init(const struct gf128 *h) {
  ref_pow[0] = (struct gf128){1ULL << 63, 0};
  for (__u32 i = 1; i < GHASH_MAX_CT_BLOCKS + 2; i++)
    ref_pow[i] = ref_mul(&ref_pow[i - 1], h);
}

// The tag delta as the old tc code computed it: every block the patch
// touches times H^(n + 1 - b), each its own power.
static struct gf128 naive_span_delta(const __u8 *delta, __u32 sec_off,
                                     __u32 len, __u32 ct_len) {
  __u32 n = (ct_len + 15) / 16;
  struct gf128 sum = {0, 0};
  for (__u32 b = sec_off / 16; b <= (sec_off + len - 1) / 16; b++) {
    struct gf128 d = block_delta_ref(delta, b, sec_off, len);
    struct gf128 c = ref_mul(&d, &ref_pow[n + 1 - b]);
    gf_xor(&sum, &c);
  }
  return sum;
}

static __u8 span_delta_buf[32768];

static void check_span(const struct engine_key *k, __u32 sec_off, __u32 len,
                       __u32 ct_len) {
  struct gf128 want = naive_span_delta(span_delta_buf, sec_off, len, ct_len), got;
  assert(engine_span_delta(k, span_delta_buf, sizeof(span_delta_buf) - 1,
                           sec_off, len, ct_len, &got));
  if (!gf_eq(&want, &got)) {
    printf("\n    sec_off=%u len=%u ct_len=%u", sec_off, len, ct_len);
    print_gf("want", &want);
    print_gf("got ", &got);
  }
  assert(gf_eq(&want, &got));
}

static void test_ghash_span_vs_naive(void) {
  struct gf128 h = rng_gf128();
  struct engine_key k;
  engine_key_init(&k, &h);
  ref_pow_init(&h);
  for (int i = 1; i < GHASH_POW_BITS; i++)
    assert(gf_eq(&k.pow[i], &ref_pow[1u << i]));
  rng_bytes(span_delta_buf, sizeof(span_delta_buf));

  const __u32 ct13 = 16384 + 256;                 // largest TLS 1.3 ciphertext
  const __u32 ct12 = TLS_MAX_RECORD_LEN - 8 - 16; // largest TLS 1.2 one

  // Short patches: every alignment, every length up to 4 blocks, records
  // ending with the patch or later.
  for (__u32 a = 0; a < 16; a++)
    for (__u32 len = 1; len <= 64; len++)
      for (__u32 base = 0; base <= 48; base += 48) {
        __u32 off = base + a;
        static const __u32 extra[] = {0, 1, 17, 1000};
        for (unsigned e = 0; e < 4; e++)
          check_span(&k, off, len, off + len + extra[e]);
        check_span(&k, off, len, ct13);
      }

  // Long patches, up to a whole record, at every alignment.
  static const __u32 lens[] = {127,  128,  129,  255,  256,  257,   1000,
                               1024, 4095, 4096, 4097, 8191, 16383, 16384};
  for (unsigned l = 0; l < sizeof(lens) / sizeof(lens[0]); l++)
    for (__u32 a = 0; a < 16; a++) {
      __u32 len = lens[l], off = a;
      check_span(&k, off, len, off + len);
      check_span(&k, off, len, off + len + 15);
      check_span(&k, off, len, ct12);
      if (off + len <= ct13)
        check_span(&k, off, len, ct13);
      check_span(&k, ct12 - len - a, len, ct12); // ending a's bytes from the end
    }
  check_span(&k, 0, ct12, ct12);
  check_span(&k, 0, ct13, ct13);

  // Random patches in random records.
  for (int t = 0; t < 500; t++) {
    __u32 ct_len = 1 + rng64() % ct12;
    __u32 sec_off = rng64() % ct_len;
    __u32 len = 1 + rng64() % (ct_len - sec_off);
    if (t % 2)
      len = 1 + len % 300; // placeholder-sized, more often
    check_span(&k, sec_off, len, ct_len);
  }
}

// GHASH(H, A, C) by the definition (NIST SP 800-38D §6.4), bit-serial.
static struct gf128 ref_ghash(const struct gf128 *h, const __u8 *a, __u32 alen,
                              const __u8 *c, __u32 clen) {
  struct gf128 x = {0, 0};
  const __u8 *parts[2] = {a, c};
  __u32 lens[2] = {alen, clen};
  for (int p = 0; p < 2; p++)
    for (__u32 i = 0; i < lens[p]; i += 16) {
      __u8 blk[16] = {0};
      memcpy(blk, parts[p] + i, lens[p] - i < 16 ? lens[p] - i : 16);
      struct gf128 v;
      gf128_load(blk, &v);
      gf_xor(&x, &v);
      x = ref_mul(&x, h);
    }
  struct gf128 l = {(__u64)alen * 8, (__u64)clen * 8};
  gf_xor(&x, &l);
  return ref_mul(&x, h);
}

static void test_ghash_span_vs_definition(void) {
  // The GCM spec's test cases 3 and 4: H, ciphertext, AAD and GHASH. The
  // engine computes GHASH itself as the tag delta of "patching" an all-zero
  // ciphertext into C (whose GHASH is the length block's L * H).
  __u8 hb[16], c[64], a[20], g3[16], g4[16];
  hex_to_bytes("b83b533708bf535d0aa6e52980d53b78", hb, 16);
  hex_to_bytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
               "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
               c, 64);
  hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2", a, 20);
  hex_to_bytes("7f1b32b81b820d02614f8895ac1d4eac", g3, 16);
  hex_to_bytes("698e57f70e6ecc7fd9463b7260a9ae5f", g4, 16);
  struct gf128 h, want3, want4;
  gf128_load(hb, &h);
  gf128_load(g3, &want3);
  gf128_load(g4, &want4);
  struct gf128 r3 = ref_ghash(&h, NULL, 0, c, 64), r4 = ref_ghash(&h, a, 20, c, 60);
  assert(gf_eq(&r3, &want3) && gf_eq(&r4, &want4));

  struct engine_key k;
  engine_key_init(&k, &h);
  struct gf128 got3, got4;
  static __u8 win[SECRET_MAX_LEN];
  memset(win, 0, sizeof(win));
  memcpy(win, c, 64);
  assert(engine_span_delta(&k, win, SECRET_MAX_LEN - 1, 0, 64, 64, &got3));
  struct gf128 z3 = ref_ghash(&h, NULL, 0, (const __u8[64]){0}, 64);
  gf_xor(&got3, &z3);
  assert(gf_eq(&got3, &want3));
  assert(engine_span_delta(&k, win, SECRET_MAX_LEN - 1, 0, 60, 60, &got4));
  struct gf128 z4 = ref_ghash(&h, a, 20, (const __u8[60]){0}, 60);
  gf_xor(&got4, &z4);
  assert(gf_eq(&got4, &want4));

  // Random records with a TLS 1.2 AAD (13 bytes): the tag delta of
  // patching C into C' is GHASH(A, C') ^ GHASH(A, C), up to the largest
  // record, one to four patches each (two of them may share a block).
  static __u8 ct[TLS_MAX_RECORD_LEN], patched[TLS_MAX_RECORD_LEN];
  static const __u32 sizes[] = {17, 100, 1500, 4096, 16384 + 256,
                                TLS_MAX_RECORD_LEN - 8 - 16};
  for (unsigned s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
    for (int t = 0; t < 4; t++) {
      __u32 ct_len = sizes[s];
      struct gf128 hk = rng_gf128();
      engine_key_init(&k, &hk);
      __u8 aad[13];
      rng_bytes(aad, 13);
      rng_bytes(ct, ct_len);
      memcpy(patched, ct, ct_len);
      struct gf128 sum = {0, 0};
      __u32 npatch = 1 + t, at = rng64() % 40;
      for (__u32 p = 0; p < npatch && at < ct_len; p++) {
        __u32 len = 1 + rng64() % SECRET_MAX_LEN;
        if (len > ct_len - at)
          len = ct_len - at;
        __u8 d[SECRET_MAX_LEN] = {0};
        rng_bytes(d, len);
        for (__u32 i = 0; i < len; i++)
          patched[at + i] ^= d[i];
        struct gf128 one;
        assert(engine_span_delta(&k, d, SECRET_MAX_LEN - 1, at, len, ct_len, &one));
        gf_xor(&sum, &one);
        at += len + rng64() % (ct_len / 4 + 1); // 0: the next patch shares a block
      }
      struct gf128 before = ref_ghash(&hk, aad, 13, ct, ct_len);
      struct gf128 after = ref_ghash(&hk, aad, 13, patched, ct_len);
      gf_xor(&after, &before);
      assert(gf_eq(&sum, &after));
    }
}

static void test_ghash_span_vs_go_gcm(void) {
  // Tag deltas from Go's crypto/cipher GCM (AES-128 and AES-256, a random
  // 13-byte AAD): Seal(P) ^ Seal(P ^ delta at off), the tags only. Cases:
  // the tc fixture's shape, the largest TLS 1.3 ciphertext with a
  // placeholder at its start and a full-size one at its end, the largest
  // TLS 1.2 one, a patch across blocks 1023/1024, a mid-size record.
  static const struct {
    const char *h;
    __u32 ct_len, off;
    const char *delta, *want;
  } v[] = {
      {"25d5215d0dea6f003ad099040ce385eb", 26, 2, "6f140d24abc4c0b707c2057d6f8f32951ec04a6cf5ddc3b1",
       "7b17ad5063eeaaf9ca0b5f0bcece510c"},
      {"a27112340e58c1019a2a68230abab4fc", 16640, 3, "67b679734830791249e89293a065311132c0972ea1183e7d",
       "07002daf6e6db7566eb4e76c21e70db0"},
      {"89ff96f22532ac84f2d632e291075d9d", 16640, 16512,
       "6d13ed76b635bd10719db7178ff5ed13f391f7a4dd73f75b478d1e8256fb401c4fbc33bcf8810c5d4736dc9e1234f50c"
       "02cd5efc796179aee16ec80e63206c4e628d5f510f0dec4814f938e098245108117a64cb46d2aee0dd6525cdcbd530bf"
       "c9147b96225b4db88b76bdf43c68b3ab8ba1143a2d4685ccc0c0c5ebc64a9109",
       "784d0d8ecda2c178ff15f596c4f12505"},
      {"63d839b1721b2c13d9eb659955f3c50c", 18408, 1029,
       "ef6b04b80c787983bb7162bb2a3db7ee85d9aa62e47b11166d99f15af206e0a2f6716ac2e68bc5edfc22f20b68f0fa91"
       "c8763bf2690d9fdcfe6e3a79dd09c61a0c1f4a1c6215e56b4a48d77106",
       "5c77a53fa6952561005de00924ba8baf"},
      {"20920db436d539e7e65de4f45a78ac94", 18408, 16371,
       "c144a79cb46299cbbc5c725e37807c883e69cd5bcd1606f72e650226037ca538dd08db61d1251ac7",
       "807b465d4cdf4c2e169873c04411f668"},
      {"cb317e55fd37b4a6131af74e408f05b0", 4096, 17,
       "681b8dfc4593e37edb931d870715518506dcdd2dc298da2c40e0b48bb6e75a84abed74c15047a8046d2cae29659146c9"
       "7b7f6b5be32a27267f439ad9169541ef2e819f3aa2881c364c38bf387b2f1d23d97bb4c4791d892d7ce3c0f6f4b94918"
       "6c24676b496c3bbf995d71a9c4c72366bdbdc268c6047ee35d5d975ccd0c87a1",
       "d3b0fe8a774f303e43e6bf600e9c1944"},
  };
  for (unsigned i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
    __u8 hb[16], wb[16], d[SECRET_MAX_LEN] = {0};
    __u32 len = strlen(v[i].delta) / 2;
    assert(len <= SECRET_MAX_LEN);
    hex_to_bytes(v[i].h, hb, 16);
    hex_to_bytes(v[i].want, wb, 16);
    hex_to_bytes(v[i].delta, d, len);
    struct gf128 h, want, got;
    gf128_load(hb, &h);
    gf128_load(wb, &want);
    struct engine_key k;
    engine_key_init(&k, &h);
    assert(engine_span_delta(&k, d, SECRET_MAX_LEN - 1, v[i].off, len, v[i].ct_len, &got));
    assert(gf_eq(&got, &want));
  }
}

// ============================================================================
// main
// ============================================================================

// ============================================================================
// tls_parse_sni
// ============================================================================

#include "tls_sni_fixtures.h"

static __u32 parse_sni(const unsigned char *ch, __u32 len, char host[MAX_HOST_LEN],
                       __u32 *host_len) {
  // The BPF caller parses a TLS_SNI_BUF_LEN scratch copy; mirror that.
  static __u8 buf[TLS_SNI_BUF_LEN];
  memset(buf, 0, sizeof(buf));
  memcpy(buf, ch, len < sizeof(buf) ? len : sizeof(buf));
  memset(host, 0, MAX_HOST_LEN);
  return tls_parse_sni(buf, len, host, host_len);
}

static void assert_sni(const unsigned char *ch, __u32 len, const char *want) {
  char host[MAX_HOST_LEN];
  __u32 n = 0;
  assert(parse_sni(ch, len, host, &n) == SNI_STATUS_SEEN);
  assert(n == strlen(want));
  assert(memcmp(host, want, n) == 0);
  // Zero-padded, so hosts_match against a synced allowed_host works.
  for (__u32 i = n; i < MAX_HOST_LEN; i++)
    assert(host[i] == 0);
}

static void test_sni_go(void) { assert_sni(ch_go, sizeof(ch_go), "api.example.com"); }
static void test_sni_node(void) { assert_sni(ch_node, sizeof(ch_node), "api.example.com"); }
static void test_sni_bun(void) { assert_sni(ch_bun, sizeof(ch_bun), "api.example.com"); }

static void test_sni_lowercase_trailing_dot(void) {
  // Python sent "API.Example.com." verbatim.
  assert_sni(ch_py, sizeof(ch_py), "api.example.com");
}

static void test_sni_absent(void) {
  char host[MAX_HOST_LEN];
  __u32 n = 7;
  assert(parse_sni(ch_py_nosni, sizeof(ch_py_nosni), host, &n) == SNI_STATUS_ABSENT);
  assert(n == 0);
}

static void test_sni_truncated_real(void) {
  // A prefix of a real ClientHello is TRUNCATED until every extension header
  // (type + length) is inside it: an unseen header could be ECH. Only the
  // body of the last extension may be cut (Go's ~1.2 KB key_share ends the
  // list), since bodies other than server_name are skipped, not read.
  char host[MAX_HOST_LEN];
  __u32 n;
  int seen = 0;
  for (__u32 len = 0; len < sizeof(ch_go); len++) {
    __u32 st = parse_sni(ch_go, len, host, &n);
    if (st == SNI_STATUS_SEEN) {
      seen = 1;
      assert(n == 15 && memcmp(host, "api.example.com", 15) == 0);
      continue;
    }
    assert(!seen); // once every header is in, longer prefixes stay SEEN
    assert(st == SNI_STATUS_TRUNCATED || st == SNI_NOT_CLIENT_HELLO);
  }
}

static void test_sni_not_client_hello(void) {
  char host[MAX_HOST_LEN];
  __u32 n;
  unsigned char appdata[64] = {0x17, 0x03, 0x03, 0x00, 0x3b};
  assert(parse_sni(appdata, sizeof(appdata), host, &n) == SNI_NOT_CLIENT_HELLO);
  unsigned char server_hello[64] = {0x16, 0x03, 0x03, 0x00, 0x3b, 0x02};
  assert(parse_sni(server_hello, sizeof(server_hello), host, &n) == SNI_NOT_CLIENT_HELLO);
  unsigned char http[] = "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
  assert(parse_sni(http, sizeof(http) - 1, host, &n) == SNI_NOT_CLIENT_HELLO);
}

// build_ch wraps an extensions block in a minimal ClientHello record.
static __u32 build_ch(unsigned char *out, const unsigned char *exts, __u32 exts_len) {
  __u32 body = 2 + 32 + 1 + 4 + 2 + 2 + exts_len; // version..compression + ext len
  __u32 o = 0;
  out[o++] = 0x16; out[o++] = 0x03; out[o++] = 0x01;
  out[o++] = (unsigned char)((body + 4) >> 8); out[o++] = (unsigned char)(body + 4);
  out[o++] = 0x01;
  out[o++] = 0; out[o++] = (unsigned char)(body >> 8); out[o++] = (unsigned char)body;
  out[o++] = 0x03; out[o++] = 0x03;
  memset(out + o, 0xAB, 32); o += 32;  // random
  out[o++] = 0;                        // session_id
  out[o++] = 0; out[o++] = 2; out[o++] = 0x13; out[o++] = 0x01; // one cipher suite
  out[o++] = 1; out[o++] = 0;          // null compression
  out[o++] = (unsigned char)(exts_len >> 8); out[o++] = (unsigned char)exts_len;
  memcpy(out + o, exts, exts_len);
  return o + exts_len;
}

// sni_ext appends a server_name extension with one host_name entry.
static __u32 sni_ext(unsigned char *out, const char *name, __u32 name_len) {
  __u32 o = 0;
  out[o++] = 0; out[o++] = 0;
  out[o++] = (unsigned char)((name_len + 5) >> 8); out[o++] = (unsigned char)(name_len + 5);
  out[o++] = (unsigned char)((name_len + 3) >> 8); out[o++] = (unsigned char)(name_len + 3);
  out[o++] = 0;
  out[o++] = (unsigned char)(name_len >> 8); out[o++] = (unsigned char)name_len;
  memcpy(out + o, name, name_len);
  return o + name_len;
}

static __u32 dummy_ext(unsigned char *out, __u32 type, __u32 len) {
  out[0] = (unsigned char)(type >> 8); out[1] = (unsigned char)type;
  out[2] = (unsigned char)(len >> 8); out[3] = (unsigned char)len;
  memset(out + 4, 0x5A, len);
  return 4 + len;
}

static void test_sni_synthetic(void) {
  unsigned char exts[256], ch[512];
  __u32 e = sni_ext(exts, "Svc.NS.svc.cluster.local", 24);
  __u32 len = build_ch(ch, exts, e);
  assert_sni(ch, len, "svc.ns.svc.cluster.local");
}

static void test_sni_ech_wins(void) {
  // ECH before or after a readable server_name: the outer SNI is not the
  // real host, refuse either way.
  unsigned char exts[256], ch[512];
  char host[MAX_HOST_LEN];
  __u32 n;
  __u32 e = sni_ext(exts, "api.example.com", 15);
  e += dummy_ext(exts + e, TLS_EXT_ECH, 32);
  __u32 len = build_ch(ch, exts, e);
  assert(parse_sni(ch, len, host, &n) == SNI_STATUS_ECH);

  e = dummy_ext(exts, TLS_EXT_ECH, 32);
  e += sni_ext(exts + e, "api.example.com", 15);
  len = build_ch(ch, exts, e);
  assert(parse_sni(ch, len, host, &n) == SNI_STATUS_ECH);
}

static void test_sni_rejects_bad_host_bytes(void) {
  unsigned char exts[256], ch[512];
  char host[MAX_HOST_LEN];
  __u32 n;
  // Embedded NUL would compare equal to a zero-padded "api.example.com".
  __u32 len = build_ch(ch, exts, sni_ext(exts, "api.example.com\0evil", 20));
  assert(parse_sni(ch, len, host, &n) == SNI_STATUS_MALFORMED);
  len = build_ch(ch, exts, sni_ext(exts, "api example.com", 15));
  assert(parse_sni(ch, len, host, &n) == SNI_STATUS_MALFORMED);
  // A lone "." strips to an empty host.
  len = build_ch(ch, exts, sni_ext(exts, ".", 1));
  assert(parse_sni(ch, len, host, &n) == SNI_STATUS_MALFORMED);
}

static void test_sni_too_long(void) {
  unsigned char exts[256], ch[512];
  char host[MAX_HOST_LEN], name[MAX_HOST_LEN];
  __u32 n;
  memset(name, 'a', sizeof(name));
  // MAX_HOST_LEN - 1 fits (sync rejects hosts >= MAX_HOST_LEN), MAX_HOST_LEN does not.
  __u32 len = build_ch(ch, exts, sni_ext(exts, name, MAX_HOST_LEN - 1));
  assert(parse_sni(ch, len, host, &n) == SNI_STATUS_SEEN && n == MAX_HOST_LEN - 1);
  len = build_ch(ch, exts, sni_ext(exts, name, MAX_HOST_LEN));
  assert(parse_sni(ch, len, host, &n) == SNI_STATUS_MALFORMED);
}

static void test_sni_duplicate_server_name(void) {
  unsigned char exts[256], ch[512];
  char host[MAX_HOST_LEN];
  __u32 n;
  __u32 e = sni_ext(exts, "api.example.com", 15);
  e += sni_ext(exts + e, "evil.example", 12);
  __u32 len = build_ch(ch, exts, e);
  assert(parse_sni(ch, len, host, &n) == SNI_STATUS_MALFORMED);
}

static void test_sni_lying_lengths(void) {
  unsigned char exts[256], ch[512];
  char host[MAX_HOST_LEN];
  __u32 n;
  __u32 e = sni_ext(exts, "api.example.com", 15);
  __u32 len = build_ch(ch, exts, e);

  unsigned char bad[512];
  // Extension length runs past the extensions block.
  memcpy(bad, ch, len);
  bad[len - e + 3] = 0xFF;
  assert(parse_sni(bad, len, host, &n) == SNI_STATUS_MALFORMED);
  // Host name length disagrees with the extension length.
  memcpy(bad, ch, len);
  bad[len - 15 - 1] = 14;
  assert(parse_sni(bad, len, host, &n) == SNI_STATUS_MALFORMED);
  // Handshake longer than its record.
  memcpy(bad, ch, len);
  bad[4] = (unsigned char)(bad[4] - 1);
  assert(parse_sni(bad, len, host, &n) == SNI_STATUS_MALFORMED);
  // Extensions block shorter than the handshake says.
  memcpy(bad, ch, len);
  bad[len - e - 1] = (unsigned char)(bad[len - e - 1] - 1);
  assert(parse_sni(bad, len, host, &n) == SNI_STATUS_MALFORMED);
}

static void test_sni_too_many_extensions(void) {
  unsigned char exts[512], ch[1024];
  char host[MAX_HOST_LEN];
  __u32 n;
  __u32 e = 0;
  for (int i = 0; i < TLS_SNI_MAX_EXTS; i++)
    e += dummy_ext(exts + e, 0x1000 + (__u32)i, 0);
  e += sni_ext(exts + e, "api.example.com", 15);
  __u32 len = build_ch(ch, exts, e);
  // server_name sits past the walk limit: not trusted.
  assert(parse_sni(ch, len, host, &n) == SNI_STATUS_MALFORMED);
}

static void test_sni_past_copy_buffer(void) {
  // server_name after TLS_SNI_BUF_LEN bytes of padding: TRUNCATED.
  static unsigned char exts[TLS_SNI_BUF_LEN + 64], ch[TLS_SNI_BUF_LEN + 192];
  char host[MAX_HOST_LEN];
  __u32 n;
  __u32 e = dummy_ext(exts, 0x0015, TLS_SNI_BUF_LEN); // padding extension
  e += sni_ext(exts + e, "api.example.com", 15);
  __u32 len = build_ch(ch, exts, e);
  assert(len > TLS_SNI_BUF_LEN);
  assert(parse_sni(ch, len, host, &n) == SNI_STATUS_TRUNCATED);
}

// ============================================================================
// DNS answer walks (dns_parse_question, dns_scan_addr_records)
// ============================================================================

struct dns_msg {
  __u8 b[MAX_DNS_PKT];
  __u32 len;
};

static void dm_u8(struct dns_msg *m, __u8 v) {
  assert(m->len < MAX_DNS_PKT);
  m->b[m->len++] = v;
}

static void dm_u16(struct dns_msg *m, __u16 v) {
  dm_u8(m, (__u8)(v >> 8));
  dm_u8(m, (__u8)v);
}

static void dm_u32(struct dns_msg *m, __u32 v) {
  dm_u16(m, (__u16)(v >> 16));
  dm_u16(m, (__u16)v);
}

// dm_name writes a dotted name as uncompressed labels.
static void dm_name(struct dns_msg *m, const char *name) {
  while (*name) {
    const char *dot = strchr(name, '.');
    __u32 n = dot ? (__u32)(dot - name) : (__u32)strlen(name);
    dm_u8(m, (__u8)n);
    for (__u32 i = 0; i < n; i++)
      dm_u8(m, (__u8)name[i]);
    name += n;
    if (*name == '.')
      name++;
  }
  dm_u8(m, 0);
}

static void dm_ptr(struct dns_msg *m, __u16 off) { dm_u16(m, 0xC000 | off); }

// dm_response starts a NOERROR response (QR, RD, RA) with one question.
static void dm_response(struct dns_msg *m, const char *qname, __u16 qtype,
                        __u16 ancount) {
  memset(m, 0, sizeof(*m));
  dm_u16(m, 0x1234); // ID
  dm_u16(m, 0x8180); // flags
  dm_u16(m, 1);      // QDCOUNT
  dm_u16(m, ancount);
  dm_u16(m, 0); // NSCOUNT
  dm_u16(m, 0); // ARCOUNT
  dm_name(m, qname);
  dm_u16(m, qtype);
  dm_u16(m, DNS_CLASS_IN);
}

// dm_rr writes a record's fixed part and rdata; the owner name comes first.
static void dm_rr(struct dns_msg *m, __u16 type, __u32 ttl, const __u8 *rdata,
                  __u16 rdlen) {
  dm_u16(m, type);
  dm_u16(m, DNS_CLASS_IN);
  dm_u32(m, ttl);
  dm_u16(m, rdlen);
  for (__u16 i = 0; i < rdlen; i++)
    dm_u8(m, rdata[i]);
}

static void dm_a(struct dns_msg *m, __u32 ttl, __u8 a, __u8 b, __u8 c, __u8 d) {
  __u8 ip[4] = {a, b, c, d};
  dm_rr(m, DNS_TYPE_A, ttl, ip, 4);
}

// dm_aaaa writes an AAAA record for 2001:db8::<last>.
static void dm_aaaa(struct dns_msg *m, __u32 ttl, __u8 last) {
  __u8 ip[16] = {0x20, 0x01, 0x0d, 0xb8};
  ip[15] = last;
  dm_rr(m, DNS_TYPE_AAAA, ttl, ip, 16);
}

static __u32 dns_question(const struct dns_msg *m, struct dns_question *q) {
  memset(q, 0, sizeof(*q));
  return dns_parse_question(m->b, m->len, q);
}

static __u32 dns_answers(const struct dns_msg *m, struct dns_answers *a) {
  struct dns_question q;
  assert(dns_question(m, &q) == DNS_SCAN_OK);
  memset(a, 0, sizeof(*a));
  return dns_scan_addr_records(m->b, m->len, q.answers_off, q.ancount, q.qtype, a);
}

static void test_dns_question_basic(void) {
  struct dns_msg m;
  dm_response(&m, "API.Example.COM", DNS_TYPE_A, 1);
  __u32 answers = m.len;
  dm_ptr(&m, 12);
  dm_a(&m, 30, 10, 0, 0, 1);

  struct dns_question q;
  assert(dns_question(&m, &q) == DNS_SCAN_OK);
  assert(q.qname_len == 15);
  assert(memcmp(q.qname, "api.example.com", 16) == 0); // zero-padded
  assert(q.qtype == DNS_TYPE_A);
  assert(q.ancount == 1);
  assert(q.answers_off == answers);

  dm_response(&m, "api.example.com", DNS_TYPE_AAAA, 1);
  assert(dns_question(&m, &q) == DNS_SCAN_OK);
  assert(q.qtype == DNS_TYPE_AAAA);
}

static void test_dns_question_not_an_answer(void) {
  struct dns_msg m;
  struct dns_question q;
  struct {
    __u8 byte, value;
  } cases[] = {
      {2, 0x01}, // a query (QR = 0)
      {2, 0x83}, // truncated (TC = 1)
      {2, 0x89}, // opcode 1 (IQUERY)
      {3, 0x83}, // NXDOMAIN
      {5, 2},    // two questions
      {7, 0},    // no answers
  };
  for (__u32 i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    dm_response(&m, "api.example.com", DNS_TYPE_A, 1);
    dm_ptr(&m, 12);
    dm_a(&m, 30, 10, 0, 0, 1);
    m.b[cases[i].byte] = cases[i].value;
    assert(dns_question(&m, &q) == DNS_SCAN_NOT_ANSWER);
  }
  // Shorter than a header, cut inside the name, cut before QTYPE/QCLASS.
  dm_response(&m, "api.example.com", DNS_TYPE_A, 1);
  assert(dns_parse_question(m.b, 11, &q) == DNS_SCAN_NOT_ANSWER);
  memset(&q, 0, sizeof(q));
  assert(dns_parse_question(m.b, 20, &q) == DNS_SCAN_NOT_ANSWER);
  memset(&q, 0, sizeof(q));
  assert(dns_parse_question(m.b, m.len - 1, &q) == DNS_SCAN_NOT_ANSWER);
}

static void test_dns_question_bad_names(void) {
  struct dns_msg m;
  struct dns_question q;
  const char *bad[] = {
      "a b.example.com",  // space
      "ex\x01mple.com",   // control byte
      "",                 // root
  };
  for (__u32 i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    dm_response(&m, bad[i], DNS_TYPE_A, 1);
    assert(dns_question(&m, &q) == DNS_SCAN_BAD_NAME);
  }

  // A '.' inside a label (escaped dot) must not read as a label boundary.
  dm_response(&m, "x", DNS_TYPE_A, 1);
  m.len = 12;
  dm_u8(&m, 3);
  dm_u8(&m, 'a');
  dm_u8(&m, '.');
  dm_u8(&m, 'b');
  dm_u8(&m, 0);
  dm_u16(&m, DNS_TYPE_A);
  dm_u16(&m, DNS_CLASS_IN);
  assert(dns_question(&m, &q) == DNS_SCAN_BAD_NAME);

  // A compression pointer in the question.
  dm_response(&m, "x", DNS_TYPE_A, 1);
  m.len = 12;
  dm_ptr(&m, 12);
  dm_u16(&m, DNS_TYPE_A);
  dm_u16(&m, DNS_CLASS_IN);
  assert(dns_question(&m, &q) == DNS_SCAN_BAD_NAME);
}

static void test_dns_question_name_length(void) {
  // 63 bytes, the longest host kloak watches: accepted.
  char name[80];
  memset(name, 'a', sizeof(name));
  memcpy(name + 59, ".com", 5); // 59 + 4 = 63 bytes, NUL included above
  assert(strlen(name) == 63);
  struct dns_msg m;
  struct dns_question q;
  dm_response(&m, name, DNS_TYPE_A, 1);
  assert(dns_question(&m, &q) == DNS_SCAN_OK);
  assert(q.qname_len == 63 && q.qname[63] == 0);
  assert(memcmp(q.qname, name, 63) == 0);

  // 64 bytes: refused, it could never match.
  memset(name, 'a', sizeof(name));
  memcpy(name + 60, ".com", 5);
  dm_response(&m, name, DNS_TYPE_A, 1);
  assert(dns_question(&m, &q) == DNS_SCAN_BAD_NAME);
}

static void test_dns_answers_cname_chain(void) {
  struct dns_msg m;
  dm_response(&m, "api.example.com", DNS_TYPE_A, 3);
  // api.example.com CNAME edge.example.net
  __u32 cname_owner = m.len;
  dm_ptr(&m, 12);
  struct dns_msg target = {0};
  dm_name(&target, "edge.example.net");
  dm_rr(&m, 5, 300, target.b, (__u16)target.len);
  __u32 cname_target = cname_owner + 2 + 10;
  // edge.example.net A 192.0.2.10 / 192.0.2.11 (owner: pointer to the target)
  dm_ptr(&m, (__u16)cname_target);
  dm_a(&m, 60, 192, 0, 2, 10);
  __u32 second = m.len;
  dm_ptr(&m, (__u16)cname_target);
  dm_a(&m, 61, 192, 0, 2, 11);

  struct dns_answers a;
  assert(dns_answers(&m, &a) == DNS_SCAN_OK);
  assert(a.n_recs == 2);
  assert(a.recs[0].ttl == 60 && a.recs[1].ttl == 61);
  assert(a.recs[1].off == second + 2 + 10);
  assert(memcmp(a.recs[1].ip, "\xc0\x00\x02\x0b", 4) == 0);
  assert(memcmp(m.b + a.recs[0].off, "\xc0\x00\x02\x0a", 4) == 0);
}

static void test_dns_answers_uncompressed_and_aaaa(void) {
  struct dns_msg m;
  dm_response(&m, "api.example.com", DNS_TYPE_A, 3);
  dm_name(&m, "api.example.com"); // uncompressed owner
  dm_a(&m, 5, 198, 51, 100, 7);
  dm_ptr(&m, 12);
  dm_aaaa(&m, 5, 1); // AAAA in the answer to an A question: not listed
  dm_ptr(&m, 12);
  dm_a(&m, 5, 198, 51, 100, 8);

  struct dns_answers a;
  assert(dns_answers(&m, &a) == DNS_SCAN_OK);
  assert(a.n_recs == 2);
  assert(a.recs[0].ip[3] == 7 && a.recs[1].ip[3] == 8);
  // Only the 4 bytes of an A record's address are set.
  for (__u32 i = 4; i < 16; i++)
    assert(a.recs[0].ip[i] == 0);
}

static void test_dns_answers_aaaa(void) {
  // The answer to an AAAA question lists its AAAA records, behind a CNAME,
  // and skips any A record.
  struct dns_msg m;
  dm_response(&m, "api.example.com", DNS_TYPE_AAAA, 4);
  __u32 cname_owner = m.len;
  dm_ptr(&m, 12);
  struct dns_msg target = {0};
  dm_name(&target, "edge.example.net");
  dm_rr(&m, 5, 300, target.b, (__u16)target.len);
  __u32 cname_target = cname_owner + 2 + 10;
  dm_ptr(&m, (__u16)cname_target);
  dm_aaaa(&m, 60, 0x10);
  dm_ptr(&m, (__u16)cname_target);
  dm_a(&m, 60, 192, 0, 2, 10);
  __u32 second = m.len;
  dm_ptr(&m, (__u16)cname_target);
  dm_aaaa(&m, 61, 0x11);

  struct dns_answers a;
  assert(dns_answers(&m, &a) == DNS_SCAN_OK);
  assert(a.n_recs == 2);
  assert(a.recs[0].ttl == 60 && a.recs[1].ttl == 61);
  assert(a.recs[1].off == second + 2 + 10);
  const __u8 want[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11};
  assert(memcmp(a.recs[1].ip, want, 16) == 0);
  assert(memcmp(m.b + a.recs[1].off, want, 16) == 0);

  // An AAAA record that is not 16 bytes long.
  dm_response(&m, "api.example.com", DNS_TYPE_AAAA, 1);
  dm_ptr(&m, 12);
  __u8 four[4] = {1, 2, 3, 4};
  dm_rr(&m, DNS_TYPE_AAAA, 5, four, 4);
  assert(dns_answers(&m, &a) == DNS_SCAN_MALFORMED);

  // Another question type: nothing is listed.
  dm_response(&m, "api.example.com", 16 /* TXT */, 1);
  dm_ptr(&m, 12);
  dm_a(&m, 5, 192, 0, 2, 10);
  assert(dns_answers(&m, &a) == DNS_SCAN_OK);
  assert(a.n_recs == 0 && a.rr_len == 0);
}

static void test_dns_answers_limits(void) {
  struct dns_msg m;
  struct dns_answers a;
  // DNS_MAX_ADDR_RECORDS records fit, one more leaves the answer unchanged.
  for (__u32 count = DNS_MAX_ADDR_RECORDS; count <= DNS_MAX_ADDR_RECORDS + 1; count++) {
    dm_response(&m, "api.example.com", DNS_TYPE_A, (__u16)count);
    for (__u32 i = 0; i < count; i++) {
      dm_ptr(&m, 12);
      dm_a(&m, 5, 10, 0, 0, (__u8)i);
    }
    __u32 want = count == DNS_MAX_ADDR_RECORDS ? DNS_SCAN_OK : DNS_SCAN_INCOMPLETE;
    assert(dns_answers(&m, &a) == want);
  }

  // Fewer records than ancount, or the last one cut short.
  dm_response(&m, "api.example.com", DNS_TYPE_A, 3);
  dm_ptr(&m, 12);
  dm_a(&m, 5, 10, 0, 0, 1);
  dm_ptr(&m, 12);
  dm_a(&m, 5, 10, 0, 0, 2);
  assert(dns_answers(&m, &a) == DNS_SCAN_INCOMPLETE);
  m.b[7] = 2;
  m.len -= 1;
  assert(dns_answers(&m, &a) == DNS_SCAN_INCOMPLETE);

  // An A record that is not 4 bytes long.
  dm_response(&m, "api.example.com", DNS_TYPE_A, 1);
  dm_ptr(&m, 12);
  __u8 five[5] = {1, 2, 3, 4, 5};
  dm_rr(&m, DNS_TYPE_A, 5, five, 5);
  assert(dns_answers(&m, &a) == DNS_SCAN_MALFORMED);

  // A reserved label type in an owner name.
  dm_response(&m, "api.example.com", DNS_TYPE_A, 1);
  dm_u8(&m, 0x80);
  dm_a(&m, 5, 10, 0, 0, 1);
  assert(dns_answers(&m, &a) == DNS_SCAN_MALFORMED);
}

// Ones' complement helpers mirroring the kernel's csum_replace4.
static __u16 oc_add(__u16 a, __u16 b) {
  __u32 s = (__u32)a + b;
  return (__u16)((s & 0xFFFF) + (s >> 16));
}

static __u16 oc_sum(const __u8 *b, __u32 len) {
  __u16 s = 0;
  for (__u32 i = 0; i + 1 < len; i += 2)
    s = oc_add(s, (__u16)((b[i] << 8) | b[i + 1]));
  if (len & 1)
    s = oc_add(s, (__u16)(b[len - 1] << 8));
  return s;
}

static __u16 csum_replace4(__u16 check, __u32 from, __u32 to) {
  __u8 f[4], t[4];
  memcpy(f, &from, 4);
  memcpy(t, &to, 4);
  __u16 fs = oc_add((__u16)((f[0] << 8) | f[1]), (__u16)((f[2] << 8) | f[3]));
  __u16 ts = oc_add((__u16)((t[0] << 8) | t[1]), (__u16)((t[2] << 8) | t[3]));
  return (__u16)~oc_add(oc_add((__u16)~check, (__u16)~fs), ts);
}

static void test_csum_odd_bytes(void) {
  __u32 v;
  memcpy(&v, "\x01\x02\x03\x04", 4);
  __u32 w = csum_odd_bytes(v);
  assert(memcmp(&w, "\x02\x01\x04\x03", 4) == 0);

  // Updating the checksum for a 4-byte change at every offset of a buffer
  // matches recomputing it, with csum_odd_bytes at odd offsets.
  __u8 buf[40];
  for (__u32 i = 0; i < sizeof(buf); i++)
    buf[i] = (__u8)(i * 37 + 11);
  for (__u32 off = 0; off + 4 <= sizeof(buf); off++) {
    __u8 b[40];
    memcpy(b, buf, sizeof(b));
    __u16 check = (__u16)~oc_sum(b, sizeof(b));
    __u32 from, to;
    memcpy(&from, b + off, 4);
    memcpy(&to, "\xc6\x12\x00\x05", 4); // 198.18.0.5
    memcpy(b + off, &to, 4);
    if (off & 1) {
      from = csum_odd_bytes(from);
      to = csum_odd_bytes(to);
    }
    __u16 updated = csum_replace4(check, from, to);
    __u16 want = (__u16)~oc_sum(b, sizeof(b));
    // 0x0000 and 0xFFFF are the same ones' complement value.
    assert((updated == 0xFFFF ? 0 : updated) == (want == 0xFFFF ? 0 : want));
  }
}

// v4 returns a.b.c.d IPv4-mapped; v6 returns 2001:db8::<last>.
static const __u8 *v4(__u8 *out, __u8 a, __u8 b, __u8 c, __u8 d) {
  memset(out, 0, 16);
  out[10] = out[11] = 0xff;
  out[12] = a;
  out[13] = b;
  out[14] = c;
  out[15] = d;
  return out;
}

static const __u8 *v6(__u8 *out, __u8 last) {
  memset(out, 0, 16);
  out[0] = 0x20;
  out[1] = 0x01;
  out[2] = 0x0d;
  out[3] = 0xb8;
  out[15] = last;
  return out;
}

static void test_vip_addr(void) {
  __u8 b[16], c[16];
  assert(vip_addr_eq(v6(b, 1), v6(c, 1)));
  assert(!vip_addr_eq(v6(b, 1), v6(c, 2)));
  v6(c, 1);
  c[0] ^= 0x80; // first byte differs
  assert(!vip_addr_eq(v6(b, 1), c));
  assert(!vip_addr_eq(v4(b, 0, 0, 0, 1), v6(c, 1)));
  assert(vip_addr_v4mapped(v4(b, 10, 0, 0, 1)));
  assert(!vip_addr_v4mapped(v6(b, 1)));
  memset(b, 0, 16);
  assert(!vip_addr_v4mapped(b) && vip_addr_unspecified(b)); // ::
  assert(vip_addr_unspecified(v4(b, 0, 0, 0, 0)));         // 0.0.0.0
  assert(!vip_addr_unspecified(v4(b, 0, 0, 0, 1)));
  assert(!vip_addr_unspecified(v6(b, 0)));                 // 2001:db8::
  memset(b, 0, 16);
  b[15] = 1;
  assert(!vip_addr_unspecified(b)); // ::1
  memset(b, 0, 16);
  b[10] = 0xff;
  assert(!vip_addr_unspecified(b) && !vip_addr_v4mapped(b)); // ::ff00:0:0

  // 2001:2::/48.
  const __u8 net[16] = {0x20, 0x01, 0x00, 0x02};
  const __u8 mask[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  __u8 in[16] = {0x20, 0x01, 0x00, 0x02, 0, 0, 0xab, 0xcd};
  in[15] = 9;
  assert(vip_in_prefix6(net, mask, in));
  in[5] = 1; // 2001:2:1::/48
  assert(!vip_in_prefix6(net, mask, in));
  assert(!vip_in_prefix6(net, mask, v4(b, 198, 18, 0, 5)));
  // No IPv6 range: nothing is in it, not even ::.
  const __u8 zero[16] = {0};
  assert(!vip_in_prefix6(zero, zero, zero));
  // A /52: the mask's partial byte counts.
  const __u8 mask52[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0};
  in[5] = 0;
  in[6] = 0x0f;
  assert(vip_in_prefix6(net, mask52, in));
  in[6] = 0x10;
  assert(!vip_in_prefix6(net, mask52, in));
}

static void test_vip_upstream_record(void) {
  struct vip_upstream_val v;
  memset(&v, 0, sizeof(v));
  __u8 a[16], b[16], c[16], d[16], e[16], zero[16];
  v4(a, 10, 0, 0, 1);
  v4(b, 10, 0, 0, 2);
  v4(c, 10, 0, 0, 3);
  v4(d, 10, 0, 0, 4);
  v4(e, 10, 0, 0, 5);
  v4(zero, 0, 0, 0, 0);

  vip_upstream_record(&v, a, 100);
  assert(memcmp(v.slot[0].ip, a, 16) == 0 && v.slot[0].expires_at == 100);
  // Same address: the later expiry wins, an earlier one doesn't shorten it.
  vip_upstream_record(&v, a, 200);
  vip_upstream_record(&v, a, 150);
  assert(v.slot[0].expires_at == 200 && v.slot[1].expires_at == 0);
  // Unspecified addresses are not recorded.
  vip_upstream_record(&v, zero, 999);
  memset(zero, 0, 16);
  vip_upstream_record(&v, zero, 999);
  // Nor is an address without an expiry (expires_at 0 marks empty slots).
  vip_upstream_record(&v, b, 0);
  assert(vip_addr_unspecified(v.slot[1].ip) && v.slot[1].expires_at == 0);

  vip_upstream_record(&v, b, 300);
  vip_upstream_record(&v, c, 50);
  vip_upstream_record(&v, d, 400);
  // Full: e replaces c, the slot that expires first.
  vip_upstream_record(&v, e, 500);
  assert(memcmp(v.slot[2].ip, e, 16) == 0 && v.slot[2].expires_at == 500);
  assert(memcmp(v.slot[0].ip, a, 16) == 0 && memcmp(v.slot[1].ip, b, 16) == 0 &&
         memcmp(v.slot[3].ip, d, 16) == 0);

  // IPv6 addresses (a fake IPv6's upstreams) are compared whole.
  memset(&v, 0, sizeof(v));
  vip_upstream_record(&v, v6(a, 1), 100);
  vip_upstream_record(&v, v6(b, 2), 100);
  vip_upstream_record(&v, v6(c, 1), 300);
  assert(memcmp(v.slot[0].ip, a, 16) == 0 && v.slot[0].expires_at == 300);
  assert(memcmp(v.slot[1].ip, b, 16) == 0 && vip_addr_unspecified(v.slot[2].ip));
}

static void test_vip_upstream_pick(void) {
  struct vip_upstream_val v;
  memset(&v, 0, sizeof(v));
  __u8 out[16], want[16];
  memset(out, 0xaa, 16);
  assert(!vip_upstream_pick(&v, 0, 0, out));
  assert(out[0] == 0xaa); // untouched

  __u8 a[16], b[16], c[16];
  vip_upstream_record(&v, v4(a, 10, 0, 0, 1), 100);
  vip_upstream_record(&v, v4(b, 10, 0, 0, 2), 300);
  vip_upstream_record(&v, v4(c, 10, 0, 0, 3), 200);
  // All unexpired: rnd picks among them, in slot order.
  assert(vip_upstream_pick(&v, 50, 0, out) && memcmp(out, a, 16) == 0);
  assert(vip_upstream_pick(&v, 50, 1, out) && memcmp(out, b, 16) == 0);
  assert(vip_upstream_pick(&v, 50, 2, out) && memcmp(out, c, 16) == 0);
  assert(vip_upstream_pick(&v, 50, 3, out) && memcmp(out, a, 16) == 0);
  // a expired: only b and c.
  assert(vip_upstream_pick(&v, 150, 0, out) && memcmp(out, b, 16) == 0);
  assert(vip_upstream_pick(&v, 150, 1, out) && memcmp(out, c, 16) == 0);
  // All expired: the one that expired last.
  assert(vip_upstream_pick(&v, 1000, 7, out) && memcmp(out, b, 16) == 0);

  memset(&v, 0, sizeof(v));
  vip_upstream_record(&v, v6(a, 7), 100);
  assert(vip_upstream_pick(&v, 50, 5, out) && memcmp(out, v6(want, 7), 16) == 0);
}

static void test_vip_socket_check(void) {
  char api[MAX_HOST_LEN] = "api.example.com";
  char other[MAX_HOST_LEN] = "api.example.co";
  const __u8 real[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 10};
  const __u8 elsewhere[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 11};
  __u32 api_len = (__u32)strlen(api);

  // No restriction: any socket, even one that connected to no fake IP.
  assert(vip_socket_check(NULL, 0, api, 0, real, elsewhere, 0, 1) == VIP_SOCK_OK);
  // A host length of MAX_HOST_LEN or more restricts nothing (as in the uprobe).
  assert(vip_socket_check(NULL, MAX_HOST_LEN, api, 0, real, elsewhere, 0, 1) == VIP_SOCK_OK);

  // Host: only a socket that connected to that host's fake IP.
  assert(vip_socket_check(api, api_len, api, 0, real, real, 0, 443) == VIP_SOCK_OK);
  assert(vip_socket_check(NULL, api_len, api, 0, real, real, 0, 443) == VIP_SOCK_DENY_HOST);
  assert(vip_socket_check(other, api_len, api, 0, real, real, 0, 443) == VIP_SOCK_DENY_HOST);

  // IP: the socket's real destination, whatever the app connected to.
  assert(vip_socket_check(api, 0, other, 16, real, real, 0, 443) == VIP_SOCK_OK);
  assert(vip_socket_check(api, 0, other, 16, real, elsewhere, 0, 443) == VIP_SOCK_DENY_ADDR);
  // Any other IP length restricts nothing.
  assert(vip_socket_check(NULL, 0, other, 4, real, elsewhere, 0, 443) == VIP_SOCK_OK);

  // Port.
  assert(vip_socket_check(api, api_len, api, 0, real, real, 443, 443) == VIP_SOCK_OK);
  assert(vip_socket_check(api, api_len, api, 0, real, real, 443, 8443) == VIP_SOCK_DENY_ADDR);

  // Every restriction applies; the host is reported first.
  assert(vip_socket_check(api, api_len, api, 16, real, real, 443, 443) == VIP_SOCK_OK);
  assert(vip_socket_check(other, api_len, api, 16, real, elsewhere, 443, 80) == VIP_SOCK_DENY_HOST);
  assert(vip_socket_check(api, api_len, api, 16, real, elsewhere, 443, 443) == VIP_SOCK_DENY_ADDR);

  // An IPv6 secret IP against an IPv6 socket, and never against the IPv4
  // socket whose address ends in the same bytes.
  __u8 real6[16], other6[16];
  v6(real6, 10);
  v6(other6, 11);
  __u8 tail[16];
  v4(tail, 0, 0, 0, 10);
  assert(vip_socket_check(api, api_len, api, 16, real6, real6, 443, 443) == VIP_SOCK_OK);
  assert(vip_socket_check(api, api_len, api, 16, real6, other6, 443, 443) == VIP_SOCK_DENY_ADDR);
  assert(vip_socket_check(api, api_len, api, 16, real6, tail, 443, 443) == VIP_SOCK_DENY_ADDR);
}

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

  printf("is_kloak_candidate:\n");
  RUN_TEST(test_candidate_plain);
  RUN_TEST(test_candidate_huffman);
  RUN_TEST(test_candidate_huffman_partial);
  RUN_TEST(test_candidate_neither);

  printf("prescan chunking:\n");
  RUN_TEST(test_prescan_chunks_tile_positions);
  RUN_TEST(test_prescan_scan_len_bounds);

  printf("patch_delta:\n");
  RUN_TEST(test_patch_tail_mask);
  RUN_TEST(test_patch_delta_raw);
  RUN_TEST(test_patch_delta_every_len);
  RUN_TEST(test_patch_delta_hpack_tail);

  printf("gf128_mul:\n");
  RUN_TEST(test_gf128_mul_identity);
  RUN_TEST(test_gf128_mul_zero);
  RUN_TEST(test_gf128_mul_known_vector);
  RUN_TEST(test_gf128_mul_gcm_vector);
  RUN_TEST(test_gf128_mul_commutativity);
  RUN_TEST(test_is_aes_gcm);

  printf("tls record framing (tc_egress):\n");
  RUN_TEST(test_tls_hdr_appdata);
  RUN_TEST(test_tls_hdr_appdata_too_short);
  RUN_TEST(test_tls_hdr_ccs);
  RUN_TEST(test_tls_hdr_handshake_and_alert);
  RUN_TEST(test_tls_hdr_rejects_garbage);
  RUN_TEST(test_tls_reclen_match_known_nonce);
  RUN_TEST(test_tls_reclen_match_unknown_nonce);
  RUN_TEST(test_tls_reclen_match_zero_plaintext);
  RUN_TEST(test_tc_record_nonce_matched);
  RUN_TEST(test_tc_record_nonce_memory_bio_no_fit);
  RUN_TEST(test_tc_record_nonce_anchored_no_fit);
  RUN_TEST(test_tc_patch_fits_tls12);
  RUN_TEST(test_tc_patch_fits_tls13);
  RUN_TEST(test_tc_patch_fits_edges);
  RUN_TEST(test_tc_entry_expired);
  RUN_TEST(test_tc_tag_action);

  printf("aes (BoringSSL H recovery):\n");
  RUN_TEST(test_aes128_fips197);
  RUN_TEST(test_aes256_fips197);
  RUN_TEST(test_aes_recover_h);

  printf("gf128_halve_to_h (OpenSSL AVX-512 / Go H recovery):\n");
  RUN_TEST(test_gf128_halve_to_h_aes_keys);
  RUN_TEST(test_gf128_halve_to_h_edges);

  printf("ghash engine (table multiply, span tag deltas):\n");
  gf128_rem4_init(rem4);
  RUN_TEST(test_gf128_words);
  RUN_TEST(test_gf128_rem4);
  RUN_TEST(test_gf128_table_entries);
  RUN_TEST(test_gf128_table_mul);
  RUN_TEST(test_gf128_mul_by);
  RUN_TEST(test_ghash_span_plan);
  RUN_TEST(test_ghash_block_delta64);
  RUN_TEST(test_ghash_span_vs_naive);
  RUN_TEST(test_ghash_span_vs_definition);
  RUN_TEST(test_ghash_span_vs_go_gcm);

  printf("tls_parse_sni (SNI check):\n");
  RUN_TEST(test_sni_go);
  RUN_TEST(test_sni_node);
  RUN_TEST(test_sni_bun);
  RUN_TEST(test_sni_lowercase_trailing_dot);
  RUN_TEST(test_sni_absent);
  RUN_TEST(test_sni_truncated_real);
  RUN_TEST(test_sni_not_client_hello);
  RUN_TEST(test_sni_synthetic);
  RUN_TEST(test_sni_ech_wins);
  RUN_TEST(test_sni_rejects_bad_host_bytes);
  RUN_TEST(test_sni_too_long);
  RUN_TEST(test_sni_duplicate_server_name);
  RUN_TEST(test_sni_lying_lengths);
  RUN_TEST(test_sni_too_many_extensions);
  RUN_TEST(test_sni_past_copy_buffer);

  printf("dns rewrite walks:\n");
  RUN_TEST(test_dns_question_basic);
  RUN_TEST(test_dns_question_not_an_answer);
  RUN_TEST(test_dns_question_bad_names);
  RUN_TEST(test_dns_question_name_length);
  RUN_TEST(test_dns_answers_cname_chain);
  RUN_TEST(test_dns_answers_uncompressed_and_aaaa);
  RUN_TEST(test_dns_answers_aaaa);
  RUN_TEST(test_dns_answers_limits);
  RUN_TEST(test_csum_odd_bytes);

  printf("vip_upstream:\n");
  RUN_TEST(test_vip_addr);
  RUN_TEST(test_vip_upstream_record);
  RUN_TEST(test_vip_upstream_pick);
  RUN_TEST(test_vip_socket_check);

  printf("\n%d/%d tests passed.\n", tests_passed, tests_run);
  return 0;
}
