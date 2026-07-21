/* test_inflate.c — DEFLATE and zlib, on synthetic streams only.
 *
 * The streams here are not pasted magic blobs. They are built by a small
 * fixed-Huffman encoder written from RFC 1951's rules, so the decoder is
 * checked against an independent implementation of the spec rather than
 * against a constant somebody once observed. A pasted blob proves the decoder
 * handles that blob; an encoder proves it handles the format.
 */

#include "inflate.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Release builds define NDEBUG, which compiles every assert() below to
 * nothing. See tests/CMakeLists.txt. */
#ifdef NDEBUG
#error "tests must be built with asserts enabled (NDEBUG is defined)"
#endif

/* --- a bit writer matching DEFLATE's two conventions ------------------------ */
/*
 * DEFLATE is LSB-first for everything EXCEPT Huffman codes, which are packed
 * starting from their most significant bit (RFC 1951 3.1.1). Getting that
 * backwards is the classic way to write an encoder that disagrees with every
 * decoder, so the two cases are separate functions here rather than one
 * function with a flag.
 */

typedef struct {
    uint8_t buf[4096];
    size_t  len;
    int     bitpos;
} bw;

static void bw_bit(bw *w, int b) {
    if (w->bitpos == 0) { w->buf[w->len] = 0; }
    if (b) w->buf[w->len] |= (uint8_t)(1 << w->bitpos);
    if (++w->bitpos == 8) { w->bitpos = 0; w->len++; }
}

/* Ordinary values: LSB first. */
static void bw_bits(bw *w, uint32_t v, int n) {
    for (int i = 0; i < n; i++) bw_bit(w, (v >> i) & 1);
}

/* Huffman codes: MSB first. */
static void bw_code(bw *w, uint32_t code, int n) {
    for (int i = n - 1; i >= 0; i--) bw_bit(w, (code >> i) & 1);
}

static void bw_flush(bw *w) {
    if (w->bitpos) { w->bitpos = 0; w->len++; }
}

/* --- the fixed literal/length alphabet, per RFC 1951 3.2.6 ------------------ */

static void put_literal(bw *w, int sym) {
    if (sym < 144)      bw_code(w, 0x30  + sym,         8);
    else if (sym < 256) bw_code(w, 0x190 + (sym - 144), 9);
    else if (sym < 280) bw_code(w, 0x000 + (sym - 256), 7);
    else                bw_code(w, 0x0C0 + (sym - 280), 8);
}

/* Length 3-10 map to codes 257-264 with no extra bits, which is all these
 * tests need. Distances 1-4 map to codes 0-3, also with no extra bits. */
static void put_match(bw *w, int length, int distance) {
    assert(length >= 3 && length <= 10);
    assert(distance >= 1 && distance <= 4);
    put_literal(w, 257 + (length - 3));
    bw_code(w, (uint32_t)(distance - 1), 5);
}

static void begin_fixed_block(bw *w, int final) {
    bw_bits(w, (uint32_t)final, 1);
    bw_bits(w, 1, 2);              /* BTYPE = 01, fixed Huffman */
}

/* --- tests ------------------------------------------------------------------ */

static void test_fixed_literals(void) {
    bw w; memset(&w, 0, sizeof(w));
    begin_fixed_block(&w, 1);
    const char *msg = "hello vita";
    for (const char *p = msg; *p; p++) put_literal(&w, (unsigned char)*p);
    put_literal(&w, 256);          /* end of block */
    bw_flush(&w);

    uint8_t out[64];
    size_t n = sizeof(out);
    assert(inf_inflate(w.buf, w.len, out, &n) == INF_OK);
    assert(n == strlen(msg));
    assert(memcmp(out, msg, n) == 0);

    printf("  fixed huffman literals         ok\n");
}

static void test_back_reference(void) {
    bw w; memset(&w, 0, sizeof(w));
    begin_fixed_block(&w, 1);
    for (const char *p = "abcd"; *p; p++) put_literal(&w, (unsigned char)*p);
    put_match(&w, 4, 4);           /* copy "abcd" again */
    put_literal(&w, 256);
    bw_flush(&w);

    uint8_t out[64];
    size_t n = sizeof(out);
    assert(inf_inflate(w.buf, w.len, out, &n) == INF_OK);
    assert(n == 8);
    assert(memcmp(out, "abcdabcd", 8) == 0);

    printf("  back-reference                 ok\n");
}

static void test_overlapping_copy(void) {
    /* A run is encoded as a match whose length exceeds its distance, so the
     * copy reads bytes it is in the middle of writing. A memcpy-based
     * implementation gets this wrong, and it is common enough in real data
     * that the bug would surface immediately — but only on real data. */
    bw w; memset(&w, 0, sizeof(w));
    begin_fixed_block(&w, 1);
    put_literal(&w, 'X');
    put_match(&w, 5, 1);           /* length 5, distance 1 -> "XXXXX" */
    put_literal(&w, 256);
    bw_flush(&w);

    uint8_t out[64];
    size_t n = sizeof(out);
    assert(inf_inflate(w.buf, w.len, out, &n) == INF_OK);
    assert(n == 6);
    assert(memcmp(out, "XXXXXX", 6) == 0);

    printf("  overlapping copy               ok\n");
}

static void test_stored_block(void) {
    const char *msg = "stored, not compressed";
    uint16_t len = (uint16_t)strlen(msg);

    uint8_t s[64];
    size_t  n = 0;
    s[n++] = 0x01;                 /* BFINAL=1, BTYPE=00, byte-aligned after */
    s[n++] = (uint8_t)(len & 0xFF);
    s[n++] = (uint8_t)(len >> 8);
    s[n++] = (uint8_t)(~len & 0xFF);
    s[n++] = (uint8_t)((~len >> 8) & 0xFF);
    memcpy(s + n, msg, len);
    n += len;

    uint8_t out[64];
    size_t  outn = sizeof(out);
    assert(inf_inflate(s, n, out, &outn) == INF_OK);
    assert(outn == len);
    assert(memcmp(out, msg, len) == 0);

    /* A corrupted NLEN must be caught: it is the format's own check that the
     * length was not garbled, and ignoring it is free but wrong. */
    s[3] ^= 0xFF;
    outn = sizeof(out);
    assert(inf_inflate(s, n, out, &outn) == INF_ERR_FORMAT);

    printf("  stored block + nlen check      ok\n");
}

static void test_zlib_wrapper(void) {
    bw w; memset(&w, 0, sizeof(w));
    begin_fixed_block(&w, 1);
    const char *msg = "zlib wrapped";
    for (const char *p = msg; *p; p++) put_literal(&w, (unsigned char)*p);
    put_literal(&w, 256);
    bw_flush(&w);

    uint32_t adler = inf_adler32((const uint8_t *)msg, strlen(msg));

    uint8_t s[256];
    size_t  n = 0;
    s[n++] = 0x78;                 /* CM=8, CINFO=7 */
    s[n++] = 0x9C;                 /* 0x789C % 31 == 0 */
    memcpy(s + n, w.buf, w.len); n += w.len;
    s[n++] = (uint8_t)(adler >> 24);   /* big-endian, unlike the rest */
    s[n++] = (uint8_t)(adler >> 16);
    s[n++] = (uint8_t)(adler >> 8);
    s[n++] = (uint8_t)adler;

    uint8_t out[64];
    size_t  outn = sizeof(out);
    assert(inf_zlib(s, n, out, &outn) == INF_OK);
    assert(outn == strlen(msg));
    assert(memcmp(out, msg, outn) == 0);

    /* The checksum is the point of the wrapper: corrupt it and the call must
     * fail even though the deflate stream itself is perfectly valid. Without
     * this, "it decompressed" and "it decompressed correctly" are the same
     * answer, and they are not. */
    s[n - 1] ^= 0x01;
    outn = sizeof(out);
    assert(inf_zlib(s, n, out, &outn) == INF_ERR_ADLER);

    printf("  zlib wrapper + adler check     ok\n");
}

static void test_rejects_malformed(void) {
    uint8_t out[64];
    size_t  n;

    /* Truncated mid-stream. */
    bw w; memset(&w, 0, sizeof(w));
    begin_fixed_block(&w, 1);
    for (const char *p = "truncate me"; *p; p++) put_literal(&w, (unsigned char)*p);
    bw_flush(&w);                  /* deliberately no end-of-block symbol */
    n = sizeof(out);
    assert(inf_inflate(w.buf, w.len, out, &n) == INF_ERR_INPUT);

    /* Reserved block type 3. */
    uint8_t bad[] = { 0x07 };      /* BFINAL=1, BTYPE=11 */
    n = sizeof(out);
    assert(inf_inflate(bad, sizeof(bad), out, &n) == INF_ERR_FORMAT);

    /* Output buffer too small — must be refused, not overrun. */
    memset(&w, 0, sizeof(w));
    begin_fixed_block(&w, 1);
    for (int i = 0; i < 40; i++) put_literal(&w, 'z');
    put_literal(&w, 256);
    bw_flush(&w);
    n = 8;
    assert(inf_inflate(w.buf, w.len, out, &n) == INF_ERR_OUTPUT);

    /* Not a zlib stream. */
    uint8_t nothdr[] = { 0x00, 0x00, 0, 0, 0, 0 };
    n = sizeof(out);
    assert(inf_zlib(nothdr, sizeof(nothdr), out, &n) == INF_ERR_HEADER);

    /* A back-reference pointing before the start of the output. */
    memset(&w, 0, sizeof(w));
    begin_fixed_block(&w, 1);
    put_literal(&w, 'a');
    put_match(&w, 3, 4);           /* distance 4 with only 1 byte written */
    bw_flush(&w);
    n = sizeof(out);
    assert(inf_inflate(w.buf, w.len, out, &n) == INF_ERR_DISTANCE);

    printf("  rejects malformed input        ok\n");
}

static void test_adler32(void) {
    /* Adler-32 of "Wikipedia" is 0x11E60398 — one of the few values for this
     * checksum published widely enough to serve as an independent vector. */
    assert(inf_adler32((const uint8_t *)"Wikipedia", 9) == 0x11E60398u);
    assert(inf_adler32((const uint8_t *)"", 0) == 1u);
    printf("  adler-32 vector                ok\n");
}

int main(void) {
    printf("inflate:\n");
    test_adler32();
    test_fixed_literals();
    test_back_reference();
    test_overlapping_copy();
    test_stored_block();
    test_zlib_wrapper();
    test_rejects_malformed();
    printf("all inflate tests passed\n");
    return 0;
}
