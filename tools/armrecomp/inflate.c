/* inflate.c — DEFLATE (RFC 1951) and zlib (RFC 1950).
 *
 * Canonical Huffman decoding: rather than build a lookup table, walk the code
 * lengths bit by bit using the per-length symbol counts. That is slower per
 * symbol than a table but it is short, has no table-construction step to get
 * subtly wrong, and is fast enough for the few megabytes a Vita module holds.
 *
 * Every table below is *derived from the RFC's rules* where the rules are
 * mechanical (the fixed Huffman code lengths) and written out only where the
 * spec gives an arbitrary list (the length/distance bases). A transcribed table
 * with one mistyped entry produces a decoder that works for most input and
 * fails on some, which is exactly the bug that survives casual testing.
 */

#include "inflate.h"

#include <string.h>

const char *inf_strerror(inf_status s) {
    switch (s) {
        case INF_OK:           return "ok";
        case INF_ERR_INPUT:    return "truncated input";
        case INF_ERR_OUTPUT:   return "output larger than expected";
        case INF_ERR_FORMAT:   return "malformed deflate stream";
        case INF_ERR_DISTANCE: return "back-reference before start of output";
        case INF_ERR_HEADER:   return "not a zlib stream";
        case INF_ERR_ADLER:    return "adler-32 mismatch";
        default:               return "?";
    }
}

/* --- bit reader (DEFLATE packs bits LSB-first within each byte) ------------- */

typedef struct {
    const uint8_t *src;
    size_t         len;
    size_t         pos;
    uint32_t       buf;
    int            cnt;
    int            overrun;
} bitreader;

static int getbit(bitreader *br) {
    if (br->cnt == 0) {
        if (br->pos >= br->len) { br->overrun = 1; return 0; }
        br->buf = br->src[br->pos++];
        br->cnt = 8;
    }
    int b = br->buf & 1;
    br->buf >>= 1;
    br->cnt--;
    return b;
}

static uint32_t getbits(bitreader *br, int n) {
    uint32_t v = 0;
    for (int i = 0; i < n; i++) v |= (uint32_t)getbit(br) << i;
    return v;
}

/* --- canonical Huffman ------------------------------------------------------ */

#define MAX_BITS 15

typedef struct {
    int16_t counts[MAX_BITS + 1];  /* how many codes of each bit length */
    int16_t symbols[288];          /* symbols ordered by code           */
} huff;

static int huff_build(huff *h, const uint8_t *lengths, int n) {
    memset(h->counts, 0, sizeof(h->counts));
    for (int i = 0; i < n; i++) h->counts[lengths[i]]++;

    /* Length 0 means "symbol unused"; it must not participate. */
    h->counts[0] = 0;

    /* Reject an over-subscribed code — more codes at some length than the
     * binary tree can hold. An incomplete code is legal (a single-symbol
     * distance tree is the common case) so it is not rejected here. */
    int left = 1;
    for (int len = 1; len <= MAX_BITS; len++) {
        left <<= 1;
        left -= h->counts[len];
        if (left < 0) return -1;
    }

    int offs[MAX_BITS + 2];
    offs[1] = 0;
    for (int len = 1; len <= MAX_BITS; len++)
        offs[len + 1] = offs[len] + h->counts[len];

    for (int i = 0; i < n; i++)
        if (lengths[i]) h->symbols[offs[lengths[i]]++] = (int16_t)i;

    return 0;
}

static int huff_decode(bitreader *br, const huff *h) {
    int code = 0, first = 0, index = 0;

    for (int len = 1; len <= MAX_BITS; len++) {
        code |= getbit(br);
        int count = h->counts[len];
        if (code - first < count) return h->symbols[index + (code - first)];
        index += count;
        first  = (first + count) << 1;
        code <<= 1;
    }
    return -1;
}

/* --- the length and distance codes ------------------------------------------ */
/*
 * These are the one place the RFC gives arbitrary values rather than a rule, so
 * they are written out. Everything else is derived.
 */

static const uint16_t len_base[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};
static const uint8_t len_extra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};
static const uint16_t dist_base[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577
};
static const uint8_t dist_extra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

/* The order in which code-length code lengths appear in a dynamic block. */
static const uint8_t clen_order[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

/* --- the fixed Huffman codes, built from the RFC's rule --------------------- */

static void build_fixed(huff *lit, huff *dist) {
    uint8_t lengths[288];

    /* RFC 1951 3.2.6: literals 0-143 are 8 bits, 144-255 are 9, 256-279 are 7,
     * 280-287 are 8. Expressed as the rule rather than a pasted table. */
    for (int i = 0;   i < 144; i++) lengths[i] = 8;
    for (int i = 144; i < 256; i++) lengths[i] = 9;
    for (int i = 256; i < 280; i++) lengths[i] = 7;
    for (int i = 280; i < 288; i++) lengths[i] = 8;
    huff_build(lit, lengths, 288);

    /* All 30 distance codes are 5 bits. */
    for (int i = 0; i < 30; i++) lengths[i] = 5;
    huff_build(dist, lengths, 30);
}

/* --- block decoding --------------------------------------------------------- */

typedef struct {
    uint8_t *dst;
    size_t   cap;
    size_t   pos;
} outbuf;

static int emit(outbuf *o, uint8_t b) {
    if (o->pos >= o->cap) return -1;
    o->dst[o->pos++] = b;
    return 0;
}

static inf_status block_huffman(bitreader *br, outbuf *o,
                                const huff *lit, const huff *dist) {
    for (;;) {
        int sym = huff_decode(br, lit);
        if (br->overrun) return INF_ERR_INPUT;
        if (sym < 0)     return INF_ERR_FORMAT;

        if (sym < 256) {
            if (emit(o, (uint8_t)sym)) return INF_ERR_OUTPUT;
            continue;
        }
        if (sym == 256) return INF_OK;      /* end of block */

        sym -= 257;
        if (sym >= 29) return INF_ERR_FORMAT;
        int length = len_base[sym] + (int)getbits(br, len_extra[sym]);

        int dsym = huff_decode(br, dist);
        if (br->overrun) return INF_ERR_INPUT;
        if (dsym < 0 || dsym >= 30) return INF_ERR_FORMAT;
        size_t distance = dist_base[dsym] + getbits(br, dist_extra[dsym]);

        if (distance > o->pos) return INF_ERR_DISTANCE;

        /* Overlapping copies are legal and common — a run is encoded as a
         * back-reference whose length exceeds its distance — so this must copy
         * byte at a time rather than memcpy. */
        for (int i = 0; i < length; i++) {
            if (emit(o, o->dst[o->pos - distance])) return INF_ERR_OUTPUT;
        }
    }
}

static inf_status block_stored(bitreader *br, outbuf *o) {
    br->cnt = 0;                 /* stored blocks are byte-aligned */
    br->buf = 0;

    if (br->pos + 4 > br->len) return INF_ERR_INPUT;
    unsigned len  = br->src[br->pos] | ((unsigned)br->src[br->pos + 1] << 8);
    unsigned nlen = br->src[br->pos + 2] | ((unsigned)br->src[br->pos + 3] << 8);
    br->pos += 4;

    if ((len ^ 0xFFFF) != nlen) return INF_ERR_FORMAT;
    if (br->pos + len > br->len) return INF_ERR_INPUT;
    if (o->pos + len > o->cap)   return INF_ERR_OUTPUT;

    memcpy(o->dst + o->pos, br->src + br->pos, len);
    br->pos += len;
    o->pos  += len;
    return INF_OK;
}

static inf_status block_dynamic(bitreader *br, outbuf *o) {
    int hlit  = (int)getbits(br, 5) + 257;
    int hdist = (int)getbits(br, 5) + 1;
    int hclen = (int)getbits(br, 4) + 4;

    if (hlit > 286 || hdist > 30) return INF_ERR_FORMAT;

    uint8_t clen_lengths[19];
    memset(clen_lengths, 0, sizeof(clen_lengths));
    for (int i = 0; i < hclen; i++)
        clen_lengths[clen_order[i]] = (uint8_t)getbits(br, 3);
    if (br->overrun) return INF_ERR_INPUT;

    huff clen;
    if (huff_build(&clen, clen_lengths, 19)) return INF_ERR_FORMAT;

    /* The literal and distance code lengths are themselves Huffman-coded, with
     * three run-length escapes (16 repeats the previous, 17 and 18 emit runs of
     * zeros). They share one array because a repeat can straddle the boundary
     * between the two alphabets. */
    uint8_t lengths[288 + 30];
    memset(lengths, 0, sizeof(lengths));

    int n = 0;
    while (n < hlit + hdist) {
        int sym = huff_decode(br, &clen);
        if (br->overrun) return INF_ERR_INPUT;
        if (sym < 0) return INF_ERR_FORMAT;

        if (sym < 16) {
            lengths[n++] = (uint8_t)sym;
        } else if (sym == 16) {
            if (n == 0) return INF_ERR_FORMAT;   /* nothing to repeat */
            uint8_t prev = lengths[n - 1];
            int rep = 3 + (int)getbits(br, 2);
            if (n + rep > hlit + hdist) return INF_ERR_FORMAT;
            while (rep--) lengths[n++] = prev;
        } else if (sym == 17) {
            int rep = 3 + (int)getbits(br, 3);
            if (n + rep > hlit + hdist) return INF_ERR_FORMAT;
            while (rep--) lengths[n++] = 0;
        } else {
            int rep = 11 + (int)getbits(br, 7);
            if (n + rep > hlit + hdist) return INF_ERR_FORMAT;
            while (rep--) lengths[n++] = 0;
        }
    }

    if (lengths[256] == 0) return INF_ERR_FORMAT;  /* no end-of-block code */

    huff lit, dist;
    if (huff_build(&lit, lengths, hlit))          return INF_ERR_FORMAT;
    if (huff_build(&dist, lengths + hlit, hdist)) return INF_ERR_FORMAT;

    return block_huffman(br, o, &lit, &dist);
}

inf_status inf_inflate(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t *out_len) {
    bitreader br = { src, src_len, 0, 0, 0, 0 };
    outbuf    o  = { dst, *out_len, 0 };

    huff fixed_lit, fixed_dist;
    build_fixed(&fixed_lit, &fixed_dist);

    for (;;) {
        int final = getbit(&br);
        int type  = (int)getbits(&br, 2);
        if (br.overrun) return INF_ERR_INPUT;

        inf_status st;
        switch (type) {
            case 0:  st = block_stored(&br, &o); break;
            case 1:  st = block_huffman(&br, &o, &fixed_lit, &fixed_dist); break;
            case 2:  st = block_dynamic(&br, &o); break;
            default: return INF_ERR_FORMAT;      /* type 3 is reserved */
        }
        if (st != INF_OK) return st;
        if (br.overrun)   return INF_ERR_INPUT;
        if (final) break;
    }

    *out_len = o.pos;
    return INF_OK;
}

/* --- zlib ------------------------------------------------------------------- */

uint32_t inf_adler32(const uint8_t *data, size_t len) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

int inf_is_zlib_header(const uint8_t *p, size_t len) {
    if (len < 2) return 0;
    /* CM must be 8 (deflate), and the two header bytes read big-endian must be
     * a multiple of 31. FDICT (bit 5 of FLG) means a preset dictionary follows,
     * which zlib streams in a SELF do not use. */
    if ((p[0] & 0x0F) != 8) return 0;
    if (((unsigned)p[0] << 8 | p[1]) % 31 != 0) return 0;
    if (p[1] & 0x20) return 0;
    return 1;
}

inf_status inf_zlib(const uint8_t *src, size_t src_len,
                    uint8_t *dst, size_t *out_len) {
    if (src_len < 6) return INF_ERR_HEADER;      /* 2 header + 4 adler */
    if (!inf_is_zlib_header(src, src_len)) return INF_ERR_HEADER;

    size_t cap = *out_len;
    size_t produced = cap;
    inf_status st = inf_inflate(src + 2, src_len - 2 - 4, dst, &produced);
    if (st != INF_OK) return st;

    /* The Adler-32 trailer is stored big-endian, unlike everything else in the
     * format. This check is the whole reason to bother with the zlib wrapper
     * rather than calling inf_inflate directly: it makes success verifiable
     * instead of merely plausible. */
    const uint8_t *tr = src + src_len - 4;
    uint32_t want = ((uint32_t)tr[0] << 24) | ((uint32_t)tr[1] << 16)
                  | ((uint32_t)tr[2] << 8)  | (uint32_t)tr[3];

    if (inf_adler32(dst, produced) != want) return INF_ERR_ADLER;

    *out_len = produced;
    return INF_OK;
}
