/* inflate.h — DEFLATE (RFC 1951) and zlib (RFC 1950), self-contained.
 *
 * Written rather than vendored, for the same reason psprecomp writes its own
 * AES: the toolkit promises that a fresh clone builds with nothing installed,
 * and DEFLATE is a fully specified algorithm rather than a research problem.
 *
 * The zlib entry point verifies the Adler-32 trailer, which is the property
 * that makes this worth doing carefully. It turns "did decompression work?"
 * from a judgement call about whether the output looks like code into a yes/no
 * answer — the same role the CMAC plays in psprecomp's KIRK path.
 */

#ifndef ARMRECOMP_INFLATE_H
#define ARMRECOMP_INFLATE_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    INF_OK = 0,
    INF_ERR_INPUT,      /* ran off the end of the input                       */
    INF_ERR_OUTPUT,     /* output would exceed the caller's buffer            */
    INF_ERR_FORMAT,     /* malformed stream (bad block type, bad Huffman, ...) */
    INF_ERR_DISTANCE,   /* a back-reference pointing before the output start  */
    INF_ERR_HEADER,     /* not a zlib stream (CMF/FLG)                        */
    INF_ERR_ADLER,      /* decompressed fine, but the checksum disagrees      */
} inf_status;

const char *inf_strerror(inf_status s);

/* Raw DEFLATE. `*out_len` is in/out: capacity on the way in, bytes produced on
 * the way out. */
inf_status inf_inflate(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t *out_len);

/* zlib wrapper: validates the 2-byte header, inflates, and verifies the
 * Adler-32 trailer against the decompressed bytes. */
inf_status inf_zlib(const uint8_t *src, size_t src_len,
                    uint8_t *dst, size_t *out_len);

/* Cheap structural check, no decompression. Used by `info` to cross-check a
 * segment's declared encryption flag against what the bytes actually are. */
int inf_is_zlib_header(const uint8_t *p, size_t len);

uint32_t inf_adler32(const uint8_t *data, size_t len);

#endif /* ARMRECOMP_INFLATE_H */
