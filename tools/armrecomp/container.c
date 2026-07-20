/* container.c — parsing the Vita container stack.
 *
 * See container.h for the shape. The discipline here is the one the whole
 * toolkit runs on: every offset that comes out of the file is checked against
 * the buffer length before it is dereferenced, and anything that does not add
 * up becomes a named error. A parser that guesses produces a report that looks
 * right and is wrong, which is worse than no report.
 */

#include "container.h"

#include <stdio.h>
#include <string.h>

/* --- bounds-checked little-endian readers ---------------------------------- */
/*
 * These return 0 and set `*ok = 0` on an out-of-range read rather than
 * trapping, so a caller can do a run of reads and check once at the end.
 */

static uint16_t rd16(const uint8_t *b, size_t size, uint64_t off, int *ok) {
    if (off + 2 > size) { *ok = 0; return 0; }
    return (uint16_t)(b[off] | ((uint16_t)b[off + 1] << 8));
}

static uint32_t rd32(const uint8_t *b, size_t size, uint64_t off, int *ok) {
    if (off + 4 > size) { *ok = 0; return 0; }
    return (uint32_t)b[off]
         | ((uint32_t)b[off + 1] << 8)
         | ((uint32_t)b[off + 2] << 16)
         | ((uint32_t)b[off + 3] << 24);
}

static uint64_t rd64(const uint8_t *b, size_t size, uint64_t off, int *ok) {
    if (off + 8 > size) { *ok = 0; return 0; }
    return (uint64_t)rd32(b, size, off, ok)
         | ((uint64_t)rd32(b, size, off + 4, ok) << 32);
}

static int fail(char *err, size_t errsz, const char *msg) {
    if (err && errsz) snprintf(err, errsz, "%s", msg);
    return 1;
}

/* --- names ----------------------------------------------------------------- */

const char *vc_kind_name(vc_kind k) {
    switch (k) {
        case VC_SELF: return "SELF (SCE\\0-wrapped ELF)";
        case VC_ELF:  return "plain ELF32";
        case VC_VELF: return "velf (ET_SCE_RELEXEC)";
        case VC_PFS:  return "PFS-encrypted";
        default:      return "unknown";
    }
}

const char *vc_elf_type_name(uint16_t t) {
    switch (t) {
        case VC_ET_EXEC:        return "ET_EXEC";
        case VC_ET_SCE_EXEC:    return "ET_SCE_EXEC (static)";
        case VC_ET_SCE_RELEXEC: return "ET_SCE_RELEXEC";
        default:                return "?";
    }
}

const char *vc_phdr_type_name(uint32_t t) {
    switch (t) {
        case VC_PT_LOAD:        return "LOAD";
        case VC_PT_SCE_RELA:    return "SCE_RELA";
        case VC_PT_SCE_COMMENT: return "SCE_COMMENT";
        case VC_PT_SCE_VERSION: return "SCE_VERSION";
        case VC_PT_ARM_EXIDX:   return "ARM_EXIDX";
        default:                return "?";
    }
}

/* --- identification -------------------------------------------------------- */

vc_kind vc_identify(const uint8_t *buf, size_t size) {
    int ok = 1;

    if (!buf || size < 0x20) return VC_UNKNOWN;

    if (rd32(buf, size, 0, &ok) == VC_SCE_MAGIC && ok)
        return VC_SELF;

    if (buf[0] == 0x7F && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F') {
        ok = 1;
        uint16_t type = rd16(buf, size, 0x10, &ok);
        if (ok && type == VC_ET_SCE_RELEXEC) return VC_VELF;
        return VC_ELF;
    }

    /* A PFS-encrypted eboot has no magic at all — it is ciphertext from byte
     * zero. We cannot positively identify it here; the caller identifies it by
     * the presence of a `sce_pfs/` directory alongside. Reporting UNKNOWN and
     * letting the CLI explain is more honest than guessing from entropy. */
    return VC_UNKNOWN;
}

/* --- the ELF layer --------------------------------------------------------- */
/*
 * Parses the ELF header and program headers at absolute offsets `elf_off` /
 * `phdr_off` in the buffer. In a SELF these are plaintext even though the
 * segments they describe are not, which is exactly why phase 1 can report what
 * phase 2 has to do.
 */

static int parse_elf_layer(const uint8_t *buf, size_t size,
                           uint64_t elf_off, uint64_t phdr_off,
                           vc_module *out, char *err, size_t errsz) {
    int ok = 1;

    if (elf_off + 0x34 > size)
        return fail(err, errsz, "ELF header offset is past the end of the file");

    if (!(buf[elf_off] == 0x7F && buf[elf_off + 1] == 'E' &&
          buf[elf_off + 2] == 'L' && buf[elf_off + 3] == 'F'))
        return fail(err, errsz, "no ELF magic at the offset the SCE header gave");

    out->elf.type      = rd16(buf, size, elf_off + 0x10, &ok);
    out->elf.machine   = rd16(buf, size, elf_off + 0x12, &ok);
    out->elf.entry     = rd32(buf, size, elf_off + 0x18, &ok);
    out->elf.phoff     = rd32(buf, size, elf_off + 0x1C, &ok);
    out->elf.phentsize = rd16(buf, size, elf_off + 0x2A, &ok);
    out->elf.phnum     = rd16(buf, size, elf_off + 0x2C, &ok);
    if (!ok) return fail(err, errsz, "ELF header runs past the end of the file");

    out->have_elf = 1;

    if (out->elf.machine != VC_EM_ARM)
        return fail(err, errsz, "not an ARM module (e_machine is not EM_ARM)");

    /* phentsize of 0 would make the loop below spin on one entry forever. */
    if (out->elf.phentsize == 0)
        return fail(err, errsz, "e_phentsize is zero");

    int n = out->elf.phnum;
    if (n > VC_MAX_SEGMENTS) n = VC_MAX_SEGMENTS;

    for (int i = 0; i < n; i++) {
        uint64_t p = phdr_off + (uint64_t)i * out->elf.phentsize;
        ok = 1;
        out->phdr[i].type   = rd32(buf, size, p + 0x00, &ok);
        out->phdr[i].offset = rd32(buf, size, p + 0x04, &ok);
        out->phdr[i].vaddr  = rd32(buf, size, p + 0x08, &ok);
        out->phdr[i].filesz = rd32(buf, size, p + 0x10, &ok);
        out->phdr[i].memsz  = rd32(buf, size, p + 0x14, &ok);
        out->phdr[i].flags  = rd32(buf, size, p + 0x18, &ok);
        out->phdr[i].align  = rd32(buf, size, p + 0x1C, &ok);
        if (!ok) return fail(err, errsz, "program header table runs past the end of the file");
        out->phdr_count++;
    }

    return 0;
}

/* --- SELF ------------------------------------------------------------------ */

static int parse_self(const uint8_t *buf, size_t size, vc_module *out,
                      char *err, size_t errsz) {
    int ok = 1;
    vc_sce_header *h = &out->sce;

    h->magic               = rd32(buf, size, 0x00, &ok);
    h->version             = rd32(buf, size, 0x04, &ok);
    h->sdk_type            = rd16(buf, size, 0x08, &ok);
    h->header_type         = rd16(buf, size, 0x0A, &ok);
    h->metadata_offset     = rd32(buf, size, 0x0C, &ok);
    h->header_len          = rd64(buf, size, 0x10, &ok);
    h->elf_filesize        = rd64(buf, size, 0x18, &ok);
    h->self_filesize       = rd64(buf, size, 0x20, &ok);
    h->padding             = rd64(buf, size, 0x28, &ok);
    h->self_offset         = rd64(buf, size, 0x30, &ok);
    h->appinfo_offset      = rd64(buf, size, 0x38, &ok);
    h->elf_offset          = rd64(buf, size, 0x40, &ok);
    h->phdr_offset         = rd64(buf, size, 0x48, &ok);
    h->shdr_offset         = rd64(buf, size, 0x50, &ok);
    h->segment_info_offset = rd64(buf, size, 0x58, &ok);
    h->sceversion_offset   = rd64(buf, size, 0x60, &ok);
    h->controlinfo_offset  = rd64(buf, size, 0x68, &ok);
    h->controlinfo_size    = rd64(buf, size, 0x70, &ok);
    if (!ok) return fail(err, errsz, "SCE header is truncated");

    if (h->version != 3)
        return fail(err, errsz, "unsupported SCE header version (expected 3)");

    /* appinfo */
    ok = 1;
    out->appinfo.auth_id     = rd64(buf, size, h->appinfo_offset + 0x00, &ok);
    out->appinfo.vendor_id   = rd32(buf, size, h->appinfo_offset + 0x08, &ok);
    out->appinfo.self_type   = rd32(buf, size, h->appinfo_offset + 0x0C, &ok);
    out->appinfo.sys_version = rd64(buf, size, h->appinfo_offset + 0x10, &ok);
    out->have_appinfo = ok;

    if (parse_elf_layer(buf, size, h->elf_offset, h->phdr_offset, out, err, errsz))
        return 1;

    /* The segment table has one entry per program header. */
    for (int i = 0; i < out->phdr_count; i++) {
        uint64_t s = h->segment_info_offset + (uint64_t)i * 0x20;
        ok = 1;
        out->seg[i].offset      = rd64(buf, size, s + 0x00, &ok);
        out->seg[i].length      = rd64(buf, size, s + 0x08, &ok);
        out->seg[i].compression = rd64(buf, size, s + 0x10, &ok);
        out->seg[i].encryption  = rd64(buf, size, s + 0x18, &ok);
        if (!ok) return fail(err, errsz, "segment table runs past the end of the file");
        out->seg_count++;
    }

    return 0;
}

/* --- entry point ----------------------------------------------------------- */

int vc_parse(const uint8_t *buf, size_t size, vc_module *out,
             char *err, size_t errsz) {
    if (!buf || !out) return fail(err, errsz, "null buffer");

    memset(out, 0, sizeof(*out));
    if (err && errsz) err[0] = '\0';

    out->kind = vc_identify(buf, size);

    switch (out->kind) {
        case VC_SELF:
            return parse_self(buf, size, out, err, errsz);

        case VC_ELF:
        case VC_VELF:
            /* Already plaintext: the ELF header is at 0 and the program header
             * table offset comes from the header itself. */
            if (parse_elf_layer(buf, size, 0, 0, out, err, errsz)) return 1;
            /* Re-read the program headers from e_phoff, which parse_elf_layer
             * could not know on its first pass. */
            out->phdr_count = 0;
            return parse_elf_layer(buf, size, 0, out->elf.phoff, out, err, errsz);

        default:
            return fail(err, errsz,
                        "unrecognised container (no SCE\\0 or ELF magic) — "
                        "if this came from a NoNpDrm dump it is PFS-encrypted; "
                        "see docs/DECRYPT.md");
    }
}
