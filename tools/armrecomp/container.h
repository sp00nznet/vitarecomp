/* container.h — the Vita container stack, from dump to module.
 *
 *   .vpk (zip)  ->  app directory  ->  eboot.bin / *.suprx
 *                                          |
 *                                          v
 *                                    SCE\0 header  (SELF)
 *                                          |
 *                                          v
 *                                    ELF32 / velf  (ARM)
 *
 * Everything this header describes is PLAINTEXT in a retail SELF. The SCE
 * header, the appinfo block, the ELF header, the program headers and the
 * segment table all sit in the clear; only segment *contents* are encrypted.
 * That is what makes a phase-1 report possible with no key material at all —
 * we can say exactly what a module is and what stands between us and its code.
 *
 * Retail PFS dumps (`sce_pfs/` present) wrap all of this in a further encrypted
 * layer and are rejected with a named diagnostic rather than parsed as garbage.
 * See docs/DECRYPT.md.
 */

#ifndef ARMRECOMP_CONTAINER_H
#define ARMRECOMP_CONTAINER_H

#include <stddef.h>
#include <stdint.h>

/* --- what we are looking at ------------------------------------------------ */

typedef enum {
    VC_UNKNOWN = 0,
    VC_SELF,        /* SCE\0-wrapped ELF — an executable module */
    VC_ELF,         /* a plain ELF32, already decrypted */
    VC_VELF,        /* a plain ELF32 with e_type ET_SCE_RELEXEC */
    VC_PFS,         /* PFS-encrypted; opaque without a per-title klicensee */
} vc_kind;

/* SCE header magic, little-endian "SCE\0". */
#define VC_SCE_MAGIC 0x00454353u

/* ELF e_type values a Vita module can carry. ET_SCE_RELEXEC is the interesting
 * one: a relocatable executable, which is what almost every retail eboot is. */
#define VC_ET_EXEC        2
#define VC_ET_SCE_RELEXEC 0xFE04

/* ELF e_machine for ARM. */
#define VC_EM_ARM 40

/* Program header types, including the two Sony added. */
#define VC_PT_LOAD            0x00000001
#define VC_PT_SCE_RELA        0x60000000
#define VC_PT_SCE_COMMENT     0x6FFFFF00
#define VC_PT_SCE_VERSION     0x6FFFFF01
#define VC_PT_ARM_EXIDX       0x70000001

/* --- the SCE header -------------------------------------------------------- */
/* Verified byte-for-byte against a retail module; see tests/test_container.c. */

/* A correction worth recording.
 *
 * The layout below is NOT the PS3 SELF layout, and the difference is a silent
 * one. PS3 goes straight from `elf_filesize` at 0x18 to `self_offset` at 0x20;
 * Vita inserts `self_filesize` and a padding qword there, shifting every
 * subsequent field by 0x10.
 *
 * Built against the PS3 layout, this parser read `elf_offset` from 0x30 and got
 * `4` — a small, entirely plausible offset that looks like a real answer. The
 * only reason it was caught is that the ELF magic is independently locatable:
 * scanning for `7F 45 4C 46` puts it at 0xA0, which is the field at 0x40, not
 * 0x30. Structure that can be cross-checked against a landmark in the file is
 * worth more than structure that merely parses.
 */

typedef struct {
    uint32_t magic;             /* 0x00  "SCE\0"                                */
    uint32_t version;           /* 0x04  3 for Vita                             */
    uint16_t sdk_type;          /* 0x08                                         */
    uint16_t header_type;       /* 0x0A  1 = SELF                               */
    uint32_t metadata_offset;   /* 0x0C                                         */
    uint64_t header_len;        /* 0x10  where the segment region begins        */
    uint64_t elf_filesize;      /* 0x18  size of the ELF once decrypted         */
    uint64_t self_filesize;     /* 0x20  Vita-only; absent on PS3               */
    uint64_t padding;           /* 0x28  Vita-only; absent on PS3               */
    uint64_t self_offset;       /* 0x30                                         */
    uint64_t appinfo_offset;    /* 0x38                                         */
    uint64_t elf_offset;        /* 0x40  plaintext ELF header lives here        */
    uint64_t phdr_offset;       /* 0x48  plaintext program headers              */
    uint64_t shdr_offset;       /* 0x50                                         */
    uint64_t segment_info_offset;/* 0x58 plaintext segment table                */
    uint64_t sceversion_offset; /* 0x60                                         */
    uint64_t controlinfo_offset;/* 0x68                                         */
    uint64_t controlinfo_size;  /* 0x70                                         */
} vc_sce_header;

/* --- the appinfo block ----------------------------------------------------- */

typedef struct {
    uint64_t auth_id;
    uint32_t vendor_id;
    uint32_t self_type;         /* 4 = application                              */
    uint64_t sys_version;
} vc_appinfo;

/* --- the segment table ----------------------------------------------------- */

/* NOTE the encoding, which reads backwards and has bitten every parser that
 * assumed 1 == true: `encryption == 1` means ENCRYPTED, `== 2` means PLAIN.
 * Likewise `compression == 2` means zlib and `== 1` means stored. Getting this
 * inverted produces a parser that cheerfully reports a retail module as
 * plaintext and then hands random bytes to the decoder. */
#define VC_COMPRESS_NONE 1
#define VC_COMPRESS_ZLIB 2
#define VC_ENCRYPT_YES   1
#define VC_ENCRYPT_NO    2

typedef struct {
    uint64_t offset;
    uint64_t length;
    uint64_t compression;
    uint64_t encryption;
} vc_segment_info;

/* --- the ELF layer --------------------------------------------------------- */

typedef struct {
    uint16_t type;              /* e_type                                       */
    uint16_t machine;           /* e_machine                                    */
    uint32_t entry;             /* e_entry                                      */
    uint32_t phoff;
    uint16_t phnum;
    uint16_t phentsize;
} vc_elf_header;

typedef struct {
    uint32_t type;
    uint32_t offset;
    uint32_t vaddr;
    uint32_t filesz;
    uint32_t memsz;
    uint32_t flags;
    uint32_t align;
} vc_phdr;

/* --- the parsed whole ------------------------------------------------------ */

#define VC_MAX_SEGMENTS 32

typedef struct {
    vc_kind         kind;
    vc_sce_header   sce;
    vc_appinfo      appinfo;
    int             have_appinfo;
    vc_elf_header   elf;
    int             have_elf;
    vc_phdr         phdr[VC_MAX_SEGMENTS];
    int             phdr_count;
    vc_segment_info seg[VC_MAX_SEGMENTS];
    int             seg_count;
} vc_module;

/* Identify and parse a buffer. Returns 0 on success, non-zero on failure, and
 * writes a human-readable reason into `err` (never truncated past `errsz`).
 *
 * Every offset read out of the file is bounds-checked against `size` before it
 * is used. A malformed or truncated module is a named error, not a crash and
 * not a plausible-looking parse. */
int vc_parse(const uint8_t *buf, size_t size, vc_module *out,
             char *err, size_t errsz);

/* Sniff the container kind alone, without a full parse. */
vc_kind vc_identify(const uint8_t *buf, size_t size);

const char *vc_kind_name(vc_kind k);
const char *vc_elf_type_name(uint16_t e_type);
const char *vc_phdr_type_name(uint32_t p_type);

#endif /* ARMRECOMP_CONTAINER_H */
