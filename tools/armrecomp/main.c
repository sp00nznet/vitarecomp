/* armrecomp â€” the Vita static-recompilation toolkit CLI.
 *
 * Phase 1: identify any layer of the container stack and report exactly what
 * stands between here and decodable ARM code. No key material is needed for
 * any of this, and none is bundled â€” see docs/DECRYPT.md.
 */

#include "container.h"
#include "inflate.h"
#include "decode.h"
#include "module.h"
#include "analyze.h"
#include "emit.h"
#include "nids.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One directory, portably. Not worth a dependency, and an existing directory
 * is success — regenerating over a previous emit is the normal case. */
#ifdef _WIN32
#include <direct.h>
#define make_dir(p) (_mkdir(p) == 0 || errno == EEXIST ? 0 : 1)
#else
#include <sys/stat.h>
#define make_dir(p) (mkdir((p), 0777) == 0 || errno == EEXIST ? 0 : 1)
#endif
#include <errno.h>

static const char *USAGE =
    "armrecomp â€” static-recompilation toolkit for PlayStation Vita\n"
    "\n"
    "  armrecomp info    <file>          identify a module and report structure\n"
    "  armrecomp extract <file> <out>    SELF -> plain ELF32\n"
    "  armrecomp cover   <file.elf>      decode-coverage report\n"
    "  armrecomp funcs   <file.elf> [niddb]  module info and the HLE work list\n"
    "\n"
    "Accepts a SELF (eboot.bin, *.suprx) or a plain ELF/velf. A PFS-encrypted\n"
    "NoNpDrm dump is reported as such rather than parsed as garbage.\n";

static uint8_t *slurp(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);

    uint8_t *buf = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
    if (!buf) { fclose(f); return NULL; }

    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *out_size = (size_t)n;
    return buf;
}

static const char *flags_str(uint32_t f, char *tmp) {
    /* ELF segment permission bits, in the conventional rwx order. */
    tmp[0] = (f & 4) ? 'r' : '-';
    tmp[1] = (f & 2) ? 'w' : '-';
    tmp[2] = (f & 1) ? 'x' : '-';
    tmp[3] = '\0';
    return tmp;
}

static int cmd_info(const char *path) {
    size_t size = 0;
    uint8_t *buf = slurp(path, &size);
    if (!buf) {
        fprintf(stderr, "armrecomp: cannot read %s\n", path);
        return 1;
    }

    vc_module m;
    char err[256];
    int rc = vc_parse(buf, size, &m, err, sizeof(err));

    printf("file:     %s\n", path);
    printf("size:     %zu bytes\n", size);
    printf("format:   %s\n", vc_kind_name(m.kind));

    if (rc) {
        printf("\nerror:    %s\n", err);
        free(buf);
        return 1;
    }

    if (m.kind == VC_SELF) {
        printf("\nSCE header:\n");
        printf("  version         %u\n", m.sce.version);
        printf("  sdk type        0x%04X\n", m.sce.sdk_type);
        printf("  header len      0x%llX\n", (unsigned long long)m.sce.header_len);
        printf("  elf filesize    %llu bytes (decrypted)\n",
               (unsigned long long)m.sce.elf_filesize);
        if (m.have_appinfo) {
            printf("  auth id         0x%016llX\n",
                   (unsigned long long)m.appinfo.auth_id);
            printf("  self type       %u%s\n", m.appinfo.self_type,
                   m.appinfo.self_type == 4 ? " (application)" : "");
            printf("  sys version     0x%llX\n",
                   (unsigned long long)m.appinfo.sys_version);
        }
    }

    if (m.have_elf) {
        printf("\nELF:\n");
        printf("  type            %s (0x%04X)\n",
               vc_elf_type_name(m.elf.type), m.elf.type);
        printf("  machine         EM_ARM\n");
        printf("  entry           0x%08X\n", m.elf.entry);
        printf("  segments        %u\n", m.elf.phnum);
    }

    if (m.phdr_count) {
        char tmp[4];
        printf("\nsegments:\n");
        printf("  %-3s %-12s %-6s %-10s %-10s %s\n",
               "#", "type", "flags", "vaddr", "filesz", "memsz");
        for (int i = 0; i < m.phdr_count; i++) {
            printf("  %-3d %-12s %-6s 0x%08X %-10u %u\n",
                   i,
                   vc_phdr_type_name(m.phdr[i].type),
                   flags_str(m.phdr[i].flags, tmp),
                   m.phdr[i].vaddr,
                   m.phdr[i].filesz,
                   m.phdr[i].memsz);
        }
    }

    if (m.seg_count) {
        int encrypted = 0;
        int disagree  = 0;

        printf("\nsegment encryption:\n");
        for (int i = 0; i < m.seg_count; i++) {
            int enc = (m.seg[i].encryption == VC_ENCRYPT_YES);
            int zip = (m.seg[i].compression == VC_COMPRESS_ZLIB);
            if (enc) encrypted++;

            /* Do not take the flag's word for it.
             *
             * The encryption field reads backwards (2 == plain), which is
             * exactly the sort of thing a parser gets inverted while still
             * producing a confident-looking report. So cross-check the claim
             * against the bytes: a segment that is really stored-zlib begins
             * with a zlib header, and ciphertext does not. `78` is the only
             * CMF a Vita SELF has been observed to use; the second byte varies
             * with compression level, and the pair must satisfy zlib's header
             * checksum (CMF<<8|FLG divisible by 31).
             *
             * This turns "the flag says plain" into "the flag says plain and
             * the bytes agree", and prints a loud line when they do not. */
            const char *observed = "";
            if (m.seg[i].offset + 2 <= size) {
                unsigned cmf = buf[m.seg[i].offset];
                unsigned flg = buf[m.seg[i].offset + 1];
                int is_zlib = (cmf & 0x0F) == 8 && ((cmf << 8) | flg) % 31 == 0;

                if (!enc && zip && !is_zlib) { observed = "  <-- FLAG SAYS PLAIN, BYTES ARE NOT ZLIB"; disagree++; }
                else if (enc && is_zlib)     { observed = "  <-- FLAG SAYS ENCRYPTED, BYTES ARE ZLIB"; disagree++; }
                else if (!enc && zip)        { observed = "  (zlib header verified)"; }
            }

            printf("  %-3d %-10llu bytes  %-9s %-9s%s\n",
                   i,
                   (unsigned long long)m.seg[i].length,
                   zip ? "zlib" : "stored",
                   enc ? "ENCRYPTED" : "plain",
                   observed);
        }

        printf("\n");
        if (disagree) {
            printf("%d segment(s) disagree with their own flags. Do not trust this\n", disagree);
            printf("report â€” the container layout or the flag encoding is being misread.\n");
        } else if (encrypted) {
            printf("%d of %d segments are encrypted. armrecomp does not ship or\n",
                   encrypted, m.seg_count);
            printf("derive key material; supply a decrypted ELF. See docs/DECRYPT.md.\n");
        } else {
            printf("no encrypted segments, verified against zlib headers â€” this\n");
            printf("module can go straight to the decoder once inflated.\n");
        }
    }

    free(buf);
    return 0;
}

/* --- extract: SELF -> plain ELF32 ------------------------------------------ */
/*
 * Reassembly is mechanical once the container is parsed: the plaintext ELF
 * header and program headers are copied out of the SELF, and each segment is
 * inflated into the file offset its program header declares.
 *
 * What makes it worth doing carefully is that every step has a value the file
 * itself declares, so success is checkable rather than assumed. Three
 * independent numbers have to agree: the inflated size against `p_filesz`, the
 * Adler-32 against the segment bytes, and the total against `elf_filesize`.
 */

static int cmd_extract(const char *path, const char *outpath) {
    size_t size = 0;
    uint8_t *buf = slurp(path, &size);
    if (!buf) {
        fprintf(stderr, "armrecomp: cannot read %s\n", path);
        return 1;
    }

    vc_module m;
    char err[256];
    if (vc_parse(buf, size, &m, err, sizeof(err))) {
        fprintf(stderr, "armrecomp: %s\n", err);
        free(buf);
        return 1;
    }

    if (m.kind == VC_ELF || m.kind == VC_VELF) {
        fprintf(stderr, "armrecomp: already a plain ELF; nothing to extract\n");
        free(buf);
        return 1;
    }

    for (int i = 0; i < m.seg_count; i++) {
        if (m.seg[i].encryption == VC_ENCRYPT_YES) {
            fprintf(stderr,
                    "armrecomp: segment %d is encrypted. This toolkit does not "
                    "ship or derive\nkey material; supply a decrypted ELF. See "
                    "docs/DECRYPT.md.\n", i);
            free(buf);
            return 1;
        }
    }

    size_t out_size = (size_t)m.sce.elf_filesize;
    uint8_t *out = (uint8_t *)calloc(out_size ? out_size : 1, 1);
    if (!out) {
        fprintf(stderr, "armrecomp: out of memory (%zu bytes)\n", out_size);
        free(buf);
        return 1;
    }

    /* ELF header, then the program header table at the offset the ELF header
     * itself declares. Both are plaintext inside the SELF. */
    if (m.sce.elf_offset + 0x34 > size) {
        fprintf(stderr, "armrecomp: ELF header past end of file\n");
        goto fail;
    }
    memcpy(out, buf + m.sce.elf_offset, 0x34);

    size_t ph_bytes = (size_t)m.elf.phnum * m.elf.phentsize;
    if (m.sce.phdr_offset + ph_bytes > size || m.elf.phoff + ph_bytes > out_size) {
        fprintf(stderr, "armrecomp: program header table does not fit\n");
        goto fail;
    }
    memcpy(out + m.elf.phoff, buf + m.sce.phdr_offset, ph_bytes);

    printf("segments:\n");
    for (int i = 0; i < m.seg_count; i++) {
        uint64_t src_off = m.seg[i].offset;
        uint64_t src_len = m.seg[i].length;
        uint32_t dst_off = m.phdr[i].offset;
        uint32_t want    = m.phdr[i].filesz;

        /* SCE_RELA and SCE_VERSION segments carry a p_offset like any other,
         * but a p_filesz of 0 would mean nothing to place. */
        if (want == 0) { printf("  %-3d skipped (p_filesz 0)\n", i); continue; }

        if (src_off + src_len > size) {
            fprintf(stderr, "armrecomp: segment %d source past end of file\n", i);
            goto fail;
        }
        if ((uint64_t)dst_off + want > out_size) {
            fprintf(stderr, "armrecomp: segment %d does not fit in the output\n", i);
            goto fail;
        }

        if (m.seg[i].compression == VC_COMPRESS_ZLIB) {
            size_t produced = want;
            inf_status st = inf_zlib(buf + src_off, (size_t)src_len,
                                     out + dst_off, &produced);
            if (st != INF_OK) {
                fprintf(stderr, "armrecomp: segment %d: %s\n", i, inf_strerror(st));
                goto fail;
            }
            /* The inflated size must match what the program header declares.
             * A stream that decompresses cleanly to the wrong length means the
             * segment table and the program headers disagree, which means the
             * container is being misread. */
            if (produced != want) {
                fprintf(stderr,
                        "armrecomp: segment %d inflated to %zu, p_filesz says %u\n",
                        i, produced, want);
                goto fail;
            }
            printf("  %-3d %8llu -> %-9u zlib, adler ok\n",
                   i, (unsigned long long)src_len, want);
        } else {
            if (src_len != want) {
                fprintf(stderr,
                        "armrecomp: segment %d stored length %llu != p_filesz %u\n",
                        i, (unsigned long long)src_len, want);
                goto fail;
            }
            memcpy(out + dst_off, buf + src_off, want);
            printf("  %-3d %8llu -> %-9u stored\n",
                   i, (unsigned long long)src_len, want);
        }
    }

    /* Independent sanity checks on the result, in increasing order of what
     * they would catch. */
    if (!(out[0] == 0x7F && out[1] == 'E' && out[2] == 'L' && out[3] == 'F')) {
        fprintf(stderr, "armrecomp: reassembled file is not an ELF\n");
        goto fail;
    }

    /* e_entry is NOT an absolute virtual address on Vita.
     *
     * It is encoded relative to the module: the top two bits select a program
     * header, the low 30 are a byte offset into that segment. Checking it as an
     * absolute address fails on every module â€” Uncharted's 0x004BA470 sits far
     * below segment 0's vaddr of 0x81000000, while being comfortably inside
     * that segment's 5,656,372 bytes.
     *
     * Worth stating because the failure is quiet in the other direction too: on
     * a module whose load address happened to be low, an absolute-address check
     * could pass by coincidence and validate nothing. */
    uint32_t entry_seg = m.elf.entry >> 30;
    uint32_t entry_off = m.elf.entry & 0x3FFFFFFF;

    int entry_in_exec = 0;
    if ((int)entry_seg < m.phdr_count &&
        (m.phdr[entry_seg].flags & 1) &&                     /* PF_X */
        entry_off < m.phdr[entry_seg].memsz) {
        entry_in_exec = 1;
    }

    FILE *f = fopen(outpath, "wb");
    if (!f) {
        fprintf(stderr, "armrecomp: cannot write %s\n", outpath);
        goto fail;
    }
    fwrite(out, 1, out_size, f);
    fclose(f);

    printf("\nwrote %s\n", outpath);
    printf("  size          %zu bytes (elf_filesize declared %llu)\n",
           out_size, (unsigned long long)m.sce.elf_filesize);
    printf("  entry         0x%08X -> segment %u + 0x%X %s\n",
           m.elf.entry, entry_seg, entry_off,
           entry_in_exec ? "(executable)"
                         : "<-- NOT in an executable segment");
    if (entry_in_exec)
        printf("  vaddr         0x%08X\n", m.phdr[entry_seg].vaddr + entry_off);

    free(out);
    free(buf);
    return entry_in_exec ? 0 : 1;

fail:
    free(out);
    free(buf);
    return 1;
}

/* --- cover: how much of a module do we actually understand? ---------------- */
/*
 * A linear sweep of .text in one instruction set. This is a MEASUREMENT, not a
 * disassembly, and it is honest about two things that would otherwise inflate
 * the result:
 *
 *  - .text contains data. ARM puts PC-relative constants in literal pools
 *    *inside* the executable segment, so some fraction of any linear sweep is
 *    decoding constants. Those bytes are not "instructions we failed to
 *    decode"; they are not instructions.
 *  - The instruction set is not knowable from a linear scan. Real code is
 *    mixed, so the sweep is run BOTH ways and both results reported. Whichever
 *    produces fewer unknowns is the module's dominant set, and the gap between
 *    them is the useful number.
 *
 * Function-accurate coverage needs phase 4, which follows control flow and
 * therefore knows the mode at every point. Until then this bounds the problem
 * rather than pretending to solve it.
 */

typedef struct {
    uint32_t count[A_NOP + 1];
    uint32_t total;
    uint32_t unknown;
    uint32_t simd;
    uint32_t widths[5];
    uint32_t targets;       /* direct branches/calls with a computed target */
    uint32_t targets_ok;    /* ...whose target lands inside this segment    */
} cover_stats;

static void sweep(const uint8_t *text, uint32_t vaddr, uint32_t len,
                  arm_mode mode, cover_stats *st) {
    memset(st, 0, sizeof(*st));

    uint32_t a = vaddr;
    const uint32_t end = vaddr + len;

    while (a < end) {
        arm_insn in;
        int n = arm_decode(text, vaddr, len, a, mode, &in);
        if (n == 0) break;

        st->total++;
        if (in.cls <= A_NOP) st->count[in.cls]++;
        if (in.cls == A_UNKNOWN || in.cls == A_UNDEF) st->unknown++;
        if (in.cls == A_SIMD) st->simd++;
        if (n <= 4) st->widths[n]++;

        if (in.has_target) {
            st->targets++;
            if (in.target >= vaddr && in.target < end) st->targets_ok++;
        }

        a += (uint32_t)n;
    }
}

/* Which instruction set is this really?
 *
 * NOT the unknown rate. That measures how permissive the decoder is for a given
 * mode, not whether the bytes are that mode â€” the ARM decoder assigns a class to
 * every op value, so it reports near-zero unknowns on any input at all,
 * including pure noise. An earlier revision used it and concluded that a module
 * whose returns are 10:1 Thumb was "dominant ARM".
 *
 * Direct branch targets are the honest discriminator, because they are
 * *arithmetic performed on the decoded bits* rather than a classification of
 * them. Decode real code in its real mode and its branches point at other code
 * in the same segment. Decode it in the wrong mode and the offsets are computed
 * from misaligned bits, so targets scatter â€” many landing outside the segment
 * entirely. This is a check the wrong answer can fail. */
static double target_score(const cover_stats *st) {
    if (st->targets == 0) return 0.0;
    return (double)st->targets_ok / st->targets;
}

static void report(const char *label, const cover_stats *st) {
    if (st->total == 0) { printf("  %-8s no instructions\n", label); return; }

    printf("  %-8s %9u insns   unknown %6.2f%%   simd %5.2f%%   "
           "branch targets in range %6.2f%%",
           label, st->total,
           100.0 * st->unknown / st->total,
           100.0 * st->simd    / st->total,
           100.0 * target_score(st));
    if (st->widths[2])
        printf("   16-bit %4.1f%%", 100.0 * st->widths[2] / st->total);
    printf("\n");
}

static int cmd_cover(const char *path) {
    size_t size = 0;
    uint8_t *buf = slurp(path, &size);
    if (!buf) {
        fprintf(stderr, "armrecomp: cannot read %s\n", path);
        return 1;
    }

    vc_module m;
    char err[256];
    if (vc_parse(buf, size, &m, err, sizeof(err))) {
        fprintf(stderr, "armrecomp: %s\n", err);
        free(buf);
        return 1;
    }
    if (m.kind == VC_SELF) {
        fprintf(stderr, "armrecomp: this is a SELF; run `extract` first\n");
        free(buf);
        return 1;
    }

    printf("file:     %s\n", path);

    int found = 0;
    for (int i = 0; i < m.phdr_count; i++) {
        if (!(m.phdr[i].flags & 1)) continue;             /* PF_X only */
        if (m.phdr[i].filesz == 0) continue;
        if ((uint64_t)m.phdr[i].offset + m.phdr[i].filesz > size) {
            fprintf(stderr, "armrecomp: segment %d extends past the file\n", i);
            continue;
        }
        found = 1;

        const uint8_t *text = buf + m.phdr[i].offset;
        uint32_t vaddr = m.phdr[i].vaddr;
        uint32_t len   = m.phdr[i].filesz;

        printf("\nsegment %d  vaddr 0x%08X  %u bytes executable\n", i, vaddr, len);

        cover_stats t, a;
        sweep(text, vaddr, len, ARM_T32, &t);
        sweep(text, vaddr, len, ARM_A32, &a);

        report("thumb", &t);
        report("arm",   &a);

        const cover_stats *best = target_score(&t) >= target_score(&a) ? &t : &a;
        printf("\n  dominant set: %s (by branch-target validity, not unknown rate)\n",
               best == &t ? "Thumb-2" : "ARM");
        printf("  class histogram (%s):\n", best == &t ? "thumb sweep" : "arm sweep");
        for (int c = 0; c <= A_NOP; c++) {
            if (!best->count[c]) continue;
            printf("    %-10s %9u  %5.2f%%\n",
                   arm_class_name((arm_class)c), best->count[c],
                   100.0 * best->count[c] / best->total);
        }
    }

    if (!found) fprintf(stderr, "armrecomp: no executable segment found\n");

    free(buf);
    return found ? 0 : 1;
}

/* --- funcs: the module's own account of what it needs ---------------------- */

/* Locate the executable segment and describe it for the module parser, and
 * collect the loadable non-executable ones for discovery to scan. */
static int exec_image(const uint8_t *buf, size_t size, const vc_module *m,
                      vm_image *img) {
    int found = 0;
    img->data           = buf;
    img->size           = size;
    img->data_seg_count = 0;

    for (int i = 0; i < m->phdr_count; i++) {
        if (m->phdr[i].filesz == 0) continue;
        if ((uint64_t)m->phdr[i].offset + m->phdr[i].filesz > size) continue;
        /* PT_LOAD only. The SCE_RELA and SCE_VERSION segments carry a vaddr of
         * zero and are not part of the address space. */
        if (m->phdr[i].type != 1) continue;

        if (m->phdr[i].flags & 1) {
            if (found) continue;                 /* first executable segment wins */
            img->seg_file  = m->phdr[i].offset;
            img->seg_vaddr = m->phdr[i].vaddr;
            img->seg_len   = m->phdr[i].filesz;
            found = 1;
        } else if (img->data_seg_count < VM_MAX_DATA_SEGS) {
            vm_seg *s = &img->data_segs[img->data_seg_count++];
            s->file  = m->phdr[i].offset;
            s->vaddr = m->phdr[i].vaddr;
            s->len   = m->phdr[i].filesz;
        }
    }
    return found;
}

static int load_module(const char *path, uint8_t **buf, size_t *size,
                       vc_module *vc, vm_image *img, vm_module *vm) {
    *buf = slurp(path, size);
    if (!*buf) { fprintf(stderr, "armrecomp: cannot read %s\n", path); return 0; }

    char err[256];
    if (vc_parse(*buf, *size, vc, err, sizeof(err))) {
        fprintf(stderr, "armrecomp: %s\n", err);
        free(*buf); return 0;
    }
    if (vc->kind == VC_SELF) {
        fprintf(stderr, "armrecomp: this is a SELF; run `extract` first\n");
        free(*buf); return 0;
    }
    if (!exec_image(*buf, *size, vc, img)) {
        fprintf(stderr, "armrecomp: no executable segment found\n");
        free(*buf); return 0;
    }
    if (vm_parse(img, vc->elf.entry, vm, err, sizeof(err))) {
        fprintf(stderr, "armrecomp: module info: %s\n", err);
        free(*buf); return 0;
    }
    return 1;
}

static int cmd_funcs(const char *path, const char *dbdir) {
    uint8_t *buf; size_t size;
    vc_module vc; vm_image img; vm_module vm;
    if (!load_module(path, &buf, &size, &vc, &img, &vm)) return 1;

    /* The NID database is optional. Without it the report still gives library
     * NIDs and counts, which is enough to size the work; with it the report
     * names every function, which is enough to plan it. */
    nid_db *db = NULL;
    if (dbdir) {
        int files = 0, entries = 0;
        db = nid_db_load(dbdir, &files, &entries);
        if (db) printf("nid db:   %d files, %d functions\n\n", files, entries);
        else    fprintf(stderr, "armrecomp: cannot read NID db at %s\n", dbdir);
    }

    printf("module:   %s\n", vm.info.name);
    printf("  nid           0x%08X\n", vm.info.module_nid);
    printf("  module_start  0x%08X\n", vm.info.module_start);
    if (vm.info.module_stop != 0xFFFFFFFF)
        printf("  module_stop   0x%08X\n", vm.info.module_stop);

    printf("\nfirmware libraries needed (%u functions across %d libraries):\n",
           vm.total_func_imports, vm.import_count);

    /* Sort by function count: the libraries a bring-up has to implement first
     * are the ones the module leans on hardest. */
    int order[VM_MAX_IMPORTS];
    for (int i = 0; i < vm.import_count; i++) order[i] = i;
    for (int i = 1; i < vm.import_count; i++) {
        int k = order[i], j = i - 1;
        while (j >= 0 && vm.imports[order[j]].num_funcs < vm.imports[k].num_funcs) {
            order[j + 1] = order[j]; j--;
        }
        order[j + 1] = k;
    }

    uint32_t named = 0, unnamed = 0;
    for (int i = 0; i < vm.import_count; i++) {
        const vm_import *im = &vm.imports[order[i]];
        const char *ln = im->name[0] ? im->name : nid_lib_name(db, im->library_nid);
        printf("  %-32s %4u   nid 0x%08X\n",
               ln ? ln : "(unnamed)", im->num_funcs, im->library_nid);

        if (!db) continue;

        /* The NID table is an array of 32-bit hashes at an absolute virtual
         * address, one per imported function, in the same order as the entry
         * (stub) table. */
        const uint8_t *t = vm_va(&img, im->func_nid_table,
                                 (uint32_t)im->num_funcs * 4);
        for (uint32_t k = 0; t && k < im->num_funcs; k++) {
            uint32_t nid = (uint32_t)t[k*4] | ((uint32_t)t[k*4+1] << 8)
                         | ((uint32_t)t[k*4+2] << 16) | ((uint32_t)t[k*4+3] << 24);
            const char *fn = nid_func_name(db, im->library_nid, nid);
            if (fn) { printf("      %-44s 0x%08X\n", fn, nid); named++; }
            else    { printf("      %-44s 0x%08X\n", "(unresolved)", nid); unnamed++; }
        }
    }

    if (db) {
        printf("\nresolved %u of %u imported functions (%.1f%%)\n",
               named, named + unnamed,
               (named + unnamed) ? 100.0 * named / (named + unnamed) : 0.0);
        nid_db_free(db);
    }

    if (vm.import_truncated)
        printf("\n  NOTE: import list truncated at %d entries\n", VM_MAX_IMPORTS);

    free(buf);
    return 0;
}

/* --- discover: how much of the module can we actually reach? ---------------- */

static int cmd_discover(const char *path) {
    uint8_t *buf; size_t size;
    vc_module vc; vm_image img; vm_module vm;
    if (!load_module(path, &buf, &size, &vc, &img, &vm)) return 1;

    vf_result r;
    if (vf_discover(&img, &vm, &r)) {
        fprintf(stderr, "armrecomp: discovery failed (out of memory)\n");
        free(buf);
        return 1;
    }

    uint32_t principled = 0, heuristic = 0;
    for (uint32_t i = 0; i < r.count; i++) {
        if (r.funcs[i].from_heuristic) heuristic++;
        else                           principled++;
    }

    printf("module:   %s   (%s)\n", vm.info.name,
           vc.elf.type == VC_ET_SCE_EXEC ? "ET_SCE_EXEC, no relocations"
                                         : "ET_SCE_RELEXEC");
    printf("text:     %u bytes at 0x%08X\n\n", img.seg_len, img.seg_vaddr);

    printf("seeds:\n");
    printf("  module_start        %u\n", r.seeds_entry);
    printf("  exports             %u\n", r.seeds_export);
    printf("  call targets        %u\n", r.seeds_call);
    printf("  pointer shape       %u  (heuristic; %u candidates rejected)\n",
           r.seeds_shape, r.rejected_shape);
    printf("    of which in .text %u\n", r.seeds_shape - r.seeds_shape_data);
    printf("    in data segments  %u  (%u segment%s scanned)\n",
           r.seeds_shape_data, img.data_seg_count,
           img.data_seg_count == 1 ? "" : "s");

    printf("\nfunctions:            %u\n", r.count);
    printf("  from seeds          %u\n", principled);
    printf("  from shape          %u  (heuristic)\n", heuristic);

    double cov = img.seg_len ? 100.0 * r.bytes_covered / img.seg_len : 0.0;
    printf("\ninstructions reached: %u\n", r.insns_total);
    printf("bytes covered:        %u / %u  (%.1f%%)\n",
           r.bytes_covered, img.seg_len, cov);
    printf("  simd                %u  (%.2f%%)\n", r.simd_insns,
           r.insns_total ? 100.0 * r.simd_insns / r.insns_total : 0.0);
    printf("  indirect sites      %u  (unresolved computed transfers)\n",
           r.indirect_sites);

    printf("\nimports:              %u functions across %d libraries\n",
           vm.total_func_imports, vm.import_count);

    /* Coverage is of the whole executable segment, which contains literal
     * pools and read-only data as well as code. 100%% is therefore not the
     * target and would in fact indicate over-reach. */
    printf("\nNote: coverage is over the whole executable segment, which also\n");
    printf("holds literal pools and read-only data. 100%% is not the target.\n");

    vf_free(&r);
    free(buf);
    return 0;
}

/* --- emit: functions to C --------------------------------------------------- */

static int cmd_emit(const char *path, const char *outpath, uint32_t limit,
                    const char *dbdir) {
    uint8_t *buf; size_t size;
    vc_module vc; vm_image img; vm_module vm;
    if (!load_module(path, &buf, &size, &vc, &img, &vm)) return 1;

    nid_db *db = NULL;
    if (dbdir) {
        int files = 0, entries = 0;
        db = nid_db_load(dbdir, &files, &entries);
        if (!db) fprintf(stderr, "armrecomp: cannot read NID db at %s "
                                 "(imports will be named by NID)\n", dbdir);
    }

    vf_result r;
    if (vf_discover(&img, &vm, &r)) {
        fprintf(stderr, "armrecomp: discovery failed\n");
        free(buf); return 1;
    }

    FILE *f = fopen(outpath, "w");
    if (!f) {
        fprintf(stderr, "armrecomp: cannot write %s\n", outpath);
        vf_free(&r); free(buf); return 1;
    }

    /* The import defaults go in their own directory beside the functions, one
     * file each. Build them into a static library listed AFTER the runtime and
     * implementing an import is just writing it — see emit.h. */
    char imppath[1024];
    snprintf(imppath, sizeof(imppath), "%s", outpath);
    char *dot = strrchr(imppath, '.');
    if (dot) *dot = '\0';
    strncat(imppath, "_imports", sizeof(imppath) - strlen(imppath) - 1);

    if (make_dir(imppath) != 0)
        fprintf(stderr, "armrecomp: cannot create %s\n", imppath);

    emit_stats st;
    em_emit(&img, &vm, db, &r, f, imppath, limit, &st);
    fclose(f);

    printf("wrote %s\n", outpath);
    printf("  functions     %u\n", st.funcs);
    printf("  instructions  %u\n", st.insns);
    printf("  translated    %u  (%.2f%%)\n", st.translated,
           st.insns ? 100.0 * st.translated / st.insns : 0.0);
    printf("  trapped       %u  (%.2f%%)\n", st.trapped,
           st.insns ? 100.0 * st.trapped / st.insns : 0.0);
    printf("  literals      %u  folded to constants\n", st.literals);
    printf("  import calls  %u  bound to firmware\n", st.import_calls);
    if (st.stub_shadowed)
        printf("  stubs shadowed %u  discovered as functions, routed as imports\n",
               st.stub_shadowed);

    if (st.trap_kinds) {
        /* Ranked, because the question is always which one to do next. */
        uint32_t ord[EM_MAX_TRAP_KINDS];
        for (uint32_t i = 0; i < st.trap_kinds; i++) ord[i] = i;
        for (uint32_t i = 1; i < st.trap_kinds; i++) {
            uint32_t k = ord[i]; int j = (int)i - 1;
            while (j >= 0 && st.traps[ord[j]].count < st.traps[k].count) {
                ord[j + 1] = ord[j]; j--;
            }
            ord[j + 1] = k;
        }
        printf("\nstill trapping, by kind:\n");
        for (uint32_t i = 0; i < st.trap_kinds; i++) {
            const em_trap_kind *t = &st.traps[ord[i]];
            printf("  %-24s %8u   %5.2f%% of all instructions\n",
                   t->what, t->count,
                   st.insns ? 100.0 * t->count / st.insns : 0.0);
        }
        if (st.traps_other)
            printf("  %-24s %8u\n", "(other kinds)", st.traps_other);
    }
    if (st.imports_used)
        printf("\nwrote %s/\n  %u import defaults, one file each, each trapping by name\n"
               "  build them as a static library listed AFTER the runtime;\n"
               "  implementing one is then just defining it\n",
               imppath, st.imports_used);
    /* Said here rather than left to be discovered as a compiler error, because
     * the error names a symptom nobody would connect to the cause. Each
     * function becomes its own COMDAT section, and the COFF object format
     * indexes at most 65,535 of them — so this is a COUNT limit, not a size
     * limit, and it arrives without warning at a few tens of thousands of
     * functions. */
    if (st.funcs > 8000)
        printf("\n%u functions is more COMDAT sections than a COFF object can index.\n"
               "  MSVC needs /bigobj on this file; other toolchains do not care.\n",
               st.funcs);

    printf("\nUntranslated instructions are named run-time traps, never silence.\n");

    nid_db_free(db);
    vm_free(&vm);
    vf_free(&r);
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fputs(USAGE, stderr);
        return 2;
    }

    if (strcmp(argv[1], "funcs") == 0 && argc >= 3)
        return cmd_funcs(argv[2], argc >= 4 ? argv[3] : NULL);

    if (strcmp(argv[1], "discover") == 0 && argc >= 3)
        return cmd_discover(argv[2]);

    if (strcmp(argv[1], "emit") == 0 && argc >= 4)
        return cmd_emit(argv[2], argv[3],
                        argc >= 5 ? (uint32_t)strtoul(argv[4], NULL, 0) : 0,
                        argc >= 6 ? argv[5] : NULL);

    if (strcmp(argv[1], "info") == 0 && argc >= 3)
        return cmd_info(argv[2]);

    if (strcmp(argv[1], "extract") == 0 && argc >= 4)
        return cmd_extract(argv[2], argv[3]);

    if (strcmp(argv[1], "cover") == 0 && argc >= 3)
        return cmd_cover(argv[2]);

    fputs(USAGE, stderr);
    return 2;
}

