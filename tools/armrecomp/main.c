/* armrecomp — the Vita static-recompilation toolkit CLI.
 *
 * Phase 1: identify any layer of the container stack and report exactly what
 * stands between here and decodable ARM code. No key material is needed for
 * any of this, and none is bundled — see docs/DECRYPT.md.
 */

#include "container.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *USAGE =
    "armrecomp — static-recompilation toolkit for PlayStation Vita\n"
    "\n"
    "  armrecomp info <file>     identify a module and report its structure\n"
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
            printf("report — the container layout or the flag encoding is being misread.\n");
        } else if (encrypted) {
            printf("%d of %d segments are encrypted. armrecomp does not ship or\n",
                   encrypted, m.seg_count);
            printf("derive key material; supply a decrypted ELF. See docs/DECRYPT.md.\n");
        } else {
            printf("no encrypted segments, verified against zlib headers — this\n");
            printf("module can go straight to the decoder once inflated.\n");
        }
    }

    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fputs(USAGE, stderr);
        return 2;
    }

    if (strcmp(argv[1], "info") == 0 && argc >= 3)
        return cmd_info(argv[2]);

    fputs(USAGE, stderr);
    return 2;
}
