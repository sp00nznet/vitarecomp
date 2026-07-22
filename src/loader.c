/* loader.c — ELF32 segment loading into guest memory. */

#include "vitarecomp/loader.h"
#include "vitarecomp/mem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PT_LOAD 1

static uint16_t r16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t r32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint8_t *slurp(const char *path, size_t *size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n <= 0) { fclose(f); return NULL; }
    rewind(f);
    uint8_t *b = (uint8_t *)malloc((size_t)n);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return NULL; }
    fclose(f);
    *size = (size_t)n;
    return b;
}

/* Walk the program headers, calling back for each PT_LOAD. `load` selects
 * whether the bytes are copied or merely measured, so probing and loading
 * cannot disagree about which segments count. */
static int walk(const char *path, vita_load_info *info, int load) {
    size_t size = 0;
    uint8_t *buf = slurp(path, &size);
    if (!buf) return 1;

    memset(info, 0, sizeof(*info));
    info->lowest = 0xFFFFFFFFu;

    if (size < 0x34 || buf[0] != 0x7F || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') {
        free(buf); return 1;
    }

    uint32_t phoff     = r32(buf + 0x1C);
    uint16_t phentsize = r16(buf + 0x2A);
    uint16_t phnum     = r16(buf + 0x2C);
    if (phentsize == 0) { free(buf); return 1; }

    for (uint16_t i = 0; i < phnum; i++) {
        uint64_t p = (uint64_t)phoff + (uint64_t)i * phentsize;
        if (p + 0x20 > size) break;

        const uint8_t *ph = buf + p;
        if (r32(ph + 0x00) != PT_LOAD) continue;

        uint32_t offset = r32(ph + 0x04);
        uint32_t vaddr  = r32(ph + 0x08);
        uint32_t filesz = r32(ph + 0x10);
        uint32_t memsz  = r32(ph + 0x14);

        if ((uint64_t)offset + filesz > size) continue;

        if (vaddr < info->lowest) info->lowest = vaddr;
        if (vaddr + memsz > info->highest) info->highest = vaddr + memsz;
        info->segments++;

        if (!load) continue;

        void *dst = vita_mem_ptr(vaddr, memsz);
        if (!dst) {
            fprintf(stderr,
                    "vitarecomp: segment %u (0x%08X, %u bytes) is outside guest memory\n",
                    i, vaddr, memsz);
            free(buf);
            return 1;
        }

        /* memsz exceeds filesz for .bss, and the difference must be zeroed
         * rather than left as whatever the allocation held. A program whose
         * .bss starts non-zero fails in ways that look like logic bugs. */
        memcpy(dst, buf + offset, filesz);
        if (memsz > filesz) memset((uint8_t *)dst + filesz, 0, memsz - filesz);
    }

    free(buf);
    return info->segments ? 0 : 1;
}

int vita_probe_elf(const char *path, vita_load_info *info) {
    return walk(path, info, 0);
}

int vita_load_elf(const char *path, vita_load_info *info) {
    return walk(path, info, 1);
}
