/* loader.h — putting the module's data where the recompiled code expects it.
 *
 * Recompiling the code is only half of it. The generated C reads its own
 * constants, tables and strings through vita_read32() at the ORIGINAL virtual
 * addresses, so those bytes have to be present in guest memory before anything
 * runs. Without this, every literal-pool address and every rodata lookup reads
 * zero — and a program that reads zero for its jump tables does not crash
 * usefully, it wanders.
 *
 * So the ELF is still needed at run time, and not as a formality: the
 * recompiler extracted the instructions from it, and the loader supplies
 * everything else that was in it.
 */

#ifndef VITARECOMP_LOADER_H
#define VITARECOMP_LOADER_H

#include <stdint.h>

typedef struct {
    uint32_t lowest;      /* lowest p_vaddr seen           */
    uint32_t highest;     /* highest p_vaddr + p_memsz     */
    int      segments;
} vita_load_info;

/* Load every PT_LOAD segment of an ELF32 into guest memory at its own vaddr.
 * `vita_mem_init` must already cover the range. Returns 0 on success. */
int vita_load_elf(const char *path, vita_load_info *info);

/* Determine the address range an ELF needs, without loading it. Lets a host
 * size its guest memory from the file rather than from a guess. */
int vita_probe_elf(const char *path, vita_load_info *info);

#endif /* VITARECOMP_LOADER_H */
