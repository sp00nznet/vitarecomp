/* mem.h — the recompiled program's address space.
 *
 * The Vita has an MMU, so unlike the PSP there is no small fixed map to fold
 * onto a backing store with a mask. What there is instead is simpler in
 * practice: a module is loaded at a known base (0x81000000 for the executable
 * segment) and the interesting addresses are all within a bounded window above
 * it. A flat host allocation plus a subtraction covers it.
 *
 * Accesses outside the window are COUNTED rather than silently returning zero.
 * A recompiled program should reach a steady state with that counter flat;
 * when it climbs, discovery or translation missed something.
 */

#ifndef VITARECOMP_MEM_H
#define VITARECOMP_MEM_H

#include <stdint.h>
#include <stddef.h>

extern uint32_t vita_mem_bad_access;

/* Reserve `size` bytes of guest address space starting at `base`. */
int  vita_mem_init(uint32_t base, size_t size);
void vita_mem_free(void);

/* Returns NULL rather than a wild pointer when an access would straddle the
 * end of the region, so a bad address is a diagnosable NULL dereference at the
 * point of failure instead of silent corruption elsewhere. */
void *vita_mem_ptr(uint32_t addr, uint32_t len);

/* Bytes backed from `addr` to the end of the region, or 0 if it is outside.
 *
 * The HLE needs this and `vita_mem_ptr` cannot answer it: a C string has no
 * length until you find its terminator, so forwarding `strlen` to the host
 * means scanning guest memory, and a scan with no bound runs off the
 * allocation when the guest hands over a pointer to something that is not a
 * string. Unlike a bad read this does not count as a bad access — asking how
 * much is there is a legitimate question. */
uint32_t vita_mem_avail(uint32_t addr);

uint32_t vita_read32(uint32_t addr);
uint16_t vita_read16(uint32_t addr);
uint8_t  vita_read8 (uint32_t addr);

void vita_write32(uint32_t addr, uint32_t v);
void vita_write16(uint32_t addr, uint16_t v);
void vita_write8 (uint32_t addr, uint8_t  v);

#endif /* VITARECOMP_MEM_H */
