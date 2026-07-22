/* dispatch.h — indirect transfers, resolved at run time.
 *
 * A recompiled program has no program counter, so `BX r3` cannot be translated
 * into anything static: the destination is a value, and it is only known while
 * the program is running. Every recompiler needs this layer, and on Vita it
 * carries more traffic than most — the module has ~18,000 indirect call sites,
 * because `module_start` itself passes the real entry point as a POINTER rather
 * than calling it, and C++ virtual dispatch does the rest.
 *
 * The table maps a guest address to the C function that was recompiled from it.
 * A hit is a real transfer; a miss is a named trap, never a silent return —
 * jumping to an address we never translated has to stop the program, because
 * continuing means running the caller's code with the callee's job undone.
 */

#ifndef VITARECOMP_DISPATCH_H
#define VITARECOMP_DISPATCH_H

#include <stdint.h>

typedef void (*vita_fn)(void);

typedef struct {
    uint32_t addr;      /* guest virtual address, Thumb bit cleared */
    vita_fn  fn;
} vita_dispatch_entry;

/* The table must be sorted by addr; the generated one is. */
void vita_dispatch_init(const vita_dispatch_entry *table, uint32_t count);

/* Call the function recompiled from `addr`. The Thumb bit is masked off here
 * rather than at every call site — a pointer to Thumb code always has bit 0
 * set, and that is an instruction-set marker, not part of the address. */
void vita_dispatch(uint32_t addr);

/* How many distinct addresses were dispatched to, and how many missed. Useful
 * for telling "the table is incomplete" from "the program went somewhere it
 * should not have". */
uint32_t vita_dispatch_hits(void);
uint32_t vita_dispatch_misses(void);

#endif /* VITARECOMP_DISPATCH_H */
