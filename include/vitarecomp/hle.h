/* hle.h — the firmware surface, implemented rather than emulated.
 *
 * A recompiled module calls firmware through a stub in its own .text. The
 * emitter binds those stubs to `vita_hle_<name>` symbols and generates a
 * default for every one of them that traps by name, so the output links from
 * the first build and an unimplemented call announces which function the game
 * wanted. This header is for the ones that are real.
 *
 * LINKING. The generated defaults must go in a STATIC LIBRARY listed AFTER the
 * vitarecomp runtime, never in an object file. A linker pulls an archive
 * member only for a symbol that is still undefined, so a real implementation
 * here wins and the trapping default is simply never extracted. That is what
 * makes the HLE incrementally implementable without editing generated code:
 * write the function, relink, and the stub stops being used. Put the defaults
 * in a plain object file instead and every implemented function becomes a
 * duplicate-symbol error.
 *
 * CALLING CONVENTION. Every `vita_hle_*` function is `void(void)` because that
 * is what the dispatch table holds. Arguments arrive in r0-r3 per AAPCS and
 * the result goes back in r0, so each one reads and writes the CPU globals
 * directly. Pointer arguments are GUEST addresses and must be translated
 * through `vita_mem_ptr` — they are not host pointers and dereferencing one as
 * though it were is the mistake this layer exists to prevent.
 */

#ifndef VITARECOMP_HLE_H
#define VITARECOMP_HLE_H

#include <stdint.h>

/* Give the guest heap a region to allocate from. The runtime cannot pick this
 * itself: where the free space is depends on how the host laid out the module
 * and its stack, which is the host's decision. `malloc` traps until this is
 * called, rather than quietly allocating over something. */
void vita_heap_init(uint32_t base, uint32_t size);

/* Bytes handed out and the high-water mark, for telling "the program leaks"
 * from "the heap was too small". */
uint32_t vita_heap_used(void);
uint32_t vita_heap_size(void);

#endif /* VITARECOMP_HLE_H */
