/* trap.c — the gaps, announcing themselves.
 *
 * Every one of these is a place the recompiler knew it did not know something.
 * They abort rather than return, because a program that continues past an
 * untranslated instruction is producing wrong results with full confidence,
 * and that is far more expensive to debug than a stop with an address on it.
 */

#include "vitarecomp/recomp_rt.h"

#include <stdio.h>
#include <stdlib.h>

void vita_trap_unimpl(uint32_t addr, uint32_t raw, const char *what) {
    fprintf(stderr,
            "vitarecomp: untranslated instruction at 0x%08X (raw 0x%08X): %s\n",
            addr, raw, what ? what : "?");
    abort();
}

void vita_trap_indirect(uint32_t addr, uint32_t target) {
    fprintf(stderr,
            "vitarecomp: unresolved indirect transfer at 0x%08X -> 0x%08X\n",
            addr, target);
    abort();
}

void vita_trap_import(uint32_t addr, uint32_t nid) {
    fprintf(stderr,
            "vitarecomp: unimplemented firmware import at 0x%08X (NID 0x%08X)\n",
            addr, nid);
    abort();
}
