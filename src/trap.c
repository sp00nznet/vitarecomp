/* trap.c — the gaps, announcing themselves.
 *
 * Every one of these is a place the recompiler knew it did not know something.
 * The default is to abort, because a program that continues past an
 * untranslated instruction produces wrong results with full confidence, and
 * that is far more expensive to debug than a stop with an address on it.
 *
 * VITARECOMP_TRACE=1 changes that to log-and-continue. It is a DISCOVERY AID,
 * not a correctness mode: past the first unimplemented import the machine state
 * is wrong, and every subsequent trap is reached through a path that would not
 * have happened on hardware. What it is good for is one run naming twenty
 * firmware functions instead of one, which is far better prioritisation than a
 * static count of what the import table contains. Anything it reports should be
 * treated as "the module wanted this" and not as "the module wants these, in
 * this order, this many times".
 */

#include "vitarecomp/recomp_rt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int   g_trace = -1;
static FILE *g_out;

/* Distinct traps already reported, so a loop does not bury the log. */
#define SEEN_SLOTS 4096
static uint32_t g_seen[SEEN_SLOTS];
static uint32_t g_hits;

static int trace_on(void) {
    if (g_trace < 0) {
        const char *e = getenv("VITARECOMP_TRACE");
        g_trace = (e && *e && *e != '0') ? 1 : 0;
        g_out = stderr;
    }
    return g_trace;
}

/* Report each distinct key once. Returns 1 the first time a key is seen. */
static int first_time(uint32_t key) {
    uint32_t h = (key * 2654435761u) & (SEEN_SLOTS - 1);
    for (uint32_t i = 0; i < SEEN_SLOTS; i++) {
        uint32_t s = (h + i) & (SEEN_SLOTS - 1);
        if (g_seen[s] == key) return 0;
        if (g_seen[s] == 0)   { g_seen[s] = key; return 1; }
    }
    return 1;   /* table full: report rather than lose it */
}

uint32_t vita_trap_count(void) { return g_hits; }

void vita_trap_unimpl(uint32_t addr, uint32_t raw, const char *what) {
    g_hits++;
    if (trace_on()) {
        if (first_time(addr))
            fprintf(g_out, "TRACE unimpl  0x%08X  raw 0x%08X  %s\n",
                    addr, raw, what ? what : "?");
        return;
    }
    fprintf(stderr,
            "vitarecomp: untranslated instruction at 0x%08X (raw 0x%08X): %s\n",
            addr, raw, what ? what : "?");
    abort();
}

void vita_trap_indirect(uint32_t addr, uint32_t target) {
    g_hits++;
    if (trace_on()) {
        if (first_time(addr))
            fprintf(g_out, "TRACE indirect 0x%08X -> 0x%08X\n", addr, target);
        return;
    }
    fprintf(stderr,
            "vitarecomp: unresolved indirect transfer at 0x%08X -> 0x%08X\n",
            addr, target);
    abort();
}

void vita_trap_import(uint32_t addr, uint32_t nid) {
    g_hits++;
    if (trace_on()) {
        /* Keyed on the NID, not the call site: the interesting question is
         * which firmware function is wanted, and the same one called from
         * three places is one thing to implement, not three. */
        if (first_time(nid ? nid : addr))
            fprintf(g_out, "TRACE import  NID 0x%08X  (stub 0x%08X)\n", nid, addr);
        return;
    }
    fprintf(stderr,
            "vitarecomp: unimplemented firmware import at 0x%08X (NID 0x%08X)\n",
            addr, nid);
    abort();
}
