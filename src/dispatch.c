/* dispatch.c — guest address to recompiled function. */

#include "vitarecomp/dispatch.h"
#include "vitarecomp/recomp_rt.h"

#include <stdio.h>

static const vita_dispatch_entry *g_table;
static uint32_t g_count;
static uint32_t g_hits, g_misses;

void vita_dispatch_init(const vita_dispatch_entry *table, uint32_t count) {
    g_table = table;
    g_count = count;
    g_hits = g_misses = 0;
}

uint32_t vita_dispatch_hits(void)   { return g_hits; }
uint32_t vita_dispatch_misses(void) { return g_misses; }

void vita_dispatch(uint32_t addr) {
    /* Bit 0 marks the instruction set, not the address. Every pointer to Thumb
     * code carries it, so failing to mask means every lookup misses by one. */
    uint32_t key = addr & ~1u;

    uint32_t lo = 0, hi = g_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (g_table[mid].addr == key) {
            g_hits++;
            g_table[mid].fn();
            return;
        }
        if (g_table[mid].addr < key) lo = mid + 1; else hi = mid;
    }

    g_misses++;
    /* A miss is not recoverable by returning. The caller expected the callee to
     * do something — set a return value, mutate memory, never come back — and
     * pretending it ran is how a recompiled program produces confident garbage.
     * vita_trap_indirect stops unless tracing is on. */
    vita_trap_indirect(0, addr);
}
