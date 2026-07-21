/* analyze.c — function discovery by recursive descent.
 *
 * The walk carries (address, mode) pairs rather than bare addresses. Every
 * seed records the instruction set it was reached in, because there is no way
 * to recover that from the bytes: Thumb decoded as ARM yields instructions, not
 * errors.
 */

#include "analyze.h"

#include <stdlib.h>
#include <string.h>

/* --- the visited bitmap ---------------------------------------------------- */
/* One bit per 2 bytes: the finest granularity an instruction can start on. */

static int seen_get(const vf_result *r, uint32_t off) {
    uint32_t i = off >> 1;
    return (r->seen[i >> 3] >> (i & 7)) & 1;
}

static void seen_set(vf_result *r, uint32_t off) {
    uint32_t i = off >> 1;
    r->seen[i >> 3] |= (uint8_t)(1u << (i & 7));
}

/* --- a queue of (address, mode) seeds -------------------------------------- */

typedef struct { uint32_t addr; arm_mode mode; uint8_t heur; } seed;

typedef struct { seed *v; uint32_t n, cap; } seedq;

static void sq_push(seedq *q, uint32_t addr, arm_mode mode, uint8_t heur) {
    if (q->n == q->cap) {
        q->cap = q->cap ? q->cap * 2 : 1024;
        q->v = (seed *)realloc(q->v, q->cap * sizeof(seed));
    }
    q->v[q->n].addr = addr;
    q->v[q->n].mode = mode;
    q->v[q->n].heur = heur;
    q->n++;
}

static void add_func(vf_result *r, uint32_t addr, arm_mode mode, uint8_t heur) {
    if (r->count == r->cap) {
        r->cap = r->cap ? r->cap * 2 : 4096;
        r->funcs = (vf_func *)realloc(r->funcs, r->cap * sizeof(vf_func));
    }
    vf_func *f = &r->funcs[r->count++];
    memset(f, 0, sizeof(*f));
    f->addr = addr;
    f->mode = mode;
    f->from_heuristic = heur;
}

/* --- walking one function --------------------------------------------------- */
/*
 * Follows local control flow from `start`, marking instruction starts and
 * queueing call targets as new functions. Branch targets are followed as local
 * flow; a branch that is really a tail call therefore merges the callee into
 * this function's extent, which inflates extent without losing correctness —
 * every instruction still gets decoded exactly once, from the right mode.
 */

static void walk(const vm_image *img, vf_result *r, seedq *q,
                 uint32_t start, arm_mode mode, vf_func *fn) {
    const uint8_t *text = img->data + img->seg_file;
    const uint32_t base = img->seg_vaddr;
    const uint32_t len  = img->seg_len;

    /* Local block worklist. Bounded: a pathological function cannot make this
     * grow without bound because every block start is marked seen first. */
    seedq local = {0};
    sq_push(&local, start, mode, 0);

    while (local.n) {
        seed s = local.v[--local.n];
        uint32_t a = s.addr;

        for (;;) {
            if (a < base || a >= base + len) break;
            uint32_t off = a - base;
            if (seen_get(r, off)) break;          /* already decoded here */

            arm_insn in;
            int n = arm_decode(text, base, len, a, s.mode, &in);
            if (n == 0) break;

            seen_set(r, off);
            r->insns_total++;
            r->bytes_covered += (uint32_t)n;
            fn->insns++;
            if (a + (uint32_t)n > fn->end) fn->end = a + (uint32_t)n;
            if (in.cls == A_SIMD) r->simd_insns++;

            /* Calls seed new functions. An interworking call flips the mode of
             * the callee, which is the whole reason mode travels with a seed. */
            if (in.cls == A_CALL) {
                if (in.has_target) {
                    arm_mode cm = in.switches_mode
                                ? (s.mode == ARM_T32 ? ARM_A32 : ARM_T32)
                                : s.mode;
                    sq_push(q, in.target, cm, 0);
                    r->seeds_call++;
                } else {
                    /* A register-form BLX. It is a call whose destination is
                     * computed, so it seeds nothing and the callee is reachable
                     * only through a stored pointer. Counting these separately
                     * is what makes the shape heuristic's job visible: they are
                     * the calls whose targets discovery cannot follow. */
                    r->indirect_sites++;
                }
                a += (uint32_t)n;
                continue;
            }

            if (in.cls == A_RETURN) break;

            if (in.cls == A_INDIRECT) { r->indirect_sites++; break; }

            if (in.cls == A_BRANCH && in.has_target) {
                sq_push(&local, in.target, s.mode, 0);
                if (!in.conditional) break;       /* unconditional: flow ends */
            }

            a += (uint32_t)n;
        }
    }

    free(local.v);
}

/* --- pointer-shape recovery ------------------------------------------------- */
/*
 * With no relocations, stored function pointers can only be recognised by what
 * they look like. A candidate word must land inside the executable segment, be
 * correctly aligned, and decode as something. That is a heuristic and is
 * reported as one — it will both miss real pointers and admit false ones.
 *
 * The Thumb bit is the one genuinely reliable signal here: a stored pointer to
 * Thumb code has bit 0 set, because that is how the hardware switches mode on
 * an indirect branch. A word with bit 0 set that otherwise looks like a code
 * address is far more likely to be a real function pointer than a coincidence.
 */

static void shape_scan(const vm_image *img, vf_result *r, seedq *q) {
    const uint8_t *text = img->data + img->seg_file;
    const uint32_t base = img->seg_vaddr;
    const uint32_t len  = img->seg_len;

    for (uint32_t off = 0; off + 4 <= len; off += 4) {
        uint32_t w = (uint32_t)text[off] | ((uint32_t)text[off + 1] << 8)
                   | ((uint32_t)text[off + 2] << 16) | ((uint32_t)text[off + 3] << 24);

        if (!(w & 1)) continue;                   /* Thumb pointers only */
        uint32_t t = w & ~1u;
        if (t < base || t >= base + len) { continue; }
        if ((t - base) & 1) continue;

        /* Do not re-seed something already decoded: that is not a discovery. */
        if (seen_get(r, t - base)) continue;

        arm_insn in;
        if (arm_decode(text, base, len, t, ARM_T32, &in) == 0) { r->rejected_shape++; continue; }
        if (in.cls == A_UNKNOWN || in.cls == A_UNDEF) { r->rejected_shape++; continue; }

        /* "Decodes as something" is far too weak a filter to be worth much:
         * the Thumb decoder almost never returns unknown, so nearly every
         * candidate passes and the heuristic degenerates into "any word with
         * bit 0 set that points into .text". In several megabytes of data that
         * is mostly coincidence.
         *
         * Requiring a function PROLOGUE is a real filter. Compiled Thumb
         * functions overwhelmingly begin by pushing registers — PUSH (0xB4xx /
         * 0xB5xx) or PUSH.W / STMDB (0xE92D). A leaf function that pushes
         * nothing will be missed, which is why the two tiers are counted and
         * reported separately rather than merged into one number. */
        uint16_t h = (uint16_t)(text[t - base] | ((uint16_t)text[t - base + 1] << 8));
        int prologue = ((h & 0xFE00) == 0xB400)          /* push            */
                    || (h == 0xE92D)                     /* push.w / stmdb  */
                    || ((h & 0xFF80) == 0xB080);         /* sub sp, #imm    */

        if (!prologue) { r->rejected_shape++; continue; }

        sq_push(q, t, ARM_T32, 1);
        r->seeds_shape++;
    }
}

/* --- entry point ------------------------------------------------------------ */

int vf_discover(const vm_image *img, const vm_module *mod, vf_result *out) {
    memset(out, 0, sizeof(*out));

    out->seen_bytes = (img->seg_len / 2 + 7) / 8 + 1;
    out->seen = (uint8_t *)calloc(out->seen_bytes, 1);
    if (!out->seen) return 1;

    seedq q = {0};
    const uint32_t base = img->seg_vaddr;

    /* 1. module_start. The offset carries no Thumb bit, and the corpus is
     *    overwhelmingly Thumb, so it is seeded as Thumb. */
    if (mod->have_info && mod->info.module_start != 0xFFFFFFFF) {
        sq_push(&q, base + (mod->info.module_start & 0x3FFFFFFF), ARM_T32, 0);
        out->seeds_entry++;
    }

    /* 2. Export entry tables. Each export names a real function. */
    if (mod->have_info) {
        uint32_t p = mod->info.export_top;
        while (p + 0x20 <= mod->info.export_end) {
            const uint8_t *e = vm_ptr(img, p, 0x20);
            if (!e) break;
            uint16_t size  = (uint16_t)(e[0] | (e[1] << 8));
            uint16_t nfunc = (uint16_t)(e[6] | (e[7] << 8));
            uint32_t etab  = (uint32_t)e[0x1C] | ((uint32_t)e[0x1D] << 8)
                           | ((uint32_t)e[0x1E] << 16) | ((uint32_t)e[0x1F] << 24);
            if (size < 0x20) break;

            const uint8_t *t = vm_va(img, etab, (uint32_t)nfunc * 4);
            for (uint32_t i = 0; t && i < nfunc; i++) {
                uint32_t v = (uint32_t)t[i*4] | ((uint32_t)t[i*4+1] << 8)
                           | ((uint32_t)t[i*4+2] << 16) | ((uint32_t)t[i*4+3] << 24);
                if (v < base || v >= base + img->seg_len) continue;
                sq_push(&q, v & ~1u, (v & 1) ? ARM_T32 : ARM_A32, 0);
                out->seeds_export++;
            }
            p += size;
        }
    }

    /* 3. Linear harvest of call targets. Recursive descent alone stalls almost
     *    immediately — the same lesson psprecomp learned when descent from the
     *    entry point found 47 instructions. */
    {
        const uint8_t *text = img->data + img->seg_file;
        for (uint32_t off = 0; off + 4 <= img->seg_len; off += 2) {
            arm_insn in;
            if (arm_decode(text, base, img->seg_len, base + off, ARM_T32, &in) == 0) continue;
            if (in.cls == A_CALL && in.has_target &&
                in.target >= base && in.target < base + img->seg_len) {
                sq_push(&q, in.target, in.switches_mode ? ARM_A32 : ARM_T32, 0);
            }
        }
    }

    /* Drain: each unseen seed becomes a function. */
    uint32_t head = 0;
    while (head < q.n) {
        seed s = q.v[head++];
        if (s.addr < base || s.addr >= base + img->seg_len) continue;
        if (seen_get(out, s.addr - base)) continue;

        add_func(out, s.addr, s.mode, s.heur);
        walk(img, out, &q, s.addr, s.mode, &out->funcs[out->count - 1]);
    }

    /* 4. Shape recovery, after everything principled has been exhausted, so it
     *    only ever adds what the reliable seeds could not reach. */
    uint32_t before = q.n;
    shape_scan(img, out, &q);
    head = before;
    while (head < q.n) {
        seed s = q.v[head++];
        if (s.addr < base || s.addr >= base + img->seg_len) continue;
        if (seen_get(out, s.addr - base)) continue;

        add_func(out, s.addr, s.mode, s.heur);
        walk(img, out, &q, s.addr, s.mode, &out->funcs[out->count - 1]);
    }

    free(q.v);
    return 0;
}

void vf_free(vf_result *r) {
    free(r->funcs);
    free(r->seen);
    memset(r, 0, sizeof(*r));
}
