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

/* Does this word have the SHAPE of a pointer to Thumb code? Cheap, and
 * deliberately says nothing about whether a function is there. */
static int code_ptr_shape(const vm_image *img, const uint8_t *p, uint32_t *out) {
    uint32_t w = (uint32_t)p[0] | ((uint32_t)p[1] << 8)
               | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    if (!(w & 1)) return 0;                       /* Thumb pointers only */
    uint32_t t = w & ~1u;
    if (t < img->seg_vaddr || t >= img->seg_vaddr + img->seg_len) return 0;
    if ((t - img->seg_vaddr) & 1) return 0;
    *out = t;
    return 1;
}

/* How many consecutive words from `off` have that shape.
 *
 * This is the evidence that turns a guess into a reading. Four adjacent words
 * that are all Thumb-tagged, all correctly aligned, and all land inside a
 * 5.6 MB window of a 4 GB space do not happen by accident — the odds are
 * around 1 in 10^13. Such a run is a POINTER TABLE, and knowing that is worth
 * more than any property of the individual entries. */
#define SHAPE_RUN_MIN 4

static uint32_t shape_run_len(const vm_image *img, const uint8_t *scan,
                              uint32_t scan_len, uint32_t off) {
    uint32_t n = 0, t;
    while (off + 4 <= scan_len && code_ptr_shape(img, scan + off, &t)) {
        n++;
        off += 4;
    }
    return n;
}

/* Sweep one region for words that look like pointers INTO the executable
 * segment. The region being scanned and the region being pointed at are two
 * different things: candidates come from wherever the module stores pointers,
 * but a valid target is always code. */
static uint32_t shape_scan_region(const vm_image *img, vf_result *r, seedq *q,
                                  const uint8_t *scan, uint32_t scan_len) {
    const uint8_t *text = img->data + img->seg_file;
    const uint32_t base = img->seg_vaddr;
    const uint32_t len  = img->seg_len;
    uint32_t found = 0;
    uint32_t run_left = 0;      /* words remaining in the current table */

    for (uint32_t off = 0; off + 4 <= scan_len; off += 4) {
        uint32_t t;

        /* Only measure when not already inside a table, so a long run costs
         * one measurement rather than one per entry. A run too short to
         * qualify is at most SHAPE_RUN_MIN words, so re-measuring across it is
         * bounded and cheap. */
        if (run_left == 0) {
            uint32_t n = shape_run_len(img, scan, scan_len, off);
            if (n >= SHAPE_RUN_MIN) run_left = n;
        }
        int in_table = run_left > 0;
        if (run_left) run_left--;

        if (!code_ptr_shape(img, scan + off, &t)) continue;

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
         * reported separately rather than merged into one number.
         *
         * INSIDE A TABLE the filter is not just unnecessary, it is wrong. A
         * word in a run has already been established as a pointer by its
         * neighbours, so demanding a prologue of it only throws away the
         * functions that genuinely lack one. On this corpus's first title that
         * is 47 of the 551 static constructors, and they are exactly the kind
         * you would expect: leaves that start with `movw` because they store a
         * constant and save nothing, and one that is a bare `bx lr`. Each one
         * missed is a run-time trap in a table the program walks at startup. */
        uint16_t h = (uint16_t)(text[t - base] | ((uint16_t)text[t - base + 1] << 8));
        int prologue = ((h & 0xFE00) == 0xB400)          /* push            */
                    || (h == 0xE92D)                     /* push.w / stmdb  */
                    || ((h & 0xFF80) == 0xB080);         /* sub sp, #imm    */

        if (!prologue && !in_table) { r->rejected_shape++; continue; }

        sq_push(q, t, ARM_T32, 1);
        r->seeds_shape++;
        found++;
    }
    return found;
}

static void shape_scan(const vm_image *img, vf_result *r, seedq *q) {
    shape_scan_region(img, r, q, img->data + img->seg_file, img->seg_len);

    /* The data segments, which is where a C++ module keeps the table of
     * static constructors. Nothing in .text points at them: the only reference
     * to a constructor is its slot in that table, so a sweep of the executable
     * segment alone finds none of them — on this corpus's first title, all 551,
     * including the module's very first function.
     *
     * Counted separately from the .text sweep. They are the same heuristic run
     * over different bytes, but a table of pointers is a much richer place to
     * find pointers than a code segment is, and merging the two numbers would
     * hide which one is doing the work. */
    for (uint32_t i = 0; i < img->data_seg_count; i++) {
        const vm_seg *s = &img->data_segs[i];
        if ((uint64_t)s->file + s->len > img->size) continue;
        r->seeds_shape_data +=
            shape_scan_region(img, r, q, img->data + s->file, s->len);
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

    /* A separate registry of function ENTRIES, distinct from the map of decoded
     * instructions.
     *
     * These must not be conflated. `seen` records "an instruction was decoded
     * here" and exists to stop the walk repeating work. Whether an address is a
     * FUNCTION is a different question, and the answer is yes whenever
     * something calls it — even if another function's flow walk happened to
     * wander through it first, which is common where code falls through into
     * what is also a call target.
     *
     * Gating registration on `seen` meant such addresses were never registered,
     * while the emitter still emitted calls to them: the generated C compiled
     * and then failed to link, naming symbols that were never defined. */
    uint8_t *fseen = (uint8_t *)calloc(out->seen_bytes, 1);
    if (!fseen) { free(q.v); return 1; }

    #define FN_MARK(a) (fseen[(((a) - base) >> 1) >> 3] |= (uint8_t)(1u << ((((a) - base) >> 1) & 7)))
    #define FN_TEST(a) ((fseen[(((a) - base) >> 1) >> 3] >> ((((a) - base) >> 1) & 7)) & 1)

    uint32_t head = 0;
    while (head < q.n) {
        seed s = q.v[head++];
        if (s.addr < base || s.addr >= base + img->seg_len) continue;
        if (FN_TEST(s.addr)) continue;

        FN_MARK(s.addr);
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
        if (FN_TEST(s.addr)) continue;

        FN_MARK(s.addr);
        add_func(out, s.addr, s.mode, s.heur);
        walk(img, out, &q, s.addr, s.mode, &out->funcs[out->count - 1]);
    }

    #undef FN_MARK
    #undef FN_TEST

    free(fseen);
    free(q.v);
    return 0;
}

void vf_free(vf_result *r) {
    free(r->funcs);
    free(r->seen);
    memset(r, 0, sizeof(*r));
}
