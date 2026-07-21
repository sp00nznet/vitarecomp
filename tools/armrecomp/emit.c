/* emit.c â€” ARM to C.
 *
 * The output is meant to be read. Every instruction carries its address and
 * disassembly as a comment above the C it became, because the first thing
 * anyone does with a recompiled function that misbehaves is compare it against
 * the original.
 *
 * Two things this does NOT do, deliberately:
 *
 *   - It does not guess. An instruction whose operands the decoder did not
 *     fill becomes a named trap, never an approximation. A gap that stops the
 *     program is worth far more than one that produces a program which runs and
 *     is wrong.
 *   - It does not reorder. ARM has no delay slots, so the translation is
 *     instruction-for-instruction, and the only control flow that moves is a
 *     branch becoming a goto.
 */

#include "emit.h"

#include <stdlib.h>
#include <string.h>

#define MAX_INSNS_PER_FUNC 65536

static const char *reg_name(int r) {
    static const char *n[16] = {
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
        "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"
    };
    return (r >= 0 && r < 16) ? n[r] : "?";
}

/* --- collecting one function's instructions -------------------------------- */

typedef struct {
    arm_insn *v;
    uint32_t  n, cap;
    uint32_t *labels;
    uint32_t  nlabels, lcap;
} fbody;

static void fb_push(fbody *b, const arm_insn *in) {
    if (b->n == b->cap) {
        b->cap = b->cap ? b->cap * 2 : 256;
        b->v = (arm_insn *)realloc(b->v, b->cap * sizeof(arm_insn));
    }
    b->v[b->n++] = *in;
}

static void fb_label(fbody *b, uint32_t addr) {
    for (uint32_t i = 0; i < b->nlabels; i++)
        if (b->labels[i] == addr) return;
    if (b->nlabels == b->lcap) {
        b->lcap = b->lcap ? b->lcap * 2 : 64;
        b->labels = (uint32_t *)realloc(b->labels, b->lcap * sizeof(uint32_t));
    }
    b->labels[b->nlabels++] = addr;
}

static int fb_has_label(const fbody *b, uint32_t addr) {
    for (uint32_t i = 0; i < b->nlabels; i++)
        if (b->labels[i] == addr) return 1;
    return 0;
}

/* Collect a function by FOLLOWING ITS CONTROL FLOW, not by sweeping its extent.
 *
 * The distinction is the difference between a usable output and a 2.4 GB one.
 * `fn->end` is the highest address the discovery walk reached, and because a
 * tail call is a branch, that walk follows branches into other functions â€” so
 * an extent routinely spans code and data belonging to many functions. Sweeping
 * it linearly re-emits all of that under every function whose extent covers it,
 * and the same instruction lands in the output dozens of times.
 *
 * Flow-following emits each instruction once, in exactly the places it is
 * genuinely reachable, and stops at returns. Extent is still useful as a bound;
 * it is not a body.
 */

#define VISIT_SLOTS 8192

typedef struct { uint32_t k[VISIT_SLOTS]; } visited;

static int visit_mark(visited *v, uint32_t addr) {
    uint32_t h = (addr * 2654435761u) & (VISIT_SLOTS - 1);
    for (uint32_t i = 0; i < VISIT_SLOTS; i++) {
        uint32_t s = (h + i) & (VISIT_SLOTS - 1);
        if (v->k[s] == addr) return 0;          /* already seen */
        if (v->k[s] == 0)    { v->k[s] = addr; return 1; }
    }
    return 0;                                    /* table full: stop expanding */
}

static int cmp_addr(const void *a, const void *b) {
    uint32_t x = ((const arm_insn *)a)->addr, y = ((const arm_insn *)b)->addr;
    return x < y ? -1 : x > y ? 1 : 0;
}

/* --- the set of addresses that are actually functions ----------------------- */
/*
 * The emitter must never name a symbol it does not define. A call target only
 * becomes `vita_func_<addr>()` if discovery registered it; anything else is a
 * trap.
 *
 * This is not defensive tidying — it is the only correct answer. A linear sweep
 * decodes literal pools and tables as instructions, and some of that data
 * decodes as a BL with a plausible target. Two such targets in this module land
 * *inside the import table*, one of them 0x32 bytes into the first entry: not
 * code, never called at run time, and pure decoding artefact. Emitting calls to
 * them produced C that compiled and then failed to link.
 */

typedef struct { uint32_t *v; uint32_t n; } funcset;

static int fs_cmp(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

static int fs_has(const funcset *s, uint32_t addr) {
    uint32_t lo = 0, hi = s->n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (s->v[mid] == addr) return 1;
        if (s->v[mid] <  addr) lo = mid + 1; else hi = mid;
    }
    return 0;
}

static void collect(const vm_image *img, const vf_func *fn, fbody *b) {
    const uint8_t *text = img->data + img->seg_file;
    const uint32_t base = img->seg_vaddr;

    visited seen;
    memset(&seen, 0, sizeof(seen));

    /* A function registered because something called it may have been walked
     * by discovery only briefly — its recorded extent can be zero or tiny. The
     * body is still real, so fall back to a generous bound and let control flow
     * terminate the walk, which it does at the first return. Extent is a
     * safety limit here, not the definition of the body. */
    uint32_t bound = (fn->end > fn->addr + 16) ? fn->end : fn->addr + 8192;

    uint32_t stack[512];
    int sp_ = 0;
    stack[sp_++] = fn->addr;

    while (sp_ > 0 && b->n < MAX_INSNS_PER_FUNC) {
        uint32_t a = stack[--sp_];

        for (;;) {
            if (a < base || a >= base + img->seg_len) break;
            if (a >= bound) break;                   /* extent as a bound */
            if (!visit_mark(&seen, a)) break;        /* already emitted */

            arm_insn in;
            int n = arm_decode(text, base, img->seg_len, a, fn->mode, &in);
            if (n == 0) break;
            fb_push(b, &in);

            if (in.cls == A_RETURN) break;

            if (in.has_target && in.cls == A_BRANCH &&
                in.target >= fn->addr && in.target < fn->end) {
                fb_label(b, in.target);
                if (sp_ < (int)(sizeof(stack) / sizeof(stack[0])))
                    stack[sp_++] = in.target;
                if (!in.conditional) break;          /* flow ends here */
            } else if (in.cls == A_BRANCH && !in.conditional) {
                break;                               /* tail call */
            }

            a += (uint32_t)n;
        }
    }

    /* Blocks were discovered out of order; emit in address order so the output
     * reads alongside a disassembly. */
    if (b->n > 1) qsort(b->v, b->n, sizeof(arm_insn), cmp_addr);
}

/* --- operand rendering ------------------------------------------------------ */

/* A register operand, with r15 resolved.
 *
 * A recompiled program has no PC, so `pc` is not a variable and emitting it
 * produces C that does not compile â€” which is the good failure. The value is
 * known at translation time: reading PC in Thumb yields the instruction's own
 * address plus 4. The high-register ADD/MOV/CMP forms are where this actually
 * shows up, and they are common enough (position-independent address
 * computation) that leaving them to a trap would cost real coverage. */
static void reg_operand(char *dst, size_t cap, int r, const arm_insn *in) {
    if (r == 15) snprintf(dst, cap, "0x%08Xu", in->addr + 4);
    else         snprintf(dst, cap, "%s", reg_name(r));
}

/* The second operand of a data-processing instruction: an immediate, a plain
 * register, or a shifted register. */
static void operand2(char *dst, size_t cap, const arm_insn *in) {
    if (in->has_imm) {
        snprintf(dst, cap, "0x%X", in->imm);
        return;
    }
    if (in->rm == ARM_NO_REG) { snprintf(dst, cap, "/*?*/0"); return; }
    if (in->shift_amt == 0 && in->shift_type == SH_LSL) {
        reg_operand(dst, cap, in->rm, in);
        return;
    }
    if (in->rm == 15) { reg_operand(dst, cap, 15, in); return; }
    static const char *fn[4] = { "vita_lsl", "vita_lsr", "vita_asr", "vita_ror" };
    snprintf(dst, cap, "%s(%s, %u)", fn[in->shift_type & 3],
             reg_name(in->rm), in->shift_amt);
}

/* The address expression for a load or store. */
static int address(char *dst, size_t cap, const arm_insn *in) {
    if (in->rn == ARM_NO_REG) return 0;

    if (in->rn == 15) {
        /* PC-relative. A recompiled program has no PC, so it is resolved here:
         * for Thumb the base is the instruction address plus 4, aligned down to
         * a word. This is what turns a literal-pool load into a constant. */
        uint32_t pc = (in->addr + 4) & ~3u;
        snprintf(dst, cap, "0x%08X", pc + in->imm);
        return 1;
    }
    if (in->has_imm && in->imm)
        snprintf(dst, cap, "%s + 0x%X", reg_name(in->rn), in->imm);
    else if (in->rm != ARM_NO_REG)
        snprintf(dst, cap, "%s + %s", reg_name(in->rn), reg_name(in->rm));
    else
        snprintf(dst, cap, "%s", reg_name(in->rn));
    return 1;
}

/* --- one instruction --------------------------------------------------------- */

static void trap(FILE *f, const arm_insn *in, const char *why) {
    fprintf(f, "    vita_trap_unimpl(0x%08X, 0x%08X, \"%s\");\n",
            in->addr, in->raw, why);
}

/* Returns 1 if real C was emitted, 0 if a trap was. */
static int emit_insn(const vm_image *img, const funcset *fs, const fbody *b,
                     const arm_insn *in, FILE *f, emit_stats *st) {
    char o2[64], addr[64], rn_s[32];

    /* The first operand, with r15 resolved. Computed once because several
     * paths below need it and the ternary for "rn defaults to rd" is easy to
     * get inconsistently wrong when repeated. */
    reg_operand(rn_s, sizeof(rn_s),
                in->rn == ARM_NO_REG ? in->rd : in->rn, in);

    /* An instruction made conditional by an IT block, or a conditional branch,
     * is wrapped rather than translated differently. Getting this wrong is
     * invisible until a condition happens to be false. */
    int guarded = 0;
    if (in->cls != A_BRANCH && in->cond != ARM_COND_AL && in->op != OP_IT) {
        fprintf(f, "    if (vita_cond(%u)) {\n", in->cond);
        guarded = 1;
    }

    int ok = 1;
    switch (in->op) {
        case OP_MOV:
            operand2(o2, sizeof(o2), in);
            fprintf(f, "    %s = %s;\n", reg_name(in->rd), o2);
            if (in->sets_flags) fprintf(f, "    vita_flags_nz(%s);\n", reg_name(in->rd));
            break;

        case OP_MVN:
            operand2(o2, sizeof(o2), in);
            fprintf(f, "    %s = ~(%s);\n", reg_name(in->rd), o2);
            if (in->sets_flags) fprintf(f, "    vita_flags_nz(%s);\n", reg_name(in->rd));
            break;

        case OP_ADD: case OP_SUB: {
            operand2(o2, sizeof(o2), in);
            const char *rn = rn_s;
            if (in->sets_flags) {
                /* The operands have to be captured before the destination is
                 * written, because rd and rn are frequently the same register
                 * and the flag computation needs the ORIGINAL values. */
                fprintf(f, "    { uint32_t _a = %s, _b = %s;\n", rn, o2);
                fprintf(f, "      %s = _a %c _b;\n", reg_name(in->rd),
                        in->op == OP_ADD ? '+' : '-');
                fprintf(f, "      vita_flags_%s(_a, _b, %s); }\n",
                        in->op == OP_ADD ? "add" : "sub", reg_name(in->rd));
            } else {
                fprintf(f, "    %s = %s %c %s;\n", reg_name(in->rd), rn,
                        in->op == OP_ADD ? '+' : '-', o2);
            }
            break;
        }

        case OP_ADC: case OP_SBC: {
            const char *rn = rn_s;
            operand2(o2, sizeof(o2), in);
            fprintf(f, "    { uint32_t _a = %s, _b = %s, _c = (uint32_t)flag_c;\n", rn, o2);
            if (in->op == OP_ADC) {
                fprintf(f, "      %s = _a + _b + _c;\n", reg_name(in->rd));
                if (in->sets_flags)
                    fprintf(f, "      vita_flags_adc(_a, _b, _c, %s);\n", reg_name(in->rd));
            } else {
                fprintf(f, "      %s = _a - _b - (1u - _c);\n", reg_name(in->rd));
                if (in->sets_flags)
                    fprintf(f, "      vita_flags_sub(_a, _b + (1u - _c), %s);\n", reg_name(in->rd));
            }
            fprintf(f, "    }\n");
            break;
        }

        case OP_RSB:
            fprintf(f, "    { uint32_t _a = 0, _b = %s;\n", reg_name(in->rn));
            fprintf(f, "      %s = _a - _b;\n", reg_name(in->rd));
            if (in->sets_flags)
                fprintf(f, "      vita_flags_sub(_a, _b, %s);\n", reg_name(in->rd));
            fprintf(f, "    }\n");
            break;

        case OP_AND: case OP_ORR: case OP_EOR: case OP_BIC: {
            operand2(o2, sizeof(o2), in);
            const char *rn = rn_s;
            const char *ops = in->op == OP_AND ? "&" : in->op == OP_ORR ? "|" : "^";
            if (in->op == OP_BIC)
                fprintf(f, "    %s = %s & ~(%s);\n", reg_name(in->rd), rn, o2);
            else
                fprintf(f, "    %s = %s %s %s;\n", reg_name(in->rd), rn, ops, o2);
            if (in->sets_flags) fprintf(f, "    vita_flags_nz(%s);\n", reg_name(in->rd));
            break;
        }

        case OP_LSL: case OP_LSR: case OP_ASR: case OP_ROR: {
            static const char *fn2[4] = { "vita_lsl", "vita_lsr", "vita_asr", "vita_ror" };
            int which = in->op == OP_LSL ? 0 : in->op == OP_LSR ? 1
                      : in->op == OP_ASR ? 2 : 3;
            const char *src = reg_name(in->rm == ARM_NO_REG ? in->rd : in->rm);
            if (in->has_imm)
                fprintf(f, "    %s = %s(%s, %u);\n", reg_name(in->rd),
                        fn2[which], src, in->imm);
            else
                fprintf(f, "    %s = %s(%s, %s & 0xFF);\n", reg_name(in->rd),
                        fn2[which], reg_name(in->rd), reg_name(in->rm));
            if (in->sets_flags) fprintf(f, "    vita_flags_nz(%s);\n", reg_name(in->rd));
            break;
        }

        case OP_MUL:
            fprintf(f, "    %s = %s * %s;\n", reg_name(in->rd),
                    reg_name(in->rd), reg_name(in->rm));
            if (in->sets_flags) fprintf(f, "    vita_flags_nz(%s);\n", reg_name(in->rd));
            break;

        case OP_CMP: case OP_CMN:
            operand2(o2, sizeof(o2), in);
            fprintf(f, "    { uint32_t _a = %s, _b = %s;\n",
                    rn_s, o2);
            fprintf(f, "      vita_flags_%s(_a, _b, _a %c _b); }\n",
                    in->op == OP_CMP ? "sub" : "add",
                    in->op == OP_CMP ? '-' : '+');
            break;

        case OP_TST:
            operand2(o2, sizeof(o2), in);
            fprintf(f, "    vita_flags_nz(%s & %s);\n",
                    rn_s, o2);
            break;

        case OP_ADR:
            fprintf(f, "    %s = 0x%08X;\n", reg_name(in->rd),
                    ((in->addr + 4) & ~3u) + in->imm);
            break;

        case OP_LDR: case OP_LDRB: case OP_LDRH: case OP_LDRSB: case OP_LDRSH: {
            if (!address(addr, sizeof(addr), in)) { ok = 0; trap(f, in, "load addr"); break; }
            /* A literal-pool load has a fixed address, so the value is known at
             * translation time and becomes a constant rather than a memory
             * access. This is also what stops the pool from being mistaken for
             * code later. */
            if (in->rn == 15) {
                uint32_t pc = (in->addr + 4) & ~3u;
                const uint8_t *p = vm_va(img, pc + in->imm, 4);
                if (p) {
                    uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8)
                               | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
                    fprintf(f, "    %s = 0x%08X;  /* literal */\n", reg_name(in->rt), v);
                    st->literals++;
                    break;
                }
            }
            const char *rd = in->op == OP_LDR   ? "vita_read32(%s)"
                           : in->op == OP_LDRB  ? "vita_read8(%s)"
                           : in->op == OP_LDRH  ? "vita_read16(%s)"
                           : in->op == OP_LDRSB ? "vita_sxtb(vita_read8(%s))"
                                                : "vita_sxth(vita_read16(%s))";
            fprintf(f, "    %s = ", reg_name(in->rt));
            fprintf(f, rd, addr);
            fprintf(f, ";\n");
            break;
        }

        case OP_STR: case OP_STRB: case OP_STRH: {
            if (!address(addr, sizeof(addr), in)) { ok = 0; trap(f, in, "store addr"); break; }
            const char *w = in->op == OP_STR ? "vita_write32"
                          : in->op == OP_STRB ? "vita_write8" : "vita_write16";
            fprintf(f, "    %s(%s, %s);\n", w, addr, reg_name(in->rt));
            break;
        }

        case OP_PUSH: {
            /* ARM pushes in descending register order to descending addresses,
             * so the lowest-numbered register ends up at the lowest address.
             * Emitting the stores in ascending order with a pre-decremented sp
             * gives the same layout without simulating the order. */
            int count = 0;
            for (int i = 0; i < 16; i++) if (in->reglist & (1u << i)) count++;
            fprintf(f, "    sp -= %d;\n", count * 4);
            int slot = 0;
            for (int i = 0; i < 16; i++) {
                if (!(in->reglist & (1u << i))) continue;
                fprintf(f, "    vita_write32(sp + %d, %s);\n", slot * 4, reg_name(i));
                slot++;
            }
            break;
        }

        case OP_POP: {
            int slot = 0;
            for (int i = 0; i < 16; i++) {
                if (!(in->reglist & (1u << i))) continue;
                if (i == 15) { slot++; continue; }   /* PC: this is the return */
                fprintf(f, "    %s = vita_read32(sp + %d);\n", reg_name(i), slot * 4);
                slot++;
            }
            fprintf(f, "    sp += %d;\n", slot * 4);
            if (in->reglist & 0x8000) fprintf(f, "    return;\n");
            break;
        }

        case OP_SXTB: case OP_SXTH: case OP_UXTB: case OP_UXTH: {
            const char *fn3 = in->op == OP_SXTB ? "vita_sxtb"
                            : in->op == OP_SXTH ? "vita_sxth"
                            : in->op == OP_UXTB ? "vita_uxtb" : "vita_uxth";
            fprintf(f, "    %s = %s(%s);\n", reg_name(in->rd), fn3, reg_name(in->rm));
            break;
        }

        case OP_REV:
            fprintf(f, "    %s = vita_rev(%s);\n", reg_name(in->rd), reg_name(in->rm));
            break;

        case OP_CBZ: case OP_CBNZ:
            if (fb_has_label(b, in->target))
                fprintf(f, "    if (%s %s 0) goto L_%08X;\n", reg_name(in->rn),
                        in->op == OP_CBZ ? "==" : "!=", in->target);
            else
                if (fs_has(fs, in->target)) fprintf(f, "    if (%s %s 0) { vita_func_%08X(); return; }\n", reg_name(in->rn), in->op == OP_CBZ ? "==" : "!=", in->target); else { fprintf(f, "    vita_trap_indirect(0x%08X, 0x%08X);\n", in->addr, in->target); ok = 0; }
            break;

        case OP_B:
            if (fb_has_label(b, in->target)) {
                if (in->cond == ARM_COND_AL) fprintf(f, "    goto L_%08X;\n", in->target);
                else fprintf(f, "    if (vita_cond(%u)) goto L_%08X;\n",
                             in->cond, in->target);
            } else {
                /* A branch out of this function's extent is a tail call. */
                if (in->cond == ARM_COND_AL)
                    if (fs_has(fs, in->target)) fprintf(f, "    vita_func_%08X(); return;\n", in->target); else { fprintf(f, "    vita_trap_indirect(0x%08X, 0x%08X);\n", in->addr, in->target); ok = 0; }
                else
                    if (fs_has(fs, in->target)) fprintf(f, "    if (vita_cond(%u)) { vita_func_%08X(); return; }\n", in->cond, in->target); else { fprintf(f, "    vita_trap_indirect(0x%08X, 0x%08X);\n", in->addr, in->target); ok = 0; }
            }
            break;

        case OP_NOP:
            fprintf(f, "    /* nop */\n");
            break;

        case OP_IT:
            /* The IT instruction itself emits nothing; its effect is that the
             * following instructions carry a condition, which the decoder has
             * already attached to them. */
            fprintf(f, "    /* it %s */\n", arm_cond_name(in->cond));
            break;

        default:
            ok = 0;
            break;
    }

    /* Control-flow classes the operand decoder does not cover are handled by
     * class rather than by op, so a call is still a call even when its exact
     * encoding was not decoded. */
    if (!ok) {
        if (in->cls == A_CALL && in->has_target && fs_has(fs, in->target)) {
            fprintf(f, "    vita_func_%08X();\n", in->target);
            ok = 1;
        } else if (in->cls == A_CALL && in->has_target) {
            fprintf(f, "    vita_trap_indirect(0x%08X, 0x%08X);\n", in->addr, in->target);
        } else if (in->cls == A_RETURN) {
            fprintf(f, "    return;\n");
            ok = 1;
        } else if (in->cls == A_CALL || in->cls == A_INDIRECT) {
            fprintf(f, "    vita_trap_indirect(0x%08X, 0);\n", in->addr);
        } else if (in->cls == A_SIMD) {
            trap(f, in, "simd");
        } else {
            trap(f, in, in->mnemonic);
        }
    }

    if (guarded) fprintf(f, "    }\n");
    return ok;
}

/* --- the whole module -------------------------------------------------------- */

int em_emit(const vm_image *img, const vm_module *mod, const vf_result *disc,
            FILE *f, uint32_t limit, emit_stats *st) {
    memset(st, 0, sizeof(*st));

    uint32_t n_funcs = disc->count;
    if (limit && limit < n_funcs) n_funcs = limit;

    /* Every address that is a defined symbol in this output, sorted for lookup.
     * Under --limit the un-emitted ones still get trapping stubs, so they are
     * genuinely defined and belong in the set. */
    funcset fs;
    fs.n = disc->count;
    fs.v = (uint32_t *)malloc((fs.n ? fs.n : 1) * sizeof(uint32_t));
    if (!fs.v) return 1;
    for (uint32_t i = 0; i < disc->count; i++) fs.v[i] = disc->funcs[i].addr;
    qsort(fs.v, fs.n, sizeof(uint32_t), fs_cmp);

    fprintf(f, "/* Generated by armrecomp. Do not edit.\n");
    fprintf(f, " *\n");
    fprintf(f, " * module: %s\n", mod->info.name);
    fprintf(f, " * %u functions\n", disc->count);
    fprintf(f, " */\n\n");
    fprintf(f, "#include \"vitarecomp/recomp_rt.h\"\n\n");

    /* Forward declarations: the call graph has cycles, so every function must
     * be visible before any body is emitted. */
    for (uint32_t i = 0; i < disc->count; i++)
        fprintf(f, "void vita_func_%08X(void);\n", disc->funcs[i].addr);
    fprintf(f, "\n");

    /* A limited emit still references functions it did not emit, so those get
     * a stub that traps. Without this the output would not link, and a silently
     * missing function is exactly the failure this project refuses. */
    if (n_funcs < disc->count) {
        fprintf(f, "/* Not emitted under --limit; present so the output links. */\n");
        for (uint32_t i = n_funcs; i < disc->count; i++)
            fprintf(f, "void vita_func_%08X(void) { vita_trap_unimpl(0x%08X, 0, \"not emitted\"); }\n",
                    disc->funcs[i].addr, disc->funcs[i].addr);
        fprintf(f, "\n");
    }

    for (uint32_t i = 0; i < n_funcs; i++) {
        const vf_func *fn = &disc->funcs[i];
        fbody b;
        memset(&b, 0, sizeof(b));
        collect(img, fn, &b);

        fprintf(f, "/* ---------------------------------------------------------------\n");
        fprintf(f, " * vita_func_%08X  --  %u instructions, %u bytes%s\n",
                fn->addr, b.n, fn->end - fn->addr,
                fn->from_heuristic ? ", discovered by shape (heuristic)" : "");
        fprintf(f, " * ------------------------------------------------------------- */\n");
        fprintf(f, "void vita_func_%08X(void) {\n", fn->addr);

        for (uint32_t k = 0; k < b.n; k++) {
            const arm_insn *in = &b.v[k];
            if (fb_has_label(&b, in->addr))
                fprintf(f, "L_%08X:\n", in->addr);

            fprintf(f, "    /* %08X  %-16s */\n", in->addr, in->mnemonic);
            if (emit_insn(img, &fs, &b, in, f, st)) st->translated++;
            else                               st->trapped++;
            st->insns++;
        }

        fprintf(f, "}\n\n");
        st->funcs++;

        free(b.v);
        free(b.labels);
    }

    free(fs.v);
    return 0;
}



