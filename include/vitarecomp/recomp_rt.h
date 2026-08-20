/* recomp_rt.h â€” the instructions whose C translation is not obvious.
 *
 * Everything here exists because a direct C expression would be WRONG, not
 * merely verbose. Each one is a place where ARM's definition and C's differ,
 * and where the difference is invisible until it produces a bad result deep in
 * arithmetic-heavy code.
 */

#ifndef VITARECOMP_RECOMP_RT_H
#define VITARECOMP_RECOMP_RT_H

#include "cpu.h"
#include "mem.h"
#include "vfp.h"

#include <math.h>

#include <stdint.h>

/* --- shifts ----------------------------------------------------------------
 *
 * C leaves a shift by >= the operand width UNDEFINED. ARM defines it: shifting
 * a 32-bit value left by 32 or more yields zero. On x86 the natural C
 * translation silently masks the count to 5 bits, so `x << 32` returns x
 * unchanged â€” the exact opposite of the right answer, and a bug that only
 * appears when a shift amount is computed rather than constant.
 */

static inline uint32_t vita_lsl(uint32_t v, uint32_t n) {
    return n >= 32 ? 0u : v << n;
}

static inline uint32_t vita_lsr(uint32_t v, uint32_t n) {
    return n >= 32 ? 0u : v >> n;
}

/* Arithmetic shift right saturates to the sign bit rather than reaching zero,
 * and C's >> on a signed value is only implementation-defined, so the sign
 * extension is done explicitly. */
static inline uint32_t vita_asr(uint32_t v, uint32_t n) {
    if (n >= 32) return (v & 0x80000000u) ? 0xFFFFFFFFu : 0u;
    if (n == 0)  return v;
    return (uint32_t)(((int32_t)v) >> n) |
           ((v & 0x80000000u) ? ~(0xFFFFFFFFu >> n) : 0u);
}

static inline uint32_t vita_ror(uint32_t v, uint32_t n) {
    n &= 31;
    return n ? ((v >> n) | (v << (32 - n))) : v;
}

/* --- flags -----------------------------------------------------------------
 *
 * N and Z are mechanical. C and V are not, and they are the reason this file
 * exists: carry on an addition is an unsigned overflow, carry on a SUBTRACTION
 * is NOT a borrow but its complement, and overflow is a signed condition that
 * shares no bits with either. Writing these inline at every call site is how a
 * recompiler ends up with subtly different flag behaviour in three places.
 */

static inline void vita_flags_nz(uint32_t res) {
    flag_n = (int)(res >> 31);
    flag_z = (res == 0);
}

static inline void vita_flags_add(uint32_t a, uint32_t b, uint32_t res) {
    vita_flags_nz(res);
    flag_c = (res < a);
    flag_v = (int)(((a ^ res) & (b ^ res)) >> 31);
}

static inline void vita_flags_adc(uint32_t a, uint32_t b, uint32_t carry,
                                  uint32_t res) {
    vita_flags_nz(res);
    /* With a carry in, `res < a` is not sufficient: a + b + 1 can equal a
     * exactly when b is 0xFFFFFFFF, which carries but does not decrease. */
    flag_c = carry ? (res <= a) : (res < a);
    flag_v = (int)(((a ^ res) & (b ^ res)) >> 31);
}

/* ARM's carry on subtraction is set when there is NO borrow â€” the opposite of
 * most people's intuition and of several other architectures. */
static inline void vita_flags_sub(uint32_t a, uint32_t b, uint32_t res) {
    vita_flags_nz(res);
    flag_c = (a >= b);
    flag_v = (int)(((a ^ b) & (a ^ res)) >> 31);
}

/* --- condition codes -------------------------------------------------------
 *
 * Used by conditional branches and by every instruction inside an IT block.
 */

static inline int vita_cond(int cc) {
    switch (cc & 0xF) {
        case 0x0: return  flag_z;                        /* eq */
        case 0x1: return !flag_z;                        /* ne */
        case 0x2: return  flag_c;                        /* cs/hs */
        case 0x3: return !flag_c;                        /* cc/lo */
        case 0x4: return  flag_n;                        /* mi */
        case 0x5: return !flag_n;                        /* pl */
        case 0x6: return  flag_v;                        /* vs */
        case 0x7: return !flag_v;                        /* vc */
        case 0x8: return  flag_c && !flag_z;             /* hi */
        case 0x9: return !flag_c ||  flag_z;             /* ls */
        case 0xA: return  flag_n == flag_v;              /* ge */
        case 0xB: return  flag_n != flag_v;              /* lt */
        case 0xC: return !flag_z && (flag_n == flag_v);  /* gt */
        case 0xD: return  flag_z || (flag_n != flag_v);  /* le */
        default:  return 1;                              /* al */
    }
}

/* --- sign extension --------------------------------------------------------- */

static inline uint32_t vita_sxtb(uint32_t v) { return (uint32_t)(int32_t)(int8_t)(v & 0xFF); }
static inline uint32_t vita_sxth(uint32_t v) { return (uint32_t)(int32_t)(int16_t)(v & 0xFFFF); }
static inline uint32_t vita_uxtb(uint32_t v) { return v & 0xFF; }
static inline uint32_t vita_uxth(uint32_t v) { return v & 0xFFFF; }

static inline uint32_t vita_rev(uint32_t v) {
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8)
         | ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
}

/* --- bitfields ---------------------------------------------------------------
 *
 * The obvious C is wrong in two places. `(1u << width) - 1` is UNDEFINED at
 * width 32, which is a legal UBFX width — and the natural way to write SBFX,
 * a left shift followed by a signed right shift, leans on `>>` sign-extending,
 * which C only implementation-defines. Both produce correct answers on the
 * usual compilers right up until they do not.
 */

static inline uint32_t vita_bf_mask(uint32_t width) {
    return width >= 32 ? 0xFFFFFFFFu : (1u << width) - 1u;
}

static inline uint32_t vita_ubfx(uint32_t v, uint32_t lsb, uint32_t width) {
    return vita_lsr(v, lsb) & vita_bf_mask(width);
}

static inline uint32_t vita_sbfx(uint32_t v, uint32_t lsb, uint32_t width) {
    uint32_t f = vita_lsr(v, lsb) & vita_bf_mask(width);
    if (width == 0 || width >= 32) return f;
    /* Sign is the field's top bit, not the register's. */
    return (f & (1u << (width - 1))) ? (f | ~vita_bf_mask(width)) : f;
}

/* BFI, and BFC with src == 0. The bits outside the field are preserved, which
 * is the whole point — this is the one place a destination register is read
 * before it is written. */
static inline uint32_t vita_bfi(uint32_t dst, uint32_t src,
                                uint32_t lsb, uint32_t width) {
    uint32_t m = vita_lsl(vita_bf_mask(width), lsb);
    return (dst & ~m) | (vita_lsl(src, lsb) & m);
}

/* --- gaps that announce themselves ------------------------------------------
 *
 * Anything not translated calls one of these. A gap that stops the program and
 * names itself is worth far more than one that produces a program which runs
 * and is quietly wrong.
 */

void vita_trap_unimpl(uint32_t addr, uint32_t raw, const char *what);
void vita_trap_indirect(uint32_t addr, uint32_t target);
void vita_trap_import(uint32_t addr, uint32_t nid, const char *name);

/* Total traps hit. Only meaningful under VITARECOMP_TRACE=1, where execution
 * continues past them; otherwise the first one ends the program. */
uint32_t vita_trap_count(void);

#endif /* VITARECOMP_RECOMP_RT_H */

