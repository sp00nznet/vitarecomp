/* vfp.c — floating-point state and the comparison semantics. */

#include "vitarecomp/vfp.h"
#include "vitarecomp/cpu.h"

vfp_reg vfp_s[32];
int fpscr_n, fpscr_z, fpscr_c, fpscr_v;

/* ARM's four comparison outcomes, written as the architecture defines them
 * rather than derived from C's operators — C has no way to express "unordered"
 * and would silently collapse it into "not equal". */
static void set_flags(int lt, int eq, int unordered) {
    if (unordered) { fpscr_n = 0; fpscr_z = 0; fpscr_c = 1; fpscr_v = 1; return; }
    if (eq)        { fpscr_n = 0; fpscr_z = 1; fpscr_c = 1; fpscr_v = 0; return; }
    if (lt)        { fpscr_n = 1; fpscr_z = 0; fpscr_c = 0; fpscr_v = 0; return; }
    /* greater than */ fpscr_n = 0; fpscr_z = 0; fpscr_c = 1; fpscr_v = 0;
}

void vfp_cmp_f32(float a, float b) {
    /* A NaN compares false against everything including itself, which is what
     * `a != a` detects. */
    int unordered = (a != a) || (b != b);
    set_flags(a < b, a == b, unordered);
}

void vfp_cmp_f64(double a, double b) {
    int unordered = (a != a) || (b != b);
    set_flags(a < b, a == b, unordered);
}

void vfp_mrs_apsr(void) {
    flag_n = fpscr_n;
    flag_z = fpscr_z;
    flag_c = fpscr_c;
    flag_v = fpscr_v;
}
