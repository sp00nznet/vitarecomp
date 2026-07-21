/* cpu.c — the machine state the generated C operates on. */

#include "vitarecomp/cpu.h"

uint32_t r0, r1, r2, r3, r4, r5, r6, r7;
uint32_t r8, r9, r10, r11, r12;
uint32_t sp, lr;

int flag_n, flag_z, flag_c, flag_v;
