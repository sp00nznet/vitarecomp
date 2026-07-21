/* cpu.h — the recompiled program's machine state.
 *
 * Registers are globals rather than a struct passed around, for the same
 * reason every recompiler does it: the generated C is millions of lines and
 * `r0` reads better than `cpu->r[0]` a few hundred thousand times over. There
 * is one thread of recompiled control at a time.
 */

#ifndef VITARECOMP_CPU_H
#define VITARECOMP_CPU_H

#include <stdint.h>

/* r0-r12, then the three with architectural meaning. r15 (PC) is deliberately
 * absent: a recompiled program has no program counter, and any instruction
 * that genuinely reads PC has its value resolved at translation time. */
extern uint32_t r0, r1, r2, r3, r4, r5, r6, r7;
extern uint32_t r8, r9, r10, r11, r12;
extern uint32_t sp, lr;

/* NZCV, held as separate ints rather than packed into a CPSR word.
 *
 * ARM leans on these far harder than MIPS does — a comparison and its branch
 * are separate instructions with arbitrary distance between them, and carry
 * feeds ADC/SBC chains. Keeping them unpacked means the compiler can usually
 * fold a flag write into the operation that produced it, and it makes the
 * generated C readable. */
extern int flag_n, flag_z, flag_c, flag_v;

#endif /* VITARECOMP_CPU_H */
