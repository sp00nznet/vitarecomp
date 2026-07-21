/* decode.h — ARMv7-A instruction decoding, both instruction sets.
 *
 * The Vita runs a Cortex-A9. Its code is predominantly Thumb-2 with a real ARM
 * minority, so a decoder that handles only one of them silently misreads the
 * other — and because both are dense encodings, misreading produces plausible
 * instructions rather than obvious garbage.
 *
 * SCOPE. This decoder determines, for every instruction:
 *
 *   - its WIDTH   (2 or 4 bytes) — required to advance correctly at all
 *   - its CLASS   (ALU / load / store / branch / SIMD / ...)
 *   - its CONTROL FLOW (target, conditionality, call vs return vs jump)
 *
 * It names common instructions but does not yet decode every operand; that
 * lands in phase 5 where the emitter needs it. The distinction matters because
 * width and control flow are what phase 4 needs, and getting those right for
 * 100% of instructions is worth more than getting operands right for 60%.
 *
 * Anything not recognised decodes to A_UNKNOWN rather than being skipped or
 * guessed at, so `cover` can report honestly how much of a module is
 * understood.
 */

#ifndef ARMRECOMP_DECODE_H
#define ARMRECOMP_DECODE_H

#include <stdint.h>

typedef enum {
    ARM_A32 = 0,    /* 4-byte ARM instructions          */
    ARM_T32 = 1,    /* 2- or 4-byte Thumb-2             */
} arm_mode;

typedef enum {
    A_UNKNOWN = 0,  /* not recognised — counted, never guessed at   */
    A_UNDEF,        /* a genuinely UNDEFINED encoding                */
    A_ALU,
    A_LOAD,
    A_STORE,
    A_LOADM,        /* LDM / POP                                     */
    A_STOREM,       /* STM / PUSH                                    */
    A_BRANCH,       /* B, conditional or not                         */
    A_CALL,         /* BL / BLX                                      */
    A_RETURN,       /* BX LR, POP {..,pc}, MOV pc,lr                 */
    A_INDIRECT,     /* BX Rm, other computed transfers               */
    A_SIMD,         /* NEON / VFP — identified, not yet translated   */
    A_SYS,          /* SVC, MRS/MSR, barriers, coprocessor           */
    A_NOP,
} arm_class;

typedef struct {
    uint32_t   addr;
    uint32_t   raw;         /* 16-bit instructions occupy the low half */
    uint8_t    width;       /* 2 or 4                                  */
    arm_mode   mode;
    arm_class  cls;
    const char *mnemonic;   /* never NULL; "?" when unknown            */

    /* Control flow, filled in when the class is a branch form. */
    int        has_target;
    uint32_t   target;
    int        conditional;
    int        switches_mode;   /* BLX / BX to the other instruction set */
} arm_insn;

const char *arm_class_name(arm_class c);

/* Decode one instruction at `addr` from `code` (which begins at `code_addr`).
 * Returns the width consumed, or 0 if there is not enough input left.
 *
 * `mode` is the current instruction set. The decoder never guesses it: mode is
 * caller state, changed only by an explicit interworking branch, because there
 * is no reliable way to infer it from a single instruction. */
int arm_decode(const uint8_t *code, uint32_t code_addr, uint32_t code_len,
               uint32_t addr, arm_mode mode, arm_insn *out);

#endif /* ARMRECOMP_DECODE_H */
