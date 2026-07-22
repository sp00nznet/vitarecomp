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

/* The specific operation, for instructions the emitter can translate. Anything
 * left as OP_NONE is decoded well enough to advance and classify but not well
 * enough to emit, and becomes a named run-time trap rather than silence. */
typedef enum {
    OP_NONE = 0,
    OP_MOV, OP_MOVT, OP_MVN, OP_ADD, OP_ADC, OP_SUB, OP_SBC, OP_RSB,
    OP_AND, OP_ORR, OP_EOR, OP_BIC,
    OP_CMP, OP_CMN, OP_TST,
    OP_LSL, OP_LSR, OP_ASR, OP_ROR,
    OP_MUL,
    OP_LDR, OP_LDRB, OP_LDRH, OP_LDRSB, OP_LDRSH, OP_LDRD,
    OP_STR, OP_STRB, OP_STRH, OP_STRD,
    OP_PUSH, OP_POP,
    OP_B, OP_BL, OP_BX, OP_BLX,
    OP_ADR,
    OP_SXTB, OP_SXTH, OP_UXTB, OP_UXTH, OP_REV,
    OP_IT, OP_NOP, OP_SVC, OP_CBZ, OP_CBNZ,

    /* Scalar VFP. Not vector work — 82% of this platform's coprocessor traffic
     * is ordinary floating point, and it maps onto C almost one to one. */
    OP_VLDR, OP_VSTR,
    OP_VADD, OP_VSUB, OP_VMUL, OP_VDIV,
    OP_VABS, OP_VNEG, OP_VSQRT,
    OP_VMOV,        /* register to register                        */
    OP_VMOV_TO_C,   /* VFP register -> core register               */
    OP_VMOV_TO_V,   /* core register -> VFP register               */
    OP_VCMP,
    OP_VCVT_F2I, OP_VCVT_I2F,
    OP_VMRS,
} arm_op;

/* Shift types, in the architecture's encoding order. */
typedef enum { SH_LSL = 0, SH_LSR = 1, SH_ASR = 2, SH_ROR = 3 } arm_shift;

#define ARM_COND_AL 0xE
#define ARM_NO_REG  (-1)

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

    /* --- operands (phase 5) ------------------------------------------------ */
    arm_op     op;
    int8_t     rd, rn, rm, rt;  /* ARM_NO_REG when unused                */
    int8_t     rt2;             /* second transfer register: LDRD/STRD    */

    /* VFP register numbers. Single-precision registers are numbered 0-31;
     * double-precision 0-15, aliased onto the same storage. */
    int8_t     vd, vn, vm;
    uint8_t    vfp_dp;          /* 1 = double precision                   */
    uint8_t    vfp_unsigned;    /* VCVT: unsigned integer form            */
    uint32_t   imm;
    uint8_t    has_imm;
    uint8_t    sets_flags;      /* writes NZCV                           */
    uint8_t    shift_type;      /* arm_shift                             */
    uint8_t    shift_amt;
    uint8_t    shift_is_reg;
    uint16_t   reglist;         /* PUSH/POP/LDM/STM                      */
    uint8_t    cond;            /* ARM_COND_AL when unconditional        */
    uint8_t    writeback;
    uint8_t    mem_add;         /* U bit: offset added rather than subtracted */
    uint8_t    it_mask;         /* IT: which of the next 4 are conditional */
} arm_insn;

const char *arm_cond_name(uint8_t cond);

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
