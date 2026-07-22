/* decode.c — ARMv7-A instruction decoding.
 *
 * Two instruction sets sharing one address space. The single most important
 * output here is WIDTH: get it wrong once and every subsequent instruction in
 * the run is decoded from the wrong offset, producing a long stretch of
 * plausible-looking nonsense rather than an obvious failure.
 *
 * Thumb width is determined by the top five bits of the first halfword, which
 * is a rule rather than a table, so it is written as one.
 */

#include "decode.h"

#include <string.h>

const char *arm_class_name(arm_class c) {
    switch (c) {
        case A_UNKNOWN:  return "unknown";
        case A_UNDEF:    return "undefined";
        case A_ALU:      return "alu";
        case A_LOAD:     return "load";
        case A_STORE:    return "store";
        case A_LOADM:    return "loadm";
        case A_STOREM:   return "storem";
        case A_BRANCH:   return "branch";
        case A_CALL:     return "call";
        case A_RETURN:   return "return";
        case A_INDIRECT: return "indirect";
        case A_SIMD:     return "simd";
        case A_SYS:      return "sys";
        case A_NOP:      return "nop";
        default:         return "?";
    }
}

const char *arm_cond_name(uint8_t cond) {
    static const char *n[16] = {
        "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
        "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
    };
    return n[cond & 0xF];
}

static uint32_t sign_extend(uint32_t v, int bits) {
    uint32_t m = 1u << (bits - 1);
    return (v ^ m) - m;
}

static uint16_t rd16le(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void set(arm_insn *o, arm_class c, const char *m) {
    o->cls = c;
    o->mnemonic = m;
}

/* --- Thumb, 16-bit ---------------------------------------------------------- */

/* The 16 data-processing operations of the 010000 group, in encoding order. */
static const arm_op t16_dp[16] = {
    OP_AND, OP_EOR, OP_LSL, OP_LSR, OP_ASR, OP_ADC, OP_SBC, OP_ROR,
    OP_TST, OP_RSB, OP_CMP, OP_CMN, OP_ORR, OP_MUL, OP_BIC, OP_MVN
};

/* The eight register-offset load/store forms, in encoding order. */
static const arm_op t16_ldst_reg[8] = {
    OP_STR, OP_STRH, OP_STRB, OP_LDRSB, OP_LDR, OP_LDRH, OP_LDRB, OP_LDRSH
};

static void decode_t16(uint16_t h, arm_insn *o) {
    o->raw = h;

    /* --- fully decoded operand forms -------------------------------------- */
    /*
     * These are ordered by encoding, and every one sets `op` so the emitter can
     * translate it. Anything falling past them keeps its class but leaves
     * op == OP_NONE and becomes a trap rather than a guess.
     *
     * Flag setting is the detail most easily got wrong here: 16-bit Thumb data
     * processing sets NZCV *implicitly*, with no S bit to read. The exception
     * is inside an IT block, where the same encodings do not. The decoder
     * records the instruction's own behaviour; honouring IT is the emitter's
     * job, because only it knows the surrounding context.
     */

    /* 000 op(2) imm5 rm rd — shift by immediate; op==11 is add/sub register */
    if ((h & 0xE000) == 0x0000 && (h & 0x1800) != 0x1800) {
        static const arm_op sh[3] = { OP_LSL, OP_LSR, OP_ASR };
        o->op = sh[(h >> 11) & 3];
        o->rd = h & 7;
        o->rm = (h >> 3) & 7;
        o->imm = (h >> 6) & 0x1F;
        o->has_imm = 1;
        o->sets_flags = 1;
        set(o, A_ALU, "shift");
        return;
    }

    /* 00011 I op rm/imm3 rn rd */
    if ((h & 0xF800) == 0x1800) {
        o->op = (h & 0x0200) ? OP_SUB : OP_ADD;
        o->rd = h & 7;
        o->rn = (h >> 3) & 7;
        if (h & 0x0400) { o->imm = (h >> 6) & 7; o->has_imm = 1; }
        else            { o->rm  = (h >> 6) & 7; }
        o->sets_flags = 1;
        set(o, A_ALU, "add/sub");
        return;
    }

    /* 001 op(2) rd imm8 */
    if ((h & 0xE000) == 0x2000) {
        static const arm_op ops[4] = { OP_MOV, OP_CMP, OP_ADD, OP_SUB };
        o->op = ops[(h >> 11) & 3];
        o->rd = o->rn = (h >> 8) & 7;
        o->imm = h & 0xFF;
        o->has_imm = 1;
        o->sets_flags = 1;
        set(o, A_ALU, "alu imm8");
        return;
    }

    /* 010000 op(4) rm rd — register data processing */
    if ((h & 0xFC00) == 0x4000) {
        o->op = t16_dp[(h >> 6) & 0xF];
        o->rd = o->rn = h & 7;
        o->rm = (h >> 3) & 7;
        o->sets_flags = 1;
        /* RSB in this group is the "negate" form: rd = 0 - rm. */
        if (o->op == OP_RSB) { o->imm = 0; o->has_imm = 1; o->rn = o->rm; }
        set(o, A_ALU, "alu reg");
        return;
    }

    /* 01000111 L Rm — interworking branches. These are the only 16-bit
     * instructions that can change instruction set, so they are handled before
     * the general data-processing case that would otherwise swallow them.
     *
     * The mask is 0xFF00, NOT 0xFF80: bit 7 is the L bit that distinguishes BX
     * from BLX, so masking it out excludes every BLX from this case. It then
     * falls through to "add/cmp/mov hi" and decodes as an ALU operation —
     * which means every indirect *call* becomes invisible, and phase 4 would
     * silently never discover the functions reached through them. */
    if ((h & 0xFF00) == 0x4700) {
        int rm = (h >> 3) & 0xF;
        if (h & 0x0080) {
            set(o, A_CALL, "blx");
            o->switches_mode = 1;
        } else if (rm == 14) {
            set(o, A_RETURN, "bx lr");
        } else {
            set(o, A_INDIRECT, "bx");
            o->switches_mode = 1;
        }
        o->op = (h & 0x0080) ? OP_BLX : OP_BX;
        o->rm = rm;
        return;
    }

    /* 010001 op(2) DN rm(4) rd(3) — high-register forms. These do NOT set
     * flags, unlike almost everything else in 16-bit Thumb; CMP is the sole
     * exception because comparing is all it does. */
    if ((h & 0xFC00) == 0x4400) {
        static const arm_op ops[3] = { OP_ADD, OP_CMP, OP_MOV };
        int which = (h >> 8) & 3;
        if (which < 3) {
            int rd = ((h >> 4) & 8) | (h & 7);
            int rm = (h >> 3) & 0xF;

            /* Writing r15 is a BRANCH, not a register write. `MOV pc, rN` is
             * an indirect jump and `ADD pc, rN` a computed one; treating either
             * as arithmetic emits an assignment where control flow belongs, and
             * the recompiled function then runs straight on past a jump it
             * should have taken. `MOV pc, lr` is the plain return form. */
            if (rd == 15 && which != 1 /* CMP never writes rd */) {
                o->rm = rm;
                if (which == 2 && rm == 14) { o->op = OP_BX; set(o, A_RETURN, "mov pc,lr"); }
                else                        { o->op = OP_BX; set(o, A_INDIRECT, "mov/add pc"); }
                return;
            }

            o->op = ops[which];
            o->rd = o->rn = (int8_t)rd;
            o->rm = (int8_t)rm;
            o->sets_flags = (o->op == OP_CMP);
            set(o, A_ALU, "add/cmp/mov hi");
            return;
        }
    }

    /* 01001 rt imm8 — LDR from the literal pool. The address is PC-relative
     * with PC aligned down to a word boundary, which is why the emitter can
     * resolve these to a constant at translation time. */
    if ((h & 0xF800) == 0x4800) {
        o->op = OP_LDR;
        o->rt = (h >> 8) & 7;
        o->rn = 15;
        o->imm = (uint32_t)(h & 0xFF) * 4;
        o->has_imm = 1;
        o->mem_add = 1;
        set(o, A_LOAD, "ldr literal");
        return;
    }

    /* 0101 op(3) rm rn rt — register-offset load/store */
    if ((h & 0xF000) == 0x5000) {
        o->op = t16_ldst_reg[(h >> 9) & 7];
        o->rt = h & 7;
        o->rn = (h >> 3) & 7;
        o->rm = (h >> 6) & 7;
        o->mem_add = 1;
        set(o, (o->op >= OP_STR) ? A_STORE : A_LOAD, "ldr/str reg");
        return;
    }

    /* 011 B L imm5 rn rt — word/byte immediate. The immediate is scaled by the
     * access size, so a byte form is NOT the word form with a smaller range. */
    if ((h & 0xE000) == 0x6000) {
        int byte = (h & 0x1000) != 0;
        int load = (h & 0x0800) != 0;
        o->op = byte ? (load ? OP_LDRB : OP_STRB) : (load ? OP_LDR : OP_STR);
        o->rt = h & 7;
        o->rn = (h >> 3) & 7;
        o->imm = (uint32_t)((h >> 6) & 0x1F) * (byte ? 1u : 4u);
        o->has_imm = 1;
        o->mem_add = 1;
        set(o, load ? A_LOAD : A_STORE, "ldr/str imm");
        return;
    }

    /* 1000 L imm5 rn rt — halfword, scaled by 2 */
    if ((h & 0xF000) == 0x8000) {
        int load = (h & 0x0800) != 0;
        o->op = load ? OP_LDRH : OP_STRH;
        o->rt = h & 7;
        o->rn = (h >> 3) & 7;
        o->imm = (uint32_t)((h >> 6) & 0x1F) * 2u;
        o->has_imm = 1;
        o->mem_add = 1;
        set(o, load ? A_LOAD : A_STORE, "ldrh/strh");
        return;
    }

    /* 1001 L rt imm8 — SP-relative, scaled by 4 */
    if ((h & 0xF000) == 0x9000) {
        int load = (h & 0x0800) != 0;
        o->op = load ? OP_LDR : OP_STR;
        o->rt = (h >> 8) & 7;
        o->rn = 13;
        o->imm = (uint32_t)(h & 0xFF) * 4u;
        o->has_imm = 1;
        o->mem_add = 1;
        set(o, load ? A_LOAD : A_STORE, "ldr/str sp");
        return;
    }

    /* 1010 SP rd imm8 — ADR, or ADD rd, sp, #imm */
    if ((h & 0xF000) == 0xA000) {
        o->rd = (h >> 8) & 7;
        o->imm = (uint32_t)(h & 0xFF) * 4u;
        o->has_imm = 1;
        if (h & 0x0800) { o->op = OP_ADD; o->rn = 13; set(o, A_ALU, "add sp"); }
        else            { o->op = OP_ADR; o->rn = 15; set(o, A_ALU, "adr"); }
        return;
    }

    /* 1100 L rn rlist — LDM / STM */
    if ((h & 0xF000) == 0xC000) {
        int load = (h & 0x0800) != 0;
        o->rn = (h >> 8) & 7;
        o->reglist = h & 0xFF;
        o->writeback = 1;
        set(o, load ? A_LOADM : A_STOREM, "ldm/stm");
        return;
    }

    switch (h >> 12) {
        case 0x0: case 0x1:                     /* shift / add / sub          */
        case 0x2: case 0x3:                     /* mov / cmp / add / sub imm  */
            set(o, A_ALU, "alu");
            return;

        case 0x4:
            if ((h & 0xFC00) == 0x4000) { set(o, A_ALU, "alu"); return; }
            if ((h & 0xFC00) == 0x4400) { set(o, A_ALU, "add/cmp/mov hi"); return; }
            set(o, A_LOAD, "ldr literal");      /* 01001 — LDR Rt,[pc,#imm]   */
            return;

        case 0x5:                               /* load/store register offset */
            set(o, (h & 0x0800) ? A_LOAD : A_STORE, "ldr/str reg");
            return;

        case 0x6: case 0x7: case 0x8: case 0x9: /* load/store immediate       */
            set(o, (h & 0x0800) ? A_LOAD : A_STORE, "ldr/str imm");
            return;

        case 0xA:                               /* adr / add sp               */
            set(o, A_ALU, "adr/add sp");
            return;

        case 0xB:                               /* miscellaneous              */
            if ((h & 0xFF00) == 0xBF00) {
                /* IT and hints share this space. IT is the one that matters:
                 * it makes up to the next four instructions conditional, which
                 * the emitter has to honour. It is identified here so that it
                 * is never silently treated as a NOP. */
                if (h & 0x000F) {
                    o->op = OP_IT;
                    o->cond = (h >> 4) & 0xF;
                    o->it_mask = h & 0xF;
                    set(o, A_SYS, "it");
                } else {
                    o->op = OP_NOP;
                    set(o, A_NOP, "nop");
                }
                return;
            }
            if ((h & 0xFF00) == 0xB000) {       /* ADD/SUB SP, #imm7*4        */
                o->op = (h & 0x0080) ? OP_SUB : OP_ADD;
                o->rd = o->rn = 13;
                o->imm = (uint32_t)(h & 0x7F) * 4u;
                o->has_imm = 1;
                set(o, A_ALU, "add/sub sp");
                return;
            }
            if ((h & 0xFF00) == 0xB200) {       /* SXTH/SXTB/UXTH/UXTB        */
                static const arm_op ex[4] = { OP_SXTH, OP_SXTB, OP_UXTH, OP_UXTB };
                o->op = ex[(h >> 6) & 3];
                o->rd = h & 7;
                o->rm = (h >> 3) & 7;
                set(o, A_ALU, "extend");
                return;
            }
            if ((h & 0xFF00) == 0xBA00 && ((h >> 6) & 3) != 1) {
                o->op = OP_REV;
                o->rd = h & 7;
                o->rm = (h >> 3) & 7;
                set(o, A_ALU, "rev");
                return;
            }
            if ((h & 0xF600) == 0xB400) {
                int load = (h & 0x0800) != 0;
                /* Bit 8 is the extra register: LR for PUSH, PC for POP. A POP
                 * that restores PC is a return, and must not also be emitted as
                 * an ordinary register load. */
                o->reglist = h & 0xFF;
                o->op = load ? OP_POP : OP_PUSH;
                if (load && (h & 0x0100)) {
                    o->reglist |= 0x8000;       /* PC */
                    set(o, A_RETURN, "pop {..,pc}");
                    return;
                }
                if (!load && (h & 0x0100)) o->reglist |= 0x4000;  /* LR */
                set(o, load ? A_LOADM : A_STOREM, load ? "pop" : "push");
                return;
            }
            if ((h & 0xF500) == 0xB100) {       /* CBZ / CBNZ                 */
                o->op = (h & 0x0800) ? OP_CBNZ : OP_CBZ;
                o->rn = h & 7;
                o->conditional = 1;
                o->has_target = 1;
                o->target = o->addr + 4
                          + ((((uint32_t)(h >> 9) & 1) << 6)
                          |  (((uint32_t)(h >> 3) & 0x1F) << 1));
                set(o, A_BRANCH, "cbz/cbnz");
                return;
            }
            set(o, A_ALU, "misc");
            return;

        case 0xC:                               /* stm / ldm                  */
            set(o, (h & 0x0800) ? A_LOADM : A_STOREM, "ldm/stm");
            return;

        case 0xD: {                             /* conditional branch, svc    */
            int cond = (h >> 8) & 0xF;
            if (cond == 0xF) { o->op = OP_SVC; set(o, A_SYS, "svc"); return; }
            if (cond == 0xE) { set(o, A_UNDEF, "udf"); return; }
            o->op = OP_B;
            o->cond = (uint8_t)cond;
            set(o, A_BRANCH, "b<cond>");
            o->conditional = 1;
            o->has_target = 1;
            o->target = o->addr + 4 + sign_extend(h & 0xFF, 8) * 2;
            return;
        }

        case 0xE:                               /* unconditional branch       */
            o->op = OP_B;
            o->cond = ARM_COND_AL;
            set(o, A_BRANCH, "b");
            o->has_target = 1;
            o->target = o->addr + 4 + sign_extend(h & 0x7FF, 11) * 2;
            return;

        default:
            set(o, A_UNKNOWN, "?");
            return;
    }
}

/* --- scalar VFP ------------------------------------------------------------- */
/*
 * The coprocessor space holds both Advanced SIMD and scalar VFP, and on this
 * platform the split is roughly 18/82 in favour of the scalar side. This
 * function claims the scalar part; anything it does not recognise falls back to
 * being reported as SIMD, so the boundary stays honest rather than optimistic.
 *
 * Register numbering is the fiddly part, and it is fiddly in opposite
 * directions for the two precisions. A single-precision register puts its LOW
 * bit in the separate D/N/M flag and its high four bits in the main field; a
 * double-precision register does the reverse. Getting it backwards yields a
 * valid register number that is simply the wrong one — no error, just a program
 * that reads floats it never wrote.
 */

static int vfp_sreg(int field, int extra) { return (field << 1) | extra; }
static int vfp_dreg(int field, int extra) { return (extra << 4) | field; }

static int decode_vfp(uint16_t h1, uint16_t h2, arm_insn *o) {
    int coproc = (h2 >> 8) & 0xF;
    int dp     = (coproc == 11);
    if (coproc != 10 && coproc != 11) return 0;   /* not scalar VFP */

    o->vfp_dp = (uint8_t)dp;

    /* --- extension register load/store: VLDR / VSTR ----------------------- */
    if ((h1 & 0xFE00) == 0xEC00) {
        int P = (h1 >> 8) & 1, U = (h1 >> 7) & 1;
        int D = (h1 >> 6) & 1, W = (h1 >> 5) & 1, L = (h1 >> 4) & 1;
        int vd = (h2 >> 12) & 0xF;

        /* P=1, W=0 is the plain offset form. The writeback and multiple-
         * register forms (VLDM/VSTM/VPUSH/VPOP) share this encoding and are
         * left alone rather than approximated. */
        if (!P || W) return 0;

        o->op  = L ? OP_VLDR : OP_VSTR;
        o->rn  = h1 & 0xF;
        o->vd  = (int8_t)(dp ? vfp_dreg(vd, D) : vfp_sreg(vd, D));
        o->imm = (uint32_t)(h2 & 0xFF) * 4u;
        o->has_imm = 1;
        o->mem_add = (uint8_t)U;
        set(o, L ? A_LOAD : A_STORE, L ? "vldr" : "vstr");
        return 1;
    }

    if ((h1 & 0xEF00) != 0xEE00) return 0;        /* not VFP data processing */

    int D  = (h1 >> 6) & 1;
    int vn = h1 & 0xF;
    int vd = (h2 >> 12) & 0xF;
    int N  = (h2 >> 7) & 1;
    int M  = (h2 >> 5) & 1;
    int vm = h2 & 0xF;
    int op = (h2 >> 6) & 1;
    int opc1 = (h1 >> 4) & 0xB;                   /* bits 7, 5:4 */

    o->vd = (int8_t)(dp ? vfp_dreg(vd, D) : vfp_sreg(vd, D));
    o->vn = (int8_t)(dp ? vfp_dreg(vn, N) : vfp_sreg(vn, N));
    o->vm = (int8_t)(dp ? vfp_dreg(vm, M) : vfp_sreg(vm, M));

    /* --- VMRS: the float flags to the integer ones ------------------------ */
    if ((h1 & 0xFFF0) == 0xEEF0 && (h2 & 0x0F10) == 0x0A10) {
        o->op = OP_VMRS;
        o->rt = (h2 >> 12) & 0xF;
        set(o, A_SYS, "vmrs");
        return 1;
    }

    /* --- VMOV between a core register and a single-precision register ----- */
    if ((h1 & 0xFFE0) == 0xEE00 && (h2 & 0x0F7F) == 0x0A10) {
        int to_vfp = ((h1 >> 4) & 1) == 0;
        o->op = to_vfp ? OP_VMOV_TO_V : OP_VMOV_TO_C;
        o->rt = (h2 >> 12) & 0xF;
        o->vn = (int8_t)vfp_sreg(vn, N);          /* always single here */
        o->vfp_dp = 0;
        set(o, A_ALU, to_vfp ? "vmov s,r" : "vmov r,s");
        return 1;
    }

    switch (opc1) {
        case 0x0:                                  /* VMLA / VMLS: accumulate */
            return 0;                              /* not approximated        */

        case 0x2:
            o->op = OP_VMUL;
            set(o, A_ALU, "vmul");
            return 1;

        case 0x3:
            o->op = op ? OP_VSUB : OP_VADD;
            set(o, A_ALU, op ? "vsub" : "vadd");
            return 1;

        case 0x8:
            o->op = OP_VDIV;
            set(o, A_ALU, "vdiv");
            return 1;

        case 0xB: {                                /* the "other" group       */
            int opc2 = h1 & 0xF;
            int opc3 = (h2 >> 6) & 3;

            if (opc2 == 0x0 && opc3 == 1) { o->op = OP_VMOV;  set(o, A_ALU, "vmov"); return 1; }
            if (opc2 == 0x0 && opc3 == 3) { o->op = OP_VABS;  set(o, A_ALU, "vabs"); return 1; }
            if (opc2 == 0x1 && opc3 == 1) { o->op = OP_VNEG;  set(o, A_ALU, "vneg"); return 1; }
            if (opc2 == 0x1 && opc3 == 3) { o->op = OP_VSQRT; set(o, A_ALU, "vsqrt"); return 1; }

            /* VCMP and VCMPE. The E form differs only in whether a quiet NaN
             * raises an exception, which this runtime does not model. */
            if ((opc2 == 0x4 || opc2 == 0x5) && (opc3 & 1)) {
                o->op = OP_VCMP;
                /* opc2 == 5 compares against zero rather than a register. */
                if (opc2 == 0x5) { o->vm = ARM_NO_REG; o->has_imm = 1; o->imm = 0; }
                set(o, A_ALU, "vcmp");
                return 1;
            }

            /* Integer to float: opc2 1000, with the source signedness in the
             * op bit rather than a separate field. */
            if (opc2 == 0x8 && (opc3 & 1)) {
                o->op = OP_VCVT_I2F;
                o->vfp_unsigned = (uint8_t)(op == 0);
                set(o, A_ALU, "vcvt f,i");
                return 1;
            }

            /* Float to integer: opc2 110x (round to nearest) or 111x (toward
             * zero). Only the toward-zero forms are claimed, because that is
             * what C's conversion does and the other rounding modes would need
             * explicit modelling to be right. */
            if ((opc2 & 0xE) == 0xC && (opc3 & 1)) {
                o->op = OP_VCVT_F2I;
                o->vfp_unsigned = (uint8_t)((opc2 & 1) == 0);
                set(o, A_ALU, "vcvt i,f");
                return 1;
            }
            return 0;
        }

        default:
            return 0;
    }
}

/* --- Thumb, 32-bit ---------------------------------------------------------- */

/* ThumbExpandImm — the 12-bit field that encodes a 32-bit constant.
 *
 * Two entirely different encodings share the field, selected by its top two
 * bits. With them clear, the low byte is replicated into a pattern (once,
 * halfword-spaced, byte-spaced, or all four); otherwise the field is a
 * rotate-right of a value whose top bit is implicit and always set.
 *
 * Reading it as a plain 12-bit integer is the obvious mistake, and it is quiet:
 * small constants happen to be in the first case with pattern 00, where the
 * naive reading is correct. Everything above 0xFF is then wrong. */
static uint32_t thumb_expand_imm(uint32_t imm12) {
    if ((imm12 & 0xC00) == 0) {
        uint32_t b = imm12 & 0xFF;
        switch ((imm12 >> 8) & 3) {
            case 0:  return b;
            case 1:  return (b << 16) | b;
            case 2:  return (b << 24) | (b << 8);
            default: return (b << 24) | (b << 16) | (b << 8) | b;
        }
    }
    /* The 8-bit value always has bit 7 set implicitly, so only 7 bits are
     * stored. Forgetting that leaves every rotated constant short by 0x80. */
    uint32_t v = 0x80u | (imm12 & 0x7F);
    uint32_t r = (imm12 >> 7) & 0x1F;
    return r ? ((v >> r) | (v << (32 - r))) : v;
}

static void decode_t32(uint16_t h1, uint16_t h2, arm_insn *o) {
    o->raw = ((uint32_t)h1 << 16) | h2;

    /* Advanced SIMD and VFP occupy the coprocessor space: bits 15:13 are 111
     * and bits 11:10 are 11, which is exactly `(h1 & 0xEC00) == 0xEC00`.
     *
     * An earlier mask of `(h1 & 0xEE00) == 0xEC00` matched only 0xEC and 0xED,
     * missing the whole of 0xEE and 0xEF — which is where VFP's CDP/MCR/MRC
     * forms live, and they are the bulk of it. Those ~2,800 instructions were
     * reported as UNKNOWN rather than SIMD, so every earlier SIMD percentage
     * this toolkit printed was an undercount and every "unknown" figure was
     * correspondingly inflated.
     *
     * Worth noting that this made the tool look better than it was on one axis
     * and worse on another, which is why the trap breakdown by kind was what
     * finally surfaced it: 2.16% of instructions decoding to "?" is a number
     * that demands an explanation, and there wasn't one. */
    if ((h1 & 0xEC00) == 0xEC00) {
        if (decode_vfp(h1, h2, o)) return;
        set(o, A_SIMD, "simd/vfp");
        return;
    }

    /* 11110 ... with bit 15 of the second halfword set: branches and
     * miscellaneous control. */
    if ((h1 & 0xF800) == 0xF000 && (h2 & 0x8000)) {
        int op1 = (h2 >> 12) & 0x7;             /* bits 14:12 of h2 */

        if ((op1 & 0x5) == 0x5) {               /* x1x1 -> BL / BLX imm */
            set(o, A_CALL, (h2 & 0x1000) ? "bl" : "blx");
            if (!(h2 & 0x1000)) o->switches_mode = 1;

            /* The J1/J2 encoding: the two J bits are stored XORed with the sign
             * bit, so they must be un-XORed before assembling the offset.
             * Treating them as plain address bits gives a target that is right
             * for short branches and wrong for long ones. */
            uint32_t s   = (h1 >> 10) & 1;
            uint32_t j1  = (h2 >> 13) & 1;
            uint32_t j2  = (h2 >> 11) & 1;
            uint32_t i1  = !(j1 ^ s);
            uint32_t i2  = !(j2 ^ s);
            uint32_t imm = (s << 24) | (i1 << 23) | (i2 << 22)
                         | ((uint32_t)(h1 & 0x03FF) << 12)
                         | ((uint32_t)(h2 & 0x07FF) << 1);
            o->has_target = 1;
            o->target = o->addr + 4 + sign_extend(imm, 25);
            return;
        }

        if ((op1 & 0x5) == 0x4) {               /* x10x -> B.W unconditional */
            /* `op` matters as much as the class. The class routes the emitter's
             * fallback, but only `op` reaches the switch that actually
             * translates a branch — leaving it OP_NONE meant every wide branch
             * decoded perfectly, computed its target correctly, and then
             * trapped anyway. 2,359 instructions, purely for want of this
             * line. */
            o->op = OP_B;
            o->cond = ARM_COND_AL;
            set(o, A_BRANCH, "b.w");
            uint32_t s   = (h1 >> 10) & 1;
            uint32_t j1  = (h2 >> 13) & 1;
            uint32_t j2  = (h2 >> 11) & 1;
            uint32_t i1  = !(j1 ^ s);
            uint32_t i2  = !(j2 ^ s);
            uint32_t imm = (s << 24) | (i1 << 23) | (i2 << 22)
                         | ((uint32_t)(h1 & 0x03FF) << 12)
                         | ((uint32_t)(h2 & 0x07FF) << 1);
            o->has_target = 1;
            o->target = o->addr + 4 + sign_extend(imm, 25);
            return;
        }

        /* x0x -> conditional B.W, or a system instruction when the condition
         * field is 111x. */
        if (((h1 >> 7) & 0xE) == 0xE) { set(o, A_SYS, "sys"); return; }
        o->op = OP_B;
        o->cond = (uint8_t)((h1 >> 6) & 0xF);
        set(o, A_BRANCH, "b<cond>.w");
        o->conditional = 1;
        {
            uint32_t s    = (h1 >> 10) & 1;
            uint32_t j1   = (h2 >> 13) & 1;
            uint32_t j2   = (h2 >> 11) & 1;
            uint32_t imm  = (s << 20) | (j2 << 19) | (j1 << 18)
                          | ((uint32_t)(h1 & 0x003F) << 12)
                          | ((uint32_t)(h2 & 0x07FF) << 1);
            o->has_target = 1;
            o->target = o->addr + 4 + sign_extend(imm, 21);
        }
        return;
    }

    /* Load/store DUAL. Bit 6 separates these from the multiple forms below, and
     * the earlier mask excluded them by keeping that bit — so every LDRD/STRD
     * fell through to unknown. They are common: compilers use them to move
     * 64-bit values and adjacent struct fields in one instruction. */
    if ((h1 & 0xFE40) == 0xE840 && (h1 & 0x0120) != 0x0000) {
        int load = (h1 & 0x0010) != 0;
        o->op  = load ? OP_LDRD : OP_STRD;
        o->rn  = h1 & 0xF;
        o->rt  = (h2 >> 12) & 0xF;
        o->rt2 = (h2 >> 8) & 0xF;
        o->imm = (uint32_t)(h2 & 0xFF) * 4u;   /* scaled by 4 */
        o->has_imm = 1;
        o->mem_add = (h1 & 0x0080) != 0;       /* U bit */
        set(o, load ? A_LOAD : A_STORE, load ? "ldrd" : "strd");
        return;
    }

    /* Load/store multiple. LDM with the PC in the list is a return. */
    if ((h1 & 0xFE40) == 0xE800) {
        int load = (h1 & 0x0010) != 0;
        if (load && (h2 & 0x8000)) { set(o, A_RETURN, "ldm {..,pc}"); return; }
        o->op = load ? OP_POP : OP_PUSH;
        o->rn = h1 & 0xF;
        o->reglist = h2;
        o->writeback = (h1 & 0x0020) != 0;
        /* Only the SP-relative writeback forms are PUSH/POP proper; the rest
         * are general LDM/STM against an arbitrary base and the emitter's
         * stack-shaped translation would be wrong for them. */
        if (o->rn != 13) o->op = OP_NONE;
        set(o, load ? A_LOADM : A_STOREM, "ldm/stm.w");
        return;
    }

    /* --- data processing -------------------------------------------------- */
    /*
     * The shifted-register (0xEA/0xEB) and modified-immediate (0xF0/0xF1)
     * groups share an operation field, an S bit, and the rn/rd placement, so
     * they are decoded together and differ only in how operand 2 is formed.
     *
     * Four operations change identity when a register field is r15, and the
     * architecture uses that rather than spending encoding space:
     *   rn == 15 turns ORR into MOV and ORN into MVN
     *   rd == 15 with S set turns AND/EOR/ADD/SUB into TST/TEQ/CMN/CMP
     * Missing either produces an instruction that reads a register which is not
     * an operand, and writes one that is not a destination.
     */
    if ((h1 & 0xFE00) == 0xEA00 || (h1 & 0xFA00) == 0xF000) {
        /* Which of the two groups matched — NOT a single bit. Both 0xEA/0xEB
         * and 0xF0/0xF1 have bit 15 set, so testing it classifies every
         * shifted-register instruction as an immediate one and then reads
         * operand 2 out of the wrong fields. */
        int is_imm = (h1 & 0xFA00) == 0xF000;
        if (is_imm && (h2 & 0x8000)) { set(o, A_UNKNOWN, "?"); return; }

        static const arm_op dp[16] = {
            OP_AND, OP_BIC, OP_ORR, OP_MVN, OP_EOR, OP_NONE, OP_NONE, OP_NONE,
            OP_ADD, OP_NONE, OP_ADC, OP_SBC, OP_NONE, OP_SUB, OP_RSB, OP_NONE
        };
        int opf = (h1 >> 5) & 0xF;
        o->op = dp[opf];
        if (o->op == OP_NONE) { set(o, A_ALU, "alu.w"); return; }

        o->rn = h1 & 0xF;
        o->rd = (h2 >> 8) & 0xF;
        o->sets_flags = (h1 & 0x0010) != 0;

        if (o->rn == 15) {
            if (opf == 0x2) o->op = OP_MOV;       /* orr rn=15 -> mov */
            if (opf == 0x3) o->op = OP_MVN;       /* orn rn=15 -> mvn */
            o->rn = ARM_NO_REG;
        }
        if (o->rd == 15 && o->sets_flags) {
            /* Compare forms: the result is discarded, only flags matter. */
            if (opf == 0x0) o->op = OP_TST;
            if (opf == 0x4) o->op = OP_TST;       /* teq: same shape for us */
            if (opf == 0x8) o->op = OP_CMN;
            if (opf == 0xD) o->op = OP_CMP;
            o->rd = ARM_NO_REG;
        }

        if (is_imm) {
            uint32_t imm12 = (uint32_t)(((h1 >> 10) & 1) << 11)
                           | (uint32_t)(((h2 >> 12) & 7) << 8)
                           | (uint32_t)(h2 & 0xFF);
            o->imm = thumb_expand_imm(imm12);
            o->has_imm = 1;
        } else {
            o->rm = h2 & 0xF;
            o->shift_type = (h2 >> 4) & 3;
            o->shift_amt  = (uint8_t)((((h2 >> 12) & 7) << 2) | ((h2 >> 6) & 3));
        }
        set(o, A_ALU, "alu.w");
        return;
    }

    /* Plain binary immediate: MOVW/MOVT and the wide add/sub. These carry a
     * 16-bit literal rather than a modified immediate, and are how compilers
     * build addresses — so they are worth decoding even though they are only
     * two encodings. */
    /* The group is selected by bit 9, which is what separates plain binary
     * immediates from the modified immediates above. Masking any lower bit
     * excludes members of the group: an earlier mask of 0xFB40 kept bit 6,
     * which MOVW sets, so MOVW never matched at all. */
    if ((h1 & 0xFA00) == 0xF200 && !(h2 & 0x8000)) {
        uint32_t imm = (uint32_t)(((h1 >> 10) & 1) << 11)
                     | (uint32_t)(((h2 >> 12) & 7) << 8)
                     | (uint32_t)(h2 & 0xFF);
        o->rd = (h2 >> 8) & 0xF;
        o->has_imm = 1;

        uint16_t form = h1 & 0xFBF0;
        if (form == 0xF240) {                     /* movw: a 16-bit literal   */
            o->op = OP_MOV;
            o->imm = imm | ((uint32_t)(h1 & 0xF) << 12);
            set(o, A_ALU, "movw");
            return;
        }
        if (form == 0xF2C0) {                     /* movt                     */
            /* MOVT writes the top half and preserves the bottom, which is not
             * a move — but it IS trivially expressible, and it is load-bearing:
             * MOVW/MOVT is how ARM builds a 32-bit address, so leaving it
             * untranslated costs every constructed pointer its high 16 bits.
             * A trace of module_start showed the result — indirect branches to
             * 0x00000000 — which is what promoted this from "deliberately
             * trapped" to "the highest-value instruction remaining". */
            o->op = OP_MOVT;
            o->imm = imm | ((uint32_t)(h1 & 0xF) << 12);
            set(o, A_ALU, "movt");
            return;
        }
        if (form == 0xF200 || form == 0xF2A0) {   /* addw / subw              */
            o->op = (form == 0xF2A0) ? OP_SUB : OP_ADD;
            o->rn = h1 & 0xF;
            o->imm = imm;
            set(o, A_ALU, "addw/subw");
            return;
        }
        set(o, A_ALU, "bitfield");                /* SBFX/UBFX/BFI and friends */
        return;
    }

    /* Single load/store, immediate and register offset. A load into the PC is
     * a return. */
    if ((h1 & 0xFE00) == 0xF800) {
        int load = (h1 & 0x0010) != 0;
        if (load && ((h2 >> 12) & 0xF) == 0xF) { set(o, A_RETURN, "ldr pc"); return; }

        int size = (h1 >> 5) & 3;                 /* 0 byte, 1 half, 2 word */
        int sign = (h1 & 0x0100) != 0;
        o->rt = (h2 >> 12) & 0xF;
        o->rn = h1 & 0xF;
        o->mem_add = 1;

        if (load) o->op = size == 0 ? (sign ? OP_LDRSB : OP_LDRB)
                        : size == 1 ? (sign ? OP_LDRSH : OP_LDRH) : OP_LDR;
        else      o->op = size == 0 ? OP_STRB : size == 1 ? OP_STRH : OP_STR;

        if (h1 & 0x0080) {                        /* 12-bit unsigned offset */
            o->imm = h2 & 0xFFF;
            o->has_imm = 1;
        } else if ((h2 & 0x0F00) == 0x0C00) {     /* 8-bit, negative */
            o->imm = h2 & 0xFF;
            o->has_imm = 1;
            o->mem_add = 0;
        } else if ((h2 & 0x0FC0) == 0x0000) {     /* register offset */
            o->rm = h2 & 0xF;
            o->shift_amt = (uint8_t)((h2 >> 4) & 3);
        } else {
            o->imm = h2 & 0xFF;
            o->has_imm = 1;
        }
        set(o, load ? A_LOAD : A_STORE, "ldr/str.w");
        return;
    }

    /* The wide sign/zero extends: rn == 15 distinguishes them from the
     * extend-and-add forms that share the encoding. */
    if ((h1 & 0xFF80) == 0xFA00 && (h1 & 0x000F) == 0x000F &&
        (h2 & 0xF080) == 0xF080) {
        static const arm_op ex[4] = { OP_SXTH, OP_UXTH, OP_SXTB, OP_UXTB };
        o->op = ex[(h1 >> 4) & 3];
        o->rd = (h2 >> 8) & 0xF;
        o->rm = h2 & 0xF;
        set(o, A_ALU, "extend.w");
        return;
    }

    /* Table branch: a jump table in one instruction, indexing a byte or
     * halfword array to compute a forward branch. It is a computed transfer
     * that discovery cannot follow, and is named here rather than left unknown
     * so its cost is visible. */
    if ((h1 & 0xFFF0) == 0xE8D0 && (h2 & 0xFFE0) == 0xF000) {
        o->rn = h1 & 0xF;
        o->rm = h2 & 0xF;
        set(o, A_INDIRECT, "tbb/tbh");
        return;
    }

    /* Shift by register. */
    if ((h1 & 0xFF80) == 0xFA00 && (h2 & 0xF0F0) == 0xF000) {
        static const arm_op sh[4] = { OP_LSL, OP_LSR, OP_ASR, OP_ROR };
        o->op = sh[(h1 >> 5) & 3];
        o->rd = (h2 >> 8) & 0xF;
        o->rn = h1 & 0xF;
        o->rm = h2 & 0xF;
        o->sets_flags = (h1 & 0x0010) != 0;
        set(o, A_ALU, "shift reg.w");
        return;
    }

    /* Multiply. MLA/MLS have a third operand and are left to a trap rather
     * than translated as a plain multiply, which would silently drop the
     * accumulate. */
    if ((h1 & 0xFFF0) == 0xFB00 && (h2 & 0x00F0) == 0x0000) {
        if (((h2 >> 12) & 0xF) == 0xF) {          /* ra == 15 -> plain MUL */
            o->op = OP_MUL;
            o->rd = (h2 >> 8) & 0xF;
            o->rn = h1 & 0xF;
            o->rm = h2 & 0xF;
            set(o, A_ALU, "mul.w");
            return;
        }
        set(o, A_ALU, "mla/mls");
        return;
    }

    set(o, A_UNKNOWN, "?");
}

/* --- ARM -------------------------------------------------------------------- */

static void decode_a32(uint32_t w, arm_insn *o) {
    o->raw = w;

    uint32_t cond = w >> 28;
    uint32_t op   = (w >> 25) & 0x7;

    if (cond != 0xF && cond != 0xE) o->conditional = 1;

    /* The unconditional encoding space (cond == 1111) holds BLX immediate,
     * advanced SIMD, and the memory barriers. It is not "condition never" —
     * reading it as a normal conditional instruction misdecodes all of it. */
    if (cond == 0xF) {
        o->conditional = 0;
        if ((w & 0xFE000000) == 0xFA000000) {
            set(o, A_CALL, "blx imm");
            o->switches_mode = 1;
            o->has_target = 1;
            o->target = o->addr + 8 + sign_extend(w & 0x00FFFFFF, 24) * 4
                      + (((w >> 24) & 1) << 1);
            return;
        }
        if ((w & 0x0F000000) == 0x0D000000 || (w & 0x0E000000) == 0x0C000000
            || (w & 0x0F000000) == 0x0E000000) {
            set(o, A_SIMD, "simd/vfp");
            return;
        }
        set(o, A_SYS, "sys");
        return;
    }

    /* BX / BLX register, which live inside the data-processing space and would
     * otherwise decode as a nonsensical MSR. */
    if ((w & 0x0FFFFFF0) == 0x012FFF10) {
        int rm = w & 0xF;
        if (rm == 14) set(o, A_RETURN, "bx lr");
        else        { set(o, A_INDIRECT, "bx"); o->switches_mode = 1; }
        return;
    }
    if ((w & 0x0FFFFFF0) == 0x012FFF30) {
        set(o, A_CALL, "blx reg");
        o->switches_mode = 1;
        return;
    }

    switch (op) {
        case 0: case 1:                             /* data processing        */
            /* MOV pc, lr is a return written as an ALU operation. */
            if (((w >> 12) & 0xF) == 15 && ((w >> 21) & 0xF) == 0xD) {
                set(o, A_RETURN, "mov pc,lr");
                return;
            }
            set(o, A_ALU, "alu");
            return;

        case 2: case 3:                             /* load / store           */
            if (op == 3 && (w & 0x00000010)) { set(o, A_UNDEF, "undef"); return; }
            if ((w & 0x00100000) && ((w >> 12) & 0xF) == 15) {
                set(o, A_RETURN, "ldr pc");
                return;
            }
            set(o, (w & 0x00100000) ? A_LOAD : A_STORE, "ldr/str");
            return;

        case 4:                                     /* ldm / stm              */
            if ((w & 0x00100000) && (w & 0x00008000)) {
                set(o, A_RETURN, "ldm {..,pc}");
                return;
            }
            set(o, (w & 0x00100000) ? A_LOADM : A_STOREM, "ldm/stm");
            return;

        case 5:                                     /* b / bl                 */
            set(o, (w & 0x01000000) ? A_CALL : A_BRANCH,
                   (w & 0x01000000) ? "bl" : "b");
            o->has_target = 1;
            o->target = o->addr + 8 + sign_extend(w & 0x00FFFFFF, 24) * 4;
            return;

        case 6:                                     /* coprocessor / SIMD     */
            set(o, A_SIMD, "simd/vfp");
            return;

        case 7:
            if (w & 0x01000000) { set(o, A_SYS, "svc"); return; }
            set(o, A_SIMD, "cdp/mcr");
            return;

        default:
            set(o, A_UNKNOWN, "?");
            return;
    }
}

/* --- entry point ------------------------------------------------------------ */

int arm_decode(const uint8_t *code, uint32_t code_addr, uint32_t code_len,
               uint32_t addr, arm_mode mode, arm_insn *out) {
    memset(out, 0, sizeof(*out));
    out->addr = addr;
    out->mode = mode;
    out->mnemonic = "?";
    /* Registers default to "absent" rather than r0, so an emitter that reads a
     * field the decoder never filled produces an obvious error instead of a
     * silent reference to the wrong register. */
    out->rd = out->rn = out->rm = out->rt = out->rt2 = ARM_NO_REG;
    out->vd = out->vn = out->vm = ARM_NO_REG;
    out->cond = ARM_COND_AL;

    if (addr < code_addr) return 0;
    uint32_t off = addr - code_addr;

    if (mode == ARM_A32) {
        if (off + 4 > code_len) return 0;
        out->width = 4;
        decode_a32(rd32le(code + off), out);
        return 4;
    }

    if (off + 2 > code_len) return 0;
    uint16_t h1 = rd16le(code + off);

    /* Thumb width, from the rule rather than a table: the first halfword
     * introduces a 32-bit instruction when its top five bits are 11101, 11110
     * or 11111. Everything else is a complete 16-bit instruction. */
    int is32 = (h1 & 0xF800) == 0xE800
            || (h1 & 0xF800) == 0xF000
            || (h1 & 0xF800) == 0xF800;

    if (!is32) {
        out->width = 2;
        decode_t16(h1, out);
        return 2;
    }

    if (off + 4 > code_len) return 0;
    out->width = 4;
    decode_t32(h1, rd16le(code + off + 2), out);
    return 4;
}
