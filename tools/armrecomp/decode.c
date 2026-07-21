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

/* --- Thumb, 32-bit ---------------------------------------------------------- */

static void decode_t32(uint16_t h1, uint16_t h2, arm_insn *o) {
    o->raw = ((uint32_t)h1 << 16) | h2;

    /* Advanced SIMD and VFP occupy the coprocessor space. They are identified
     * as a class rather than decoded, so `cover` can report how much of a given
     * module actually needs them before anyone commits to implementing them. */
    if ((h1 & 0xEF00) == 0xEF00 || (h1 & 0xEE00) == 0xEC00) {
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

    /* Load/store multiple and dual. LDM with the PC in the list is a return. */
    if ((h1 & 0xFE40) == 0xE800) {
        int load = (h1 & 0x0010) != 0;
        if (load && (h2 & 0x8000)) { set(o, A_RETURN, "ldm {..,pc}"); return; }
        set(o, load ? A_LOADM : A_STOREM, "ldm/stm.w");
        return;
    }

    /* Data processing, modified immediate and register forms. */
    if ((h1 & 0xF800) == 0xF000 || (h1 & 0xFE00) == 0xEA00) {
        set(o, A_ALU, "alu.w");
        return;
    }

    /* Single load/store. A load into the PC is a return. */
    if ((h1 & 0xFE00) == 0xF800 || (h1 & 0xFF00) == 0xF900) {
        int load = (h1 & 0x0010) != 0;
        if (load && ((h2 >> 12) & 0xF) == 0xF) { set(o, A_RETURN, "ldr pc"); return; }
        set(o, load ? A_LOAD : A_STORE, "ldr/str.w");
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
    out->rd = out->rn = out->rm = out->rt = ARM_NO_REG;
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
