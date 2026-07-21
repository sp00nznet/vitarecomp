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

static void decode_t16(uint16_t h, arm_insn *o) {
    o->raw = h;

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
                 * phase 5 has to honour. It is identified here so that it is
                 * never silently treated as a NOP. */
                set(o, (h & 0x000F) ? A_SYS : A_NOP, (h & 0x000F) ? "it" : "nop");
                return;
            }
            if ((h & 0xF600) == 0xB400) {
                int load = (h & 0x0800) != 0;
                /* POP with the PC in the register list is a return. */
                if (load && (h & 0x0100)) { set(o, A_RETURN, "pop {..,pc}"); return; }
                set(o, load ? A_LOADM : A_STOREM, load ? "pop" : "push");
                return;
            }
            if ((h & 0xF500) == 0xB100) { set(o, A_BRANCH, "cbz/cbnz");
                                          o->conditional = 1; return; }
            set(o, A_ALU, "misc");
            return;

        case 0xC:                               /* stm / ldm                  */
            set(o, (h & 0x0800) ? A_LOADM : A_STOREM, "ldm/stm");
            return;

        case 0xD: {                             /* conditional branch, svc    */
            int cond = (h >> 8) & 0xF;
            if (cond == 0xF) { set(o, A_SYS, "svc"); return; }
            if (cond == 0xE) { set(o, A_UNDEF, "udf"); return; }
            set(o, A_BRANCH, "b<cond>");
            o->conditional = 1;
            o->has_target = 1;
            o->target = o->addr + 4 + sign_extend(h & 0xFF, 8) * 2;
            return;
        }

        case 0xE:                               /* unconditional branch       */
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
