/* test_decode.c â€” ARMv7 decoding, on hand-built encodings only.
 *
 * Every encoding here is assembled in this file from the architecture's rules
 * and its expected result worked out by hand, so a wrong decoder disagrees with
 * arithmetic rather than with a blob somebody once observed.
 */

#include "decode.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef NDEBUG
#error "tests must be built with asserts enabled (NDEBUG is defined)"
#endif

/* Lay out little-endian halfwords at a notional base address. */
static uint8_t code[64];

static void put16(int off, uint16_t v) {
    code[off]     = (uint8_t)(v & 0xFF);
    code[off + 1] = (uint8_t)(v >> 8);
}

static void put32(int off, uint32_t v) {
    code[off]     = (uint8_t)(v);
    code[off + 1] = (uint8_t)(v >> 8);
    code[off + 2] = (uint8_t)(v >> 16);
    code[off + 3] = (uint8_t)(v >> 24);
}

#define BASE 0x1000u

static arm_insn dec(arm_mode mode, uint32_t addr) {
    arm_insn in;
    int n = arm_decode(code, BASE, sizeof(code), addr, mode, &in);
    assert(n == in.width);
    return in;
}

/* --- Thumb width: the thing that must never be wrong ------------------------ */
/*
 * A wrong width does not produce one wrong instruction, it desynchronises the
 * rest of the run and produces a long stretch of plausible nonsense. The rule
 * is that first halfwords 0xE800-0xFFFF introduce a 32-bit instruction.
 */

static void test_thumb_width(void) {
    memset(code, 0, sizeof(code));

    /* Just below the boundary: still 16-bit. */
    put16(0, 0xE7FE);                      /* b . (unconditional, 16-bit)    */
    assert(dec(ARM_T32, BASE).width == 2);

    /* At and above the boundary: 32-bit. All three prefixes. */
    put16(0, 0xE800); put16(2, 0x0000);
    assert(dec(ARM_T32, BASE).width == 4);
    put16(0, 0xF000); put16(2, 0xB800);
    assert(dec(ARM_T32, BASE).width == 4);
    put16(0, 0xF800); put16(2, 0x0000);
    assert(dec(ARM_T32, BASE).width == 4);

    /* An ordinary 16-bit data-processing instruction stays 2 bytes. */
    put16(0, 0x4478);                      /* add r0, pc                     */
    assert(dec(ARM_T32, BASE).width == 2);

    printf("  thumb width boundary           ok\n");
}

/* --- returns, in both instruction sets -------------------------------------- */

static void test_returns(void) {
    memset(code, 0, sizeof(code));

    put16(0, 0x4770);                      /* bx lr                          */
    assert(dec(ARM_T32, BASE).cls == A_RETURN);

    put16(0, 0xBD00);                      /* pop {pc}                       */
    assert(dec(ARM_T32, BASE).cls == A_RETURN);

    put16(0, 0xBC00);                      /* pop {} â€” no pc, not a return   */
    assert(dec(ARM_T32, BASE).cls == A_LOADM);

    put32(0, 0xE12FFF1E);                  /* bx lr (ARM)                    */
    assert(dec(ARM_A32, BASE).cls == A_RETURN);

    put32(0, 0xE8BD8000);                  /* ldm sp!, {pc} (ARM)            */
    assert(dec(ARM_A32, BASE).cls == A_RETURN);

    put32(0, 0xE1A0F00E);                  /* mov pc, lr (ARM)               */
    assert(dec(ARM_A32, BASE).cls == A_RETURN);

    printf("  returns, both modes            ok\n");
}

/* --- writing r15 is control flow, not arithmetic ---------------------------- */
/*
 * The high-register ADD/MOV group can name r15 as its destination, and doing so
 * is a BRANCH. Classifying it as an ALU write emits an assignment where a jump
 * belongs, and the recompiled function runs straight past a transfer it should
 * have taken. This was caught only because the runtime has no `pc` variable, so
 * the generated C refused to compile; with a `pc` present it would have built
 * cleanly and been silently wrong.
 */

static void test_pc_destination(void) {
    memset(code, 0, sizeof(code));

    /* rd is (DN << 3) | rd_low, split across bits 7 and 2:0. 0x46B7 is
     * rd = (1<<3)|7 = 15; 0x46B6 is rd = 14 and is an ordinary move to LR.
     * The two differ by one bit, which is why the split field is worth
     * spelling out here. */
    put16(0, 0x46B7);                      /* mov pc, r6  (rd=15, rm=6)      */
    arm_insn in = dec(ARM_T32, BASE);
    assert(in.cls == A_INDIRECT);
    assert(in.cls != A_ALU);

    put16(0, 0x46B6);                      /* mov lr, r6 â€” rd=14, still ALU  */
    in = dec(ARM_T32, BASE);
    assert(in.cls == A_ALU && in.op == OP_MOV && in.rd == 14);

    put16(0, 0x46F7);                      /* mov pc, lr                     */
    in = dec(ARM_T32, BASE);
    assert(in.cls == A_RETURN);

    put16(0, 0x4487);                      /* add pc, r0  (rd=15)            */
    in = dec(ARM_T32, BASE);
    assert(in.cls == A_INDIRECT);

    /* An ordinary high-register move is still arithmetic. */
    put16(0, 0x4630);                      /* mov r0, r6                     */
    in = dec(ARM_T32, BASE);
    assert(in.cls == A_ALU && in.op == OP_MOV && in.rd == 0 && in.rm == 6);

    /* CMP never writes its destination, so r15 there is a normal operand. */
    put16(0, 0x45B7);                      /* cmp r15, r6                    */
    in = dec(ARM_T32, BASE);
    assert(in.cls == A_ALU && in.op == OP_CMP);

    printf("  r15 destination is a branch    ok\n");
}

/* --- ThumbExpandImm --------------------------------------------------------- */
/*
 * Two encodings share one 12-bit field, and the naive "it is just a 12-bit
 * integer" reading is correct for small constants and wrong for everything
 * else â€” which is exactly the shape of bug that survives casual testing. Each
 * case is checked against a value worked out from the definition.
 */

static void test_thumb_expand_imm(void) {
    memset(code, 0, sizeof(code));

    /* mov.w rd, #imm â€” 0xF04F is ORR with rn=15, which is MOV. */

    /* Pattern 00: the byte, unchanged. */
    put16(0, 0xF04F); put16(2, 0x0042);
    arm_insn in = dec(ARM_T32, BASE);
    assert(in.op == OP_MOV && in.has_imm && in.imm == 0x42);

    /* Pattern 01: byte replicated into halves -> 0x00XY00XY. */
    put16(0, 0xF04F); put16(2, 0x1042);
    in = dec(ARM_T32, BASE);
    assert(in.imm == 0x00420042u);

    /* Pattern 10: byte replicated, shifted up -> 0xXY00XY00. */
    put16(0, 0xF04F); put16(2, 0x2042);
    in = dec(ARM_T32, BASE);
    assert(in.imm == 0x42004200u);

    /* Pattern 11: byte in all four positions. */
    put16(0, 0xF04F); put16(2, 0x3042);
    in = dec(ARM_T32, BASE);
    assert(in.imm == 0x42424242u);

    /* The rotate form. The stored 7 bits carry an implicit leading 1, so the
     * value rotated is 0x80|imm7, not imm7 â€” the single easiest thing here to
     * get wrong, and it leaves every such constant short by 0x80.
     *
     * i:imm3:a = 01000 gives a rotate of 8 applied to 0x80: 0x80000000. */
    put16(0, 0xF04F); put16(2, 0x4000);
    in = dec(ARM_T32, BASE);
    assert(in.imm == 0x80000000u);

    printf("  thumb expand immediate         ok\n");
}

/* --- 32-bit Thumb operands -------------------------------------------------- */

static void test_t32_operands(void) {
    memset(code, 0, sizeof(code));

    /* add.w r0, r1, r2 */
    put16(0, 0xEB01); put16(2, 0x0002);
    arm_insn in = dec(ARM_T32, BASE);
    assert(in.width == 4 && in.op == OP_ADD);
    assert(in.rd == 0 && in.rn == 1 && in.rm == 2 && !in.sets_flags);

    /* adds.w r0, r1, r2 â€” the S bit is bit 4 of the first halfword. */
    put16(0, 0xEB11); put16(2, 0x0002);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_ADD && in.sets_flags);

    /* orr.w with rn == 15 is MOV, not a real ORR against r15. */
    put16(0, 0xEA4F); put16(2, 0x0001);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_MOV && in.rn == ARM_NO_REG && in.rm == 1);

    /* sub.w with rd == 15 and S set is CMP: flags only, no destination. */
    put16(0, 0xEBB1); put16(2, 0x0F02);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_CMP && in.rd == ARM_NO_REG);

    /* movw r0, #0x1234 â€” a plain 16-bit literal, not a modified immediate. */
    put16(0, 0xF241); put16(2, 0x2034);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_MOV && in.imm == 0x1234);

    /* ldr.w r0, [r1, #0x100] â€” 12-bit unsigned offset form. */
    put16(0, 0xF8D1); put16(2, 0x0100);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_LDR && in.rt == 0 && in.rn == 1 && in.imm == 0x100);

    /* str.w r0, [r1, #0x100] */
    put16(0, 0xF8C1); put16(2, 0x0100);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_STR && in.rt == 0 && in.rn == 1);

    /* movt r0, #0x8100 â€” writes the TOP half only.
     *
     * MOVW/MOVT is how ARM builds a 32-bit address. Leaving MOVT untranslated
     * costs every constructed pointer its high 16 bits, which a trace of
     * module_start showed as indirect branches to 0x00000000. */
    /* rd is bits 11:8 of the SECOND halfword, so 0x1000 means r0. The 16-bit
     * literal is assembled from imm4:i:imm3:imm8 spread across both halfwords:
     * 8:0:1:0x00 gives 0x8100. */
    put16(0, 0xF2C8); put16(2, 0x1000);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_MOVT && in.rd == 0 && in.imm == 0x8100);

    /* strd r1, r0, [sp] â€” bit 6 separates dual from multiple. An earlier mask
     * kept that bit and so excluded every LDRD/STRD from decoding at all. */
    put16(0, 0xE9CD); put16(2, 0x1000);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_STRD && in.rn == 13 && in.rt == 1 && in.rt2 == 0);

    put16(0, 0xE9DD); put16(2, 0x1200);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_LDRD && in.rn == 13 && in.rt == 1 && in.rt2 == 2);

    /* mul.w r0, r1, r2 â€” ra == 15 distinguishes it from MLA. */
    put16(0, 0xFB01); put16(2, 0xF002);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_MUL && in.rd == 0 && in.rn == 1 && in.rm == 2);

    /* push.w {r4,lr} / pop.w â€” only the SP-relative forms translate as stack
     * operations; an LDM against another base must not. */
    put16(0, 0xE92D); put16(2, 0x4010);
    in = dec(ARM_T32, BASE);
    assert(in.cls == A_STOREM && in.op == OP_PUSH && in.rn == 13);

    put16(0, 0xE8B1); put16(2, 0x0030);      /* ldm r1!, {r4,r5} â€” base r1 */
    in = dec(ARM_T32, BASE);
    assert(in.cls == A_LOADM && in.op == OP_NONE);

    printf("  32-bit thumb operands          ok\n");
}

/* --- operand decoding ------------------------------------------------------- */

static void test_operands(void) {
    memset(code, 0, sizeof(code));

    /* 16-bit data processing sets flags implicitly â€” there is no S bit. */
    put16(0, 0x1C41);                      /* adds r1, r0, #1                */
    arm_insn in = dec(ARM_T32, BASE);
    assert(in.op == OP_ADD && in.rd == 1 && in.rn == 0);
    assert(in.has_imm && in.imm == 1 && in.sets_flags);

    put16(0, 0x2042);                      /* movs r0, #0x42                 */
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_MOV && in.rd == 0 && in.imm == 0x42 && in.sets_flags);

    /* Load/store immediates are scaled by the ACCESS SIZE, so the byte form is
     * not the word form with a smaller range. */
    put16(0, 0x6841);                      /* ldr r1, [r0, #4]               */
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_LDR && in.rt == 1 && in.rn == 0 && in.imm == 4);

    put16(0, 0x7841);                      /* ldrb r1, [r0, #1]              */
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_LDRB && in.imm == 1);

    put16(0, 0x8841);                      /* ldrh r1, [r0, #2]              */
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_LDRH && in.imm == 2);

    /* PUSH/POP register lists, including the extra bit for LR and PC. */
    put16(0, 0xB570);                      /* push {r4,r5,r6,lr}             */
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_PUSH && in.reglist == (0x70 | 0x4000));

    put16(0, 0xBD70);                      /* pop {r4,r5,r6,pc}              */
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_POP && (in.reglist & 0x8000) && in.cls == A_RETURN);

    printf("  operands                       ok\n");
}

/* --- the J1/J2 branch encoding ---------------------------------------------- */
/*
 * The two J bits are stored XORed with the sign bit. A decoder that treats them
 * as plain address bits is correct for short forward branches and wrong for
 * long or backward ones, which is exactly the bug that survives casual testing.
 * Both directions are checked, with the encodings derived by hand.
 */

static void test_bl_target(void) {
    memset(code, 0, sizeof(code));

    /* BL at 0x1000 -> 0x1100. offset = 0x1100 - 0x1004 = +0xFC.
     * S=0, so I1=I2=0, which means J1=J2=1. imm11 = 0xFC>>1 = 0x7E. */
    put16(0, 0xF000);
    put16(2, 0xF87E);
    arm_insn in = dec(ARM_T32, BASE);
    assert(in.width == 4);
    assert(in.cls == A_CALL);
    assert(in.has_target);
    assert(in.target == 0x1100);

    /* BL at 0x1000 -> 0x0F00. offset = 0x0F00 - 0x1004 = -0x104.
     * S=1, I1=I2=1 so J1=J2=1; imm10=0x3FF, imm11=0x77E. */
    put16(0, 0xF7FF);
    put16(2, 0xFF7E);
    in = dec(ARM_T32, BASE);
    assert(in.cls == A_CALL);
    assert(in.target == 0x0F00);

    printf("  bl target, both directions     ok\n");
}

static void test_branch_targets(void) {
    memset(code, 0, sizeof(code));

    /* 16-bit conditional branch: b<cond> +4 -> 0x1000+4+4 = 0x1008. */
    put16(0, 0xD002);                      /* cond=0 (eq), imm8=2            */
    arm_insn in = dec(ARM_T32, BASE);
    assert(in.cls == A_BRANCH && in.conditional && in.target == 0x1008);

    /* 16-bit unconditional: b . -> 0x1000+4-2 = 0x1000 (a self-loop). */
    put16(0, 0xE7FE);
    in = dec(ARM_T32, BASE);
    assert(in.cls == A_BRANCH && !in.conditional && in.target == BASE);

    /* ARM bl: pc is addr+8 on ARM, not addr+4. bl +0 -> 0x1008. */
    put32(0, 0xEB000000);
    in = dec(ARM_A32, BASE);
    assert(in.cls == A_CALL && in.target == 0x1008);

    /* ARM b backwards: imm24 = -2 -> 0x1000+8-8 = 0x1000. */
    put32(0, 0xEAFFFFFE);
    in = dec(ARM_A32, BASE);
    assert(in.cls == A_BRANCH && in.target == BASE);

    printf("  branch targets                 ok\n");
}

/* --- interworking ----------------------------------------------------------- */

static void test_mode_switches(void) {
    memset(code, 0, sizeof(code));

    put16(0, 0x4778);                      /* bx pc â€” switches to ARM        */
    arm_insn in = dec(ARM_T32, BASE);
    assert(in.cls == A_INDIRECT && in.switches_mode);

    put16(0, 0x4780);                      /* blx r0                         */
    in = dec(ARM_T32, BASE);
    assert(in.cls == A_CALL && in.switches_mode);

    put32(0, 0xE12FFF30);                  /* blx r0 (ARM)                   */
    in = dec(ARM_A32, BASE);
    assert(in.cls == A_CALL && in.switches_mode);

    /* bx lr must NOT be flagged as a mode switch â€” it is a return, and
     * treating it as interworking would corrupt the decoder's mode state for
     * everything after it. */
    put16(0, 0x4770);
    assert(dec(ARM_T32, BASE).switches_mode == 0);

    printf("  interworking                   ok\n");
}

/* --- the ARM unconditional encoding space ----------------------------------- */

static void test_arm_cond_f(void) {
    memset(code, 0, sizeof(code));

    /* cond == 1111 is not "never" â€” it is a separate encoding space. Reading it
     * as a normal conditional instruction misdecodes all of it. */
    put32(0, 0xFA000000);                  /* blx imm                        */
    arm_insn in = dec(ARM_A32, BASE);
    assert(in.cls == A_CALL && in.switches_mode && !in.conditional);

    /* A genuinely conditional instruction still reports as conditional. */
    put32(0, 0x0A000000);                  /* beq                            */
    in = dec(ARM_A32, BASE);
    assert(in.cls == A_BRANCH && in.conditional);

    /* AL (1110) is unconditional in effect and must not be flagged. */
    put32(0, 0xEA000000);                  /* b                              */
    assert(dec(ARM_A32, BASE).conditional == 0);

    printf("  arm unconditional space        ok\n");
}

/* --- SIMD is identified, not decoded ---------------------------------------- */

/* --- scalar VFP ------------------------------------------------------------- */
/*
 * Register numbering is fiddly in opposite directions for the two precisions: a
 * single-precision register keeps its LOW bit in the separate D flag and its
 * high four in the main field, while a double-precision register does the
 * reverse. Getting it backwards yields a valid register number that is simply
 * the wrong one â€” no error, just a program reading floats it never wrote.
 */

static void test_vfp(void) {
    memset(code, 0, sizeof(code));

    /* vldr s0, [r1, #8] */
    put16(0, 0xED91); put16(2, 0x0A02);
    arm_insn in = dec(ARM_T32, BASE);
    assert(in.op == OP_VLDR && in.rn == 1 && in.vd == 0);
    assert(in.imm == 8 && in.mem_add && !in.vfp_dp);

    /* vldr d0, [r1, #8] â€” coproc 11 selects double precision */
    put16(0, 0xED91); put16(2, 0x0B02);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_VLDR && in.vfp_dp && in.vd == 0);

    /* The D bit is the LOW bit of a single-precision register number. With
     * D set, Vd=0 means s1 rather than s0. */
    put16(0, 0xEDD1); put16(2, 0x0A02);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_VLDR && in.vd == 1 && !in.vfp_dp);

    /* ...but the HIGH bit of a double-precision one: D set, Vd=0 means d16. */
    put16(0, 0xEDD1); put16(2, 0x0B02);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_VLDR && in.vfp_dp && in.vd == 16);

    /* vadd.f32 s0, s1, s2 / vsub.f32 â€” the op bit of the second halfword
     * separates them within one encoding. */
    put16(0, 0xEE30); put16(2, 0x0A81);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_VADD && !in.vfp_dp);

    put16(0, 0xEE30); put16(2, 0x0AC1);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_VSUB);

    /* vmul.f32 and vdiv.f32 */
    put16(0, 0xEE20); put16(2, 0x0A81);
    assert(dec(ARM_T32, BASE).op == OP_VMUL);
    put16(0, 0xEE80); put16(2, 0x0A81);
    assert(dec(ARM_T32, BASE).op == OP_VDIV);

    /* vcmp.f32 s0, s1 */
    put16(0, 0xEEB4); put16(2, 0x0A41);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_VCMP && in.vm != ARM_NO_REG);

    /* vcmp.f32 s0, #0 â€” compares against zero, so there is no second
     * register at all. */
    put16(0, 0xEEB5); put16(2, 0x0A40);
    in = dec(ARM_T32, BASE);
    assert(in.op == OP_VCMP && in.vm == ARM_NO_REG && in.has_imm);

    /* vmrs APSR_nzcv, fpscr â€” VFP comparisons write FPSCR, and only this
     * moves them where a conditional branch can see them. */
    put16(0, 0xEEF1); put16(2, 0xFA10);
    assert(dec(ARM_T32, BASE).op == OP_VMRS);

    /* vabs / vneg / vsqrt share an encoding, split by opc2 and opc3. */
    put16(0, 0xEEB0); put16(2, 0x0AC0);
    assert(dec(ARM_T32, BASE).op == OP_VABS);
    put16(0, 0xEEB1); put16(2, 0x0A40);
    assert(dec(ARM_T32, BASE).op == OP_VNEG);
    put16(0, 0xEEB1); put16(2, 0x0AC0);
    assert(dec(ARM_T32, BASE).op == OP_VSQRT);

    /* Advanced SIMD proper is still reported as SIMD, not claimed. */
    put16(0, 0xEF00); put16(2, 0x0000);
    assert(dec(ARM_T32, BASE).cls == A_SIMD);

    printf("  scalar vfp                     ok\n");
}

static void test_simd_identified(void) {
    memset(code, 0, sizeof(code));

    arm_insn in;
    put16(0, 0xEF00); put16(2, 0x0000);    /* advanced SIMD (Thumb)          */
    assert(dec(ARM_T32, BASE).cls == A_SIMD);

    /* VSTR shares the coprocessor space but is scalar VFP, not vector work, so
     * it is now claimed and translated rather than reported as opaque SIMD.
     * Most of this space is like that: 82% of it on a real module is scalar
     * floating point. */
    put16(0, 0xED00); put16(2, 0x0A00);    /* vstr s0, [r0]                  */
    in = dec(ARM_T32, BASE);
    assert(in.cls == A_STORE && in.op == OP_VSTR);
    assert(in.rn == 0 && in.vd == 0 && !in.vfp_dp);

    put32(0, 0xEE000A10);                  /* vmov (ARM)                     */
    assert(dec(ARM_A32, BASE).cls == A_SIMD);

    printf("  simd identified as a class     ok\n");
}

/* --- IT blocks -------------------------------------------------------------- */

static void test_it_block(void) {
    memset(code, 0, sizeof(code));

    /* IT makes up to the next four instructions conditional. It must be
     * distinguishable from the NOP-family hints that share its encoding
     * space, because phase 5 has to honour it. */
    put16(0, 0xBF08);                      /* it eq â€” mask nonzero           */
    arm_insn in = dec(ARM_T32, BASE);
    assert(in.cls == A_SYS && strcmp(in.mnemonic, "it") == 0);

    put16(0, 0xBF00);                      /* nop â€” mask zero                */
    in = dec(ARM_T32, BASE);
    assert(in.cls == A_NOP);

    printf("  it block vs nop                ok\n");
}

/* --- refusing to run off the end -------------------------------------------- */

static void test_bounds(void) {
    arm_insn in;
    /* A 32-bit Thumb instruction whose second halfword is past the end must
     * report "no instruction", not decode from uninitialised memory. */
    memset(code, 0, sizeof(code));
    put16(sizeof(code) - 2, 0xF000);
    assert(arm_decode(code, BASE, sizeof(code),
                      BASE + sizeof(code) - 2, ARM_T32, &in) == 0);

    /* An address before the start of the buffer. */
    assert(arm_decode(code, BASE, sizeof(code), BASE - 4, ARM_T32, &in) == 0);

    printf("  bounds                         ok\n");
}

int main(void) {
    printf("decode:\n");
    test_thumb_width();
    test_returns();
    test_pc_destination();
    test_operands();
    test_thumb_expand_imm();
    test_t32_operands();
    test_bl_target();
    test_branch_targets();
    test_mode_switches();
    test_arm_cond_f();
    test_simd_identified();
    test_vfp();
    test_it_block();
    test_bounds();
    printf("all decode tests passed\n");
    return 0;
}

