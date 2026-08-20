# Translation

What decodes, what translates, and what is left. All figures are from
`armrecomp` on *Uncharted: Fight for Fortune* unless stated otherwise.

## Coverage, and why the dominant instruction set is decided by branch targets

Every module in the corpus is **Thumb-2 dominant**, with a real ARM minority
that makes mode tracking mandatory rather than optional.

Every module in the corpus is **Thumb-2 dominant**, with a real ARM minority
that makes mode tracking mandatory rather than optional.

```
$ armrecomp cover uncharted.elf
segment 0  vaddr 0x81000000  5656372 bytes executable
  thumb    2137553 insns  unknown 3.67%  simd 2.45%  branch targets in range 99.89%  16-bit 67.7%
  arm      1414093 insns  unknown 1.66%  simd 13.52%  branch targets in range 32.15%

  dominant set: Thumb-2 (by branch-target validity, not unknown rate)
    alu           936488  43.81%
    load          352769  16.50%
    store         291456  13.64%
    branch        256083  11.98%
    call          102178   4.78%
    return         32078   1.50%
    simd           52427   2.45%
    sys             1496   0.07%
```


The dominant set is picked by **branch-target validity**, not by unknown rate —
see [`LESSONS.md`](LESSONS.md#the-unknown-rate-is-not-a-validity-measure) for
why the obvious metric reports the wrong answer.

**The unknown rate is an upper bound, not a decode failure rate.** ARM puts
PC-relative constants in literal pools *inside* `.text`, so part of any linear
sweep is decoding data. Those bytes are not instructions we failed to decode;
they are not instructions.

## ThumbExpandImm, and why it is worth a test

32-bit Thumb encodes a 32-bit constant in twelve bits, and **two entirely
different encodings share the field**, selected by its top two bits. Clear, and
the low byte is replicated into a pattern; otherwise the field is a
rotate-right of a value whose top bit is implicit and always set.

Reading it as a plain 12-bit integer is the obvious mistake and a quiet one:
small constants land in the first case with pattern `00`, where the naive
reading is *correct*. Everything above `0xFF` is then wrong. The implicit top
bit is the other trap — forgetting it leaves every rotated constant short by
`0x80`.

Two more that only a test catches, both found that way here:

- **The immediate/register split is not a single bit.** `0xEA`/`0xEB` and
  `0xF0`/`0xF1` both have bit 15 set, so testing it classifies every
  shifted-register instruction as an immediate one and reads operand 2 from the
  wrong fields.
- **`MOVW` sets bit 6**, so a group mask that keeps that bit excludes `MOVW`
  from its own group entirely.

Four operations also change identity when a register field is `r15`, which the
architecture uses instead of spending encoding space: `rn == 15` turns `ORR`
into `MOV` and `ORN` into `MVN`; `rd == 15` with `S` set turns
`AND`/`EOR`/`ADD`/`SUB` into `TST`/`TEQ`/`CMN`/`CMP`.


## What is still trapping, ranked

`emit` reports the remaining gaps by kind, because "8% untranslated" is not
actionable and "SIMD is 65% of what is left" is:

```
still trapping, by kind:            (all 20,989 functions, 1,583,445 insns)
  simd/vfp                       9784    0.62% of all instructions
  branch: target not a function  5363    0.34%
  ?                              2507    0.16%
  ldm/stm                        1820    0.11%
  misc                           1019    0.06%
  indirect transfer               740    0.05%
  mla/mls                         518    0.03%
  ldm/stm.w                       393    0.02%
  sys                             285    0.02%
  svc                             224    0.01%
  sat                             139    0.01%
  branch: target off-segment      131    0.01%
  udf                             119    0.01%
  alu.w / alu.w rd=pc             180    0.01%
  cbz/cbnz                         61    0.00%
  writes pc                        34    0.00%
  sbfx / bfi                       11    0.00%
```

**Measure the whole module, not a prefix.** The same run over the first 1,500
functions reports 98.33%; over all 20,989 it is **98.87%**. A prefix is not a
sample — functions are emitted in address order, and the low end of `.text` is
not representative of it. Every figure here is the full-module one.

Reading what remains in value order rather than count order:

1. **Advanced SIMD — 9,646 (0.63%).** The only genuinely hard piece left.

   Splitting this bucket paid twice. The first split found 82% of it was scalar
   VFP. Splitting the *remainder* found 40% of that was scalar VFP too —
   `VPUSH`/`VPOP`/`VLDM`/`VSTM` and multiply-accumulate, both of which had been
   declined earlier on the reasoning that approximating them would be worse
   than trapping. `VMLA` expresses directly as `vd = vd + (vn * vm)`; the only
   real loss is that ARM may fuse the multiply and add without an intermediate
   rounding, where C rounds twice — a last-bit mantissa difference, recorded
   rather than silently accepted.
2. **Branch targets — 4,736 (0.31%).** Targets that are neither a placed label
   nor a registered function. A *discovery* fix — being branched to from
   outside a collected region makes an address an entry point, exactly as being
   called does.
3. **`"?"` — 2,468 (0.16%).** Mostly data decoded as code, which is what a
   linear sweep over literal pools produces and not a decoder failure.
4. **`LDM`/`STM` — 2,204 combined (0.15%)** across the general and wide forms.
5. **The long tail — under 1,600 combined.** `misc`, `MLA`/`MLS`, `sys`, `SVC`,
   `SSAT`/`USAT`, `UDF`, off-segment branches, `alu.w`, `CBZ`/`CBNZ`.

**Bitfield ops are done.** `SBFX`/`UBFX`/`BFI`/`BFC` were 655 (0.47%) at 1,500
functions and are now 11 — and those 11 are deliberate, being extracts that run
off the end of the register. That is UNPREDICTABLE, it comes from decoding data
as code, and it traps rather than being clamped: a clamped extract would say
nothing true.

Excluding NEON, roughly **0.5%** remains, so about **99.4% is reachable without
touching the vector unit**.


## NEON: a minority of the code, but the majority of what is left

The usual reason given for the Vita being a hard recompilation target is its
NEON vector unit. That reputation turns out to be misdirected, and the reason is
worth stating precisely.

**Most of the coprocessor space is not vector work at all.** Breaking the 5.19%
down by sub-encoding:

| Sub-encoding | Share of the coprocessor space | Difficulty |
|---|---:|---|
| VFP load/store (`VLDR`/`VSTR`/`VLDM`) | 47.9% | Moving 32-bit values |
| VFP single-precision | 32.1% | Scalar float → C `float`, near 1:1 |
| VFP double-precision | 1.6% | Same, `double` |
| **Advanced SIMD (NEON)** | **18.1%** | The genuinely hard part |
| other coprocessor | 0.3% | — |

**82% of it is scalar floating point**, and nearly half is load/store that does
no arithmetic whatsoever. Implementing scalar VFP took the SIMD bucket from
7,242 instructions to 2,207 and overall translation from 92.04% to **95.64%**.

What is left of the coprocessor space after scalar VFP is **0.63% of all
instructions** across the whole module, and NEON is the bulk of it — a fraction
of the size the headline figure suggested. It is still the hardest thing left,
but it is not a wall, and it was never the reason this platform looked
difficult. (The sub-encoding split above was measured before the scalar VFP
work; the 0.63% is the residue after it.)

The lesson generalises past this instruction set: a bucket named after its
hardest member gets budgeted like its hardest member. Splitting it by encoding
before writing any code turned "the largest remaining problem" into "half of it
is `memcpy`".
