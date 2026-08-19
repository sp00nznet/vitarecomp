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
still trapping, by kind:
  simd/vfp                          2207    1.58% of all instructions
  branch: target not a function      906    0.65%
  bitfield                          655    0.47%
  ?                                 236    0.17%
  ldm/stm                            96    0.07%
  indirect transfer                  95    0.07%
  misc                               88    0.06%
  sys                                64    0.05%
```

Reading what remains in value order rather than count order:

1. **Advanced SIMD — 1,647 (1.18%), of which ~1,300 is true NEON.** The only
   genuinely hard piece left.

   Splitting this bucket paid twice. The first split found 82% of it was scalar
   VFP. Splitting the *remainder* found 40% of that was scalar VFP too —
   `VPUSH`/`VPOP`/`VLDM`/`VSTM` (293) and multiply-accumulate (476), both of
   which had been declined earlier on the reasoning that approximating them
   would be worse than trapping. `VMLA` expresses directly as
   `vd = vd + (vn * vm)`; the only real loss is that ARM may fuse the multiply
   and add without an intermediate rounding, where C rounds twice — a last-bit
   mantissa difference, recorded rather than silently accepted.
2. **Branch targets — 906 (0.65%).** The residue of the branch work: targets
   that really are neither a placed label nor a registered function. A
   *discovery* fix — being branched to from outside a collected region makes an
   address an entry point, exactly as being called does.
3. **Bitfield ops — 655 (0.47%).** `SBFX`/`UBFX`/`BFI`/`BFC`. Mechanical.
4. **`"?"` — 236 (0.17%).** Down from 3,034; mostly data decoded as code.
5. **The long tail — under 350 combined.** General `LDM`/`STM`, `MLA`/`MLS`,
   `misc`, `sys`.

Excluding NEON, roughly **1.4%** remains, so about **99% is reachable without
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

NEON proper is **0.94% of all instructions** — a quarter the size the headline
figure suggested. It is still the hardest thing left, but it is not a wall, and
it was never the reason this platform looked difficult.

The lesson generalises past this instruction set: a bucket named after its
hardest member gets budgeted like its hardest member. Splitting it by encoding
before writing any code turned "the largest remaining problem" into "half of it
is `memcpy`".
