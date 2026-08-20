# Lessons

Corrections, and bugs found by running the thing rather than reasoning about
it. Kept because the wrong answers here were all plausible, and the record of
*why* they were wrong is worth more than the fixed code.

## Running it is what found the next bug

The recompiled `module_start` was given a host — ELF segments loaded into guest
memory at their own vaddrs, a stack, and a call — and traced. The result was
immediate and unambiguous:

```
TRACE unimpl  0x8100B92A  raw 0xF2C81262  movt
TRACE unimpl  0x8100B930  raw 0xF2C81C4B  movt
TRACE indirect 0x8100B936 -> 0x00000000
TRACE unimpl  0x8100B93C  raw 0xF2C81056  movt
```

**`MOVT` dominated, and the indirect branches to `0x00000000` were the
consequence.** ARM builds a 32-bit address with a `MOVW`/`MOVT` pair — low half
then high half — so leaving `MOVT` untranslated costs every constructed pointer
its top 16 bits, and every computed branch lands near zero.

It had been left trapping on the reasoning that "emitting it as a move would
discard the low 16 bits". That was right about the hazard and wrong about the
conclusion: the correct translation is one line,
`rd = (rd & 0xFFFF) | (imm << 16)`. Refusing to approximate had turned into
refusing to implement, and only running the thing showed the cost.

The same trace surfaced `LDRD`/`STRD` falling through as unknown — bit 6
separates the dual forms from the multiple forms, and the mask kept it, so they
never matched. After both fixes the `movt` traps are gone from the trace
entirely.

**`VITARECOMP_TRACE=1`** switches traps from abort to log-and-continue. It is a
discovery aid and is labelled as one: past the first missing piece the machine
state is wrong and every later trap is reached down a path that would not have
happened on hardware. What it is good for is one run naming many missing pieces
instead of one.


## A generated-code bug only scale revealed

Scaling the emit from 100 to 1,500 functions also exposed a generated-code bug
that smaller runs could not. Labels were recorded the moment a branch target was
seen inside a function's extent, but the block behind one is only collected if
the walk reaches it — and the walk can stop short at three separate limits. The
result was `goto L_81521D2C` with no such label, which does not compile.

The fix is to prune labels against what was actually emitted rather than raise
the limits. A `goto` into a block we never translated would be a lie even if the
compiler accepted it; dropping the label routes the branch through the
call-or-trap path, which says what is true.


## Two wrong guesses before the right measurement

The 2,547 trapping branches looked like a discovery problem — targets that were
never registered as functions. Two plausible fixes came first, and both were
wrong:

1. **An inconsistency between `bound` and `fn->end`** in the emitter's collect
   pass, where the walk used one and the labelling used the other. That was a
   genuine bug and worth fixing, but it moved translation by 0.01%.
2. **Branch targets needing promotion to functions.** Reasonable, and it is
   still true for a residue — but it was not what the bulk of them were.

Making the emitter report *why* each branch trapped settled it in one run: only
177 were the not-a-function case. The other 2,359 were something else entirely
— the decoder set the class, the mnemonic, and a correctly computed target for
`b.w` and `b<cond>.w`, and never set `op`. The emitter's translation switch is
keyed on `op`, so every wide branch decoded perfectly and then fell through to a
trap. Two missing assignments, worth **1.8% of the entire module**.

The lesson is the one this project keeps relearning in new costumes: the
plausible explanation and the true one are different things, and instrumenting
the tool to say which case it hit is cheaper than reasoning about which case it
probably hit.

Reading what remains in value order rather than count order:

1. **Advanced SIMD — 1,647 (1.18%), of which ~1,300 is true NEON.** The only
   genuinely hard piece left.

   Splitting this bucket paid twice. The first split found 82% of it was scalar
   VFP. Splitting the *remainder* found 40% of that was scalar VFP too —
   `VPUSH`/`VPOP`/`VLDM`/`VSTM` (293) and multiply-accumulate (476), both of
   which had been declined earlier on the reasoning that approximating them
   would be worse than trapping. `VMLA` expresses directly as

## Three bugs the compile caught that tests had not

**`MOV pc, rN` was decoded as an ALU write** and emitted as `pc = r6`. That is a
*branch*, not an assignment. It surfaced only because `cpu.h` deliberately has
no `pc` variable, so the C refused to compile — had `pc` existed "for
completeness", it would have built cleanly and silently run past a jump it
should have taken.

**Function extent is not function size.** The emitter first swept each
function's extent linearly, but extent is the highest address the *flow* walk
reached, and tail-call branches drag it across other functions. Every function
re-emitted that whole span: **2.39 GB of C**. Flow-following instead of sweeping
gave 133 MB and raised the translation rate, because the duplicated
data-as-code was gone.

**Being called is what makes an address a function.** Discovery gated
registration on its "already decoded here" bitmap, so a call target another
function's walk had wandered through never became a function — while the
emitter still emitted a call to it. The C compiled and failed to link. Those are
now two separate questions with two separate records.

A related one, from the same link failure: the emitter now **never names a
symbol it does not define**. Two call targets in this module land *inside the
import table*, one of them 0x32 bytes into the first entry — data that happened
to decode as a `BL`. They are traps now, not calls.


## The unknown rate is not a validity measure

The first version of `cover` picked the dominant instruction set by whichever
sweep produced fewer unknowns, and confidently reported **ARM** for a module
whose returns are 10:1 Thumb.

The reason is that the unknown rate measures *how permissive the decoder is for
a given mode*, not whether the bytes are that mode. The ARM decoder assigns a
class to every `op` value, so it reports near-zero unknowns on any input at all
— including pure noise. Two tells gave it away: the ARM sweep claimed **22.62%
system instructions** and **13.52% SIMD**, and no real compiled code has that
shape.

The honest discriminator is **branch-target validity**, because it is arithmetic
performed on the decoded bits rather than a classification of them. Decode real
code in its real mode and its branches point at other code in the same segment;
decode it in the wrong mode and the offsets come from misaligned bits and
scatter. It is a check the wrong answer can fail — 99.89% versus 32.15% on the
same bytes.

**Its known limit:** the in-range test weakens as the segment grows, since a
larger segment is an easier target to hit by chance. *Volume* (53 MB) scores ARM
at 96.30% and *AC III: Liberation* at 77.92%, where normal-sized modules put ARM
at 16–45%. Thumb wins everywhere, but the metric is least discriminating exactly
where the module is largest.

**The unknown rate is an upper bound, not a decode failure rate.** ARM puts
PC-relative constants in literal pools *inside* `.text`, so part of any linear
sweep is decoding data. Those bytes are not instructions we failed to decode;
they are not instructions. Separating them needs the control flow that discovery
recovers.

## The SIMD figure was an undercount

Earlier revisions of the README put SIMD at 2.45% for this
title. That was an undercount caused by a decoder bug: the coprocessor mask
`(h1 & 0xEE00) == 0xEC00` matches `0xEC` and `0xED` but not `0xEE`/`0xEF`,
which is where VFP's CDP/MCR/MRC forms live. Roughly 2,800 VFP instructions
were being counted as *unknown* instead. The real figure is **5.19%**, and
the "unknown" figures were correspondingly inflated.

It surfaced from the trap breakdown: 2.16% of instructions decoding to
`"?"` is a number that demands an explanation, and there wasn't one.


## Two corrections on reading the container

Both are the same lesson from a different angle: a plausible reading of a binary
is not a verified one.

**The SELF header is not the PS3 SELF header.** Vita inserts `self_filesize` and
a padding qword at `0x20`, shifting every field after it by `0x10`. Built against
the widely-published PS3 layout, the parser read `elf_offset` from `0x30` and got
`4` — not garbage, not obviously wrong, just a small plausible offset. What
caught it was that the ELF header is independently locatable: scanning for
`7F 45 4C 46` puts it at `0xA0`, which is the field at `0x40`.

**The synthetic test agreed with the bug.** It was built from the same wrong
layout as the parser, so it passed. That is the general limit of synthetic tests
on a reverse-engineered format, and the reason a real module is in the loop from
phase 1 rather than phase 3.

A third, found the same way: **MSVC Release defines `NDEBUG`**, which compiles
every `assert()` in the suite to nothing. The tests printed "all passed" while
checking nothing. The build now strips `NDEBUG` for test targets, and
`test_container.c` `#error`s if it ever comes back — a silent green run is worse
than a red one.



## The verification you keep deferring is the one that finds the bug

The generated C was confirmed to compile, link and run at 100 functions. Seven
toolkit changes later — VFP, dispatch, wide branches, VFP list forms, bitfields
— it had not been re-confirmed, and the README carried "it still builds at
scale" as a stated assumption rather than a result.

It did not build. `OP_VLDR`/`OP_VSTR` formatted their own address expression
instead of going through the shared `address()` helper, so a PC-relative VFP
load emitted `vita_read32(pc + 0x18)` — and `cpu.h` deliberately has no `pc`.
The same design decision that caught `MOV pc, rN` caught this one, three months
later, the moment anything actually invoked a compiler.

It survived that long for a mundane reason: the 100-function sample contained
no VFP literal. The check was real, and it was run, and it covered a prefix of
the program that did not include the construct that would break.

Fixing it at the shared helper rather than at the caller cured a second bug
nothing had noticed. `address()` ignored the U bit entirely, so the T32 8-bit
`[rN, #-imm]` form — which `decode.c` correctly decodes, setting `mem_add = 0`
— was emitting `rN + imm` and reading from the wrong side of the base register.
That one affected ordinary integer loads and stores, silently, everywhere.

## A prefix is not a sample

The same emit run reports **98.33%** over the first 1,500 functions and
**98.86%** over all 19,120. Functions come out in address order, so "the first
N" is a contiguous region of `.text`, not a cross-section of it — and the low
end of this module is denser in the constructs that still trap.

Every headline figure in these docs was a prefix measurement until this was
noticed. They were not wrong about direction, and each one understated the
result.

## The first indirect transfer is a firmware call, not missing code

With the build fixed, the recompiled `module_start` runs and stops at
`0x8100B936` with `unresolved indirect transfer -> 0x814B9590`. The obvious
reading is a discovery gap: an address that should have been recognised as a
function and was not.

It is not. `0x814B9590` is `SceLibc::__cxa_set_dso_handle_main` — an import
stub. Imports bind at emit time on a direct `BL` to a stub address, but this
call is reached *through a pointer*, so it never went through that path;
`vita_dispatch` searched the function table, correctly failed to find it, and
trapped.

The fix is in the dispatcher, not in discovery: an indirect transfer to a known
stub address is a firmware call and should be routed as one. Worth recording
because the trap message named the symptom accurately and still pointed at the
wrong subsystem — and because the diagnostic only became readable at all once
`vita_dispatch` was given the address of the transfer as well as its
destination. It had been reporting `at 0x00000000`.
