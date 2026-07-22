# vitarecomp

**A static-recompilation toolkit for PlayStation Vita games — turning ARM into
native C, not emulating it.**

The Vita has one good emulator (Vita3K) and, as far as we can find, **no static
recompiler**. That gap is worth closing, and the Vita is a better target than its
reputation suggests:

- **One documented CPU.** A quad-core ARM Cortex-A9 running ARMv7-A. ARM is the
  most widely documented architecture there is, and unlike the PSP's Allegrex it
  has no vendor-specific opcode divergences to rediscover.
- **A documented OS boundary.** Games call `sceKernel*` / `sceGxm*` / `sceCtrl*`
  by NID through a module import table. That is a *library* surface, not a
  hardware surface, which means it can be implemented as HLE C rather than
  emulated — and the NID→name mapping is published and MIT-licensed.
- **A corpus that needs no decryption.** See below; this is the finding that
  shapes the whole project.

`vitarecomp` is the reusable toolkit. Games brought up on it live in separate
repos that consume this one as a submodule — that split is deliberate: the
toolkit is the thing other people fork to recompile *their* Vita game.

> **No game data here.** Dumps, `eboot.bin`, `.suprx` modules, VPKs and any key
> material are all `.gitignore`d. This repo is the recompiler, the runtime, and
> docs — bring your own dump.

## How it works

```
  dump / .vpk ──► armrecomp ──► eboot.bin / *.suprx      peel the container
                  (zip · dir)    (a SCE\0-wrapped ELF)    stack down to a module
                      │
                      ▼
              ┌────────────────────┐   segment table is PLAINTEXT; segments are
              │  inflate  (phase 2)│   zlib. QA builds need no keys at all.
              └────────────────────┘   SELF ──► a plain ELF32 ARM module
                      │
                      ▼
              ┌────────────────────┐   decode ARMv7 + Thumb-2, discover functions
              │  armrecomp         │   (following the module's export table and
              │  (tools/)          │   SCE_RELA relocations), translate to C:
              └────────────────────┘   vita_func_<addr>
                      │  generated/recomp_funcs.c
                      ▼
              ┌────────────────────┐   the runtime the generated C links against:
              │  vitarecomp (lib)  │   CPU state · memory · semantic helpers ·
              │  (src/, include/)  │   sceKernel/sceGxm HLE · dispatch
              └────────────────────┘
                      │
                      ▼   (+ a per-game host: load module, register, run, present)
              native executable — the recompiled game runs
```

## Status — phase 1 (the container stack) is done and validated

Pointed at a real module, `armrecomp` identifies every layer and reports exactly
what stands between here and decodable ARM:

```
$ armrecomp info eboot.bin
size:     1680560 bytes
format:   SELF (SCE\0-wrapped ELF)

SCE header:
  version         3
  header len      0x1000
  elf filesize    3522160 bytes (decrypted)
  auth id         0x2F00000000000001
  self type       8
  sys version     0x1010000000000

ELF:
  type            ET_SCE_RELEXEC (0xFE04)
  machine         EM_ARM
  entry           0x002B36E8
  segments        5

segments:
  #   type         flags  vaddr      filesz     memsz
  0   LOAD         r-x    0x81000000 3053164    3053164
  1   LOAD         rw-    0x812EA000 7044       1204744
  2   SCE_RELA     ---    0x00000000 446924     0
  3   SCE_RELA     ---    0x00000000 4480       0
  4   SCE_VERSION  ---    0x00000000 10298      0

segment encryption:
  0   1501685    bytes  zlib      plain      (zlib header verified)
  ...
no encrypted segments, verified against zlib headers — this
module can go straight to the decoder once inflated.
```

**What works today**

- ✅ **The container stack** (`container.c`) — SCE/SELF header, appinfo, ELF32
  and program headers, and the segment table, each bounds-checking every offset
  it reads out of the file rather than walking off the end of it.
- ✅ **Refusing what it cannot parse.** A retail NoNpDrm eboot is ciphertext from
  byte zero; it is reported by name, not parsed into plausible garbage.
- ✅ **A verified plaintext claim.** The encryption flag is cross-checked against
  the actual segment bytes (zlib CMF/FLG, including the header checksum), so the
  report says "plain *and the bytes agree*" — and prints a loud disagreement line
  if they ever do not. See [`docs/DECRYPT.md`](docs/DECRYPT.md).
- ✅ **`ctest`, all synthetic** — no game data, no dump, no key material in the
  repo or in the tests.

- ✅ **DEFLATE and zlib, written not vendored** (`inflate.c`, RFC 1951/1950) —
  canonical Huffman decoding, all three block types, overlapping back-references
  handled byte-at-a-time, and the Adler-32 trailer verified. Validated against a
  fixed-Huffman *encoder* built from the spec in the test file, so the decoder is
  checked against an independent implementation rather than a pasted blob.
- ✅ **`armrecomp extract` — SELF in, plain ELF32 out.** **15/15 modules in the
  corpus extract and round-trip back through `info`**, from 236 KB
  (`libfios2.suprx`) to 53 MB (*Volume*).

- ✅ **An ARMv7 + Thumb-2 decoder** (`decode.c`) — both instruction sets, with
  correct width determination, control-flow extraction (targets, conditionality,
  interworking), IT blocks distinguished from the NOP hints that share their
  encoding, and NEON/VFP identified as a class. Operands land in phase 5.
- ✅ **`armrecomp cover`** — coverage, class histogram, and instruction-set
  determination over 16 modules.

- ✅ **`.sce_module_info`, import and export tables** (`module.c`) — and with
  them `armrecomp funcs`, which reports the HLE work list derived from the
  module's own import table rather than guessed at.
- ✅ **Function discovery** (`analyze.c`) — recursive descent carrying
  instruction-set state, seeded from `module_start`, the export table, a linear
  harvest of call targets, and prologue-filtered pointer-shape recovery.

- ✅ **The emitter** (`emit.c`) and the runtime (`src/`, `include/vitarecomp/`).
  **The generated C compiles, links, and runs.**

**Not started:** the HLE layer. This is phase 5 of six.

## The pipeline runs end to end

```
$ armrecomp emit uncharted.elf recomp_funcs.c 100 path/to/vita-headers/db/360
  functions     100
  instructions  8827
  translated    7607  (86.18%)
  trapped       1220  (13.82%)
  literals      24  folded to constants
  import calls  49  bound to firmware

$ cmake --build build --config Release && ./gencheck
runtime up: sp=0x81800000  bad_access=0
lsl(1,32)=0 (ARM says 0, naive C gives 1)
asr(0x80000000,32)=0xFFFFFFFF (ARM says all ones)
5-3: c=1 (ARM sets carry when there is NO borrow)
3-5: c=0
linked ok
```

That is **SELF → ELF → decode → discover → emit → compile → link → run**, with
no key material anywhere in it.

The output is meant to be read:

```c
/* ---------------------------------------------------------------
 * vita_func_8100B910  --  4 instructions, 8 bytes
 * ------------------------------------------------------------- */
void vita_func_8100B910(void) {
    /* 8100B910  bl               */
    vita_func_8100B918();
    /* 8100B914  nop              */
    /* nop */
}
```

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

## Where the runtime earns its keep

Every helper exists because the obvious C is **wrong**, not merely verbose:

- **Shifts by ≥ 32.** C leaves them undefined; ARM defines them as zero; x86
  masks the count to 5 bits, so the naive `v << 32` returns `v` *unchanged* —
  the exact opposite of the right answer. Invisible until a shift amount is
  computed rather than constant.
- **Carry on subtraction is NOT a borrow.** ARM sets it when there is *no*
  borrow. Getting it backwards inverts every unsigned comparison in the program.
- **`ADC`'s carry cannot be tested with `res < a`.** With a carry in, adding
  `0xFFFFFFFF` leaves the value unchanged while genuinely carrying, so the naive
  test silently breaks every multi-word addition.
- **Flag operands are captured before the destination is written**, because `rd`
  and `rn` are frequently the same register and the flag computation needs the
  original values.

All of it is pinned by `tests/test_runtime.c`, with the expected values derived
from the architecture's definition rather than from what the code returns.

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

## e_entry does not point at code

The single most consequential thing found in phase 4. On Vita, `e_entry` names
`.sce_module_info`, not an instruction. Following it as a code address on
*Uncharted: Fight for Fortune* lands in the middle of a string table, on the
module name `cardgame` — and every function discovered from that seed would be
fiction.

The real entry is `module_start` inside that structure, and the structure also
names the export and import tables. This is psprecomp's "module_start is not
the program" in a sharper form: here the ELF entry point is not even in `.text`.

**Two address conventions, not one.** The `.sce_module_info` header fields
(`export_top`, `import_top`, `module_start`) are **segment-relative offsets**.
The pointers stored *inside* an import or export entry (`library_name`, the NID
tables, the entry tables) are **absolute virtual addresses**. Resolving one as
the other does not fault — it fails a bounds check and yields nothing, so the
symptom is a table of `(unnamed)` libraries rather than an error. The two
resolvers are kept as separate functions so the choice is explicit at every
call site.

## The HLE work list, derived

```
$ armrecomp funcs uncharted.elf
module:   cardgame
firmware libraries needed (524 functions across 39 libraries):
  SceGxm                            107   nid 0xF76B66BD
  SceLibc                            68   nid 0xBE43BB07
  SceCommonDialog                    37   nid 0xE537816C
  SceLibKernel                       30   nid 0xCAE9ACE6
  SceLibm                            28   nid 0xCDAE3C7D
  SceNgs                             25   nid 0xB01598D9
  ...
```

`SceGxm` at 107 functions is over a fifth of everything imported — the deep end
of phase 6, now with a number on it. Conversely the networking and trophy
libraries total 112 functions that a single-player bring-up does not need, which
is the same shape as psprecomp deferring WTF's ad-hoc networking.

## Discovery, and what it honestly does not know

```
$ armrecomp discover uncharted.elf
module:   cardgame   (ET_SCE_EXEC, no relocations)
seeds:
  call targets        52763
  pointer shape       22288  (heuristic; 4993 candidates rejected)
functions:            18978
  from seeds           8764
  from shape          10214  (heuristic)
bytes covered:        3424148 / 5656372  (60.5%)
  indirect sites      17970  (unresolved computed transfers)
```

Three things this does not claim:

- **54% of functions come from a heuristic.** Shape recovery requires a word
  with bit 0 set (the Thumb bit, the one genuinely reliable signal), pointing
  into `.text`, that decodes as a function prologue. An earlier version required
  only that it "decode as something", which rejected 45 of 27,281 candidates —
  0.16%, meaning it was barely filtering at all. Requiring a prologue rejects
  18%. It will still admit false positives and will miss leaf functions that
  push nothing, so the two tiers are reported separately rather than summed.
- **60.5% coverage is not 39.5% missed code.** The denominator is the whole
  executable segment, which holds literal pools and read-only data. 100% would
  indicate over-reach, not success.
- **17,970 indirect call sites are unresolved.** These are register-form `BLX`
  instructions whose destination is computed, and they are exactly what
  relocation seeding would enumerate on a 2015+ module. `ET_SCE_EXEC` has no
  relocations, so shape is all there is — which is the cost of the launch-window
  catalogue being where the exclusives are.

## NEON is not the obstacle

The usual reason given for the Vita being a hard recompilation target is its
NEON vector unit. Measured across the corpus, **NEON/SIMD is 0.71–5.34% of
instructions** — 2.45% in *Uncharted: Fight for Fortune*. Recompiling the
integer core, which is ordinary well-documented ARMv7, gets you most of a game.

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

### A correction worth recording: the unknown rate is not a validity measure

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
they are not instructions. Separating them needs phase 4's control flow.

### Reassembly is checkable, not merely plausible

Decompression can succeed and still be wrong, so three independent numbers the
file itself declares have to agree before an extract is accepted: the inflated
size against each segment's `p_filesz`, the Adler-32 against the segment bytes,
and the total against `elf_filesize`. On *Uncharted: Fight for Fortune* all
three land exactly (`5,883,138` bytes declared and produced).

**`e_entry` is not an absolute address.** Vita encodes it relative to the
module — the top two bits select a program header, the low 30 are a byte offset
into that segment. `0x004BA470` sits far below segment 0's vaddr of
`0x81000000` while being comfortably inside its 5,656,372 bytes; resolved
properly it is segment 0 + `0x4BA470`, or vaddr `0x814BA470`. An
absolute-address check fails on every module — and worse, on a module with a low
load address it could pass by coincidence and validate nothing.

## The finding that shapes the project: QA builds are not encrypted

Every Vita executable is wrapped in a SELF container that *supports* encryption.
The question that matters is which modules actually *use* it — and because the
segment table is plaintext, that is answerable with no key material at all.

Across a corpus of QA/prototype builds and app-bundled system modules, **every
segment is plaintext**, zlib-compressed only:

| Module | Size | `.text` | Entry | `e_type` | Encrypted |
|---|---:|---:|---|---|---:|
| LittleBigPlanet (2012-07-31) | 4,866,592 | 8,780,492 | `0x00766468` | `SCE_EXEC` | **0** |
| AC III: Liberation (2012-09-09) | 15,049,328 | 36,615,592 | `0x01F92E0C` | `SCE_EXEC` | **0** |
| Ragnarok Odyssey (2012-09-13) | 2,592,576 | 4,692,640 | `0x0039D2C0` | `SCE_EXEC` | **0** |
| CoD: Black Ops Declassified (2012-10-02) | 4,836,896 | 9,561,752 | `0x007C1F1C` | `SCE_EXEC` | **0** |
| **Uncharted: Fight for Fortune** (2012-11-01) | 2,871,472 | 5,656,372 | `0x004BA470` | `SCE_EXEC` | **0** |
| Guacamelee! (2013-03-06) | 4,317,584 | — | — | `SCE_EXEC` | **0** |
| Valhalla Knights 3 (2013-05-30) | 2,523,552 | 5,596,220 | `0x004032DC` | `SCE_EXEC` | **0** |
| Titan Souls (2015-04-01) | 1,680,560 | 3,053,164 | `0x002B36E8` | `SCE_RELEXEC` | **0** |
| Shovel Knight (2015-04-08) | 2,306,752 | 3,582,384 | `0x00306030` | `SCE_RELEXEC` | **0** |
| Super Blackout (2015-07-26) | 1,571,696 | — | `0x00209488` | `SCE_RELEXEC` | **0** |
| Super Meat Boy (2015-09-18) | 945,600 | — | `0x0014A1F4` | `SCE_RELEXEC` | **0** |
| Volume (2015-12-09) | 17,110,432 | — | `0x025D0660` | `SCE_RELEXEC` | **0** |
| Trillion: God of Destruction (2016-02-15) | 2,093,456 | 3,375,228 | `0x002AAC68` | `SCE_RELEXEC` | **0** |
| `libc.suprx` | 202,560 | 326,740 | `0x0003B4F8` | `SCE_RELEXEC` | **0** |
| `libfios2.suprx` | 116,928 | — | `0x00022878` | `SCE_RELEXEC` | **0** |

### Static vs relocatable is the split that matters

`e_type` is not cosmetic. `ET_SCE_RELEXEC` modules carry `PT_SCE_RELA`
segments, and a relocation naming a word that holds an address **is** a stored
function pointer — thread entries, callbacks, vtables. Mining them is
enumeration, not guesswork, and on PSP it moved coverage from 75% to 89%.

`ET_SCE_EXEC` modules are statically linked: absolute addresses need no
patching, so there are no relocations to mine. Recovering their function
pointers falls back to recognising them by shape (in range, instruction-aligned,
decodes as an instruction), which is a heuristic and is kept labelled as one.

**The split is not per-title — it is chronological**, and across 15 measured
modules it has no exceptions:

| Era | `e_type` | `SCE_RELA` segments | Modules |
|---|---|---:|---:|
| 2012-07 → 2013-05 | `ET_SCE_EXEC` | **0** | 7 |
| 2015-04 → 2016-02 | `ET_SCE_RELEXEC` | 2 | 6 (+2 system modules) |

The boundary falls somewhere between 2013-05 and 2015-04, which points at a
toolchain generation change — but **that mechanism is unconfirmed, and the two
obvious candidates were both refuted by measurement.** `sdk_type` is `0x00C0`
on every module in the corpus, so it discriminates nothing. `sys_version` does
not track the split either: *Guacamelee* (2013-03) and *Uncharted: Fight for
Fortune* (2012-11) both carry the later `0x1010000000000` while still being
static. The correlation is real; the cause is not established, and there is no
earlier signal in the container than `e_type` itself.

**Why this matters more than one title's difficulty:** the Vita exclusives worth
recompiling are overwhelmingly launch-window titles, because that is when the
platform still had exclusives — and the entire launch window is static. So
shape-based pointer recovery is not a workaround for one awkward pick, it is
required infrastructure for the early-era catalogue as a whole.

That is a large claim, so it is checked against the bytes rather than the flag:
every segment begins with a valid zlib header, and offset `0x1000` holds a
plaintext ELF header whose `e_entry` matches the value read independently from
the ELF header at `0xA0`. Five independent segments landing on valid zlib magic
is not something ciphertext does.

**Consequence:** the entire pipeline — parse, inflate, decode, discover, emit,
compile, link — can be built and validated end to end without any key material
entering the picture. This is the same result `psprecomp` found on PSP prototype
discs, and it has the same effect on the project's shape.

**Honestly accounted for:** we do not yet have a *true negative* — a module we
know to be encrypted that the parser correctly reports as such. Until one is in
the corpus, "the parser discriminates" rests on the zlib cross-check rather than
on a demonstrated encrypted case. Retail NoNpDrm dumps sit behind a further PFS
layer keyed per-title by the dumping console, and stay out of scope entirely;
see [`docs/DECRYPT.md`](docs/DECRYPT.md).

## Two corrections worth recording

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

## Building

Requires CMake and a C compiler (MSVC on Windows; gcc/clang elsewhere). The core
has **no external dependencies** — a fresh clone builds with nothing installed.

```powershell
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release
# -> build/tools/armrecomp/Release/armrecomp.exe
# -> the vitarecomp runtime static library
```

```
armrecomp info <file>     identify a module and report its structure
```

`info` accepts a SELF (`eboot.bin`, `*.suprx`) or a plain ELF/velf.

## On licensing, and why there is no emulator vendored here

The same arrangement `psprecomp` has with PPSSPP, and for the same reason: the
emulator is a thing you *diff against*, never a thing you link.

| Project | License | How it is used |
|---|---|---|
| [vita-headers](https://github.com/vitasdk/vita-headers) | MIT | The NID database — the published mapping from import NIDs to function names. The reference for the HLE work list. |
| [VitaSDK](https://github.com/vitasdk) | MIT | Headers and the published ABI for `sceGxm` / `sceKernel` / `sceCtrl`. |
| **Vita3K** | **GPLv2** | **Oracle only** — run as a separate process and compared against. No code copied, linked, or vendored. |

**This is the constraint that most shapes the runtime.** Vita3K is GPLv2, so the
usual "chop the emulator into a link library" move is not available if the
toolkit is to stay MIT — and the part you would most want from it (the `sceGxm`
and kernel HLE) is exactly the part you would be tempted to vendor. That layer
has to be written here, against the MIT headers.

*Licenses above are the working understanding and are re-checked before any code
or data from a project is actually used.*

## Repository layout

```
include/vitarecomp/   runtime API (phase 3)
src/                  runtime (phase 3)
tools/armrecomp/      the toolkit: container stack (SELF · ELF/velf), CLI
tests/                ctest: container parser — synthetic, no game data
docs/                 DECRYPT (and, as they land: ARCHITECTURE · CONTAINERS ·
                      RECOMPILER · ORACLE)
```

## The HLE work list, resolved

```
$ armrecomp funcs uncharted.elf path/to/vita-headers/db/360
nid db:   154 files, 9274 functions
...
resolved 519 of 524 imported functions (99.0%)
```

Imports are NIDs — the first four bytes of the SHA-1 of a function's name — so
the names come from the MIT [vita-headers](https://github.com/vitasdk/vita-headers)
database. It is **loaded at run time, not vendored**: bundling it would be
permitted, but it is data, and keeping it external means the toolkit carries no
third-party source and a newer database needs no rebuild.

**`SceGxm` is 107 functions, and that number is misleading.** About 85 are
struct field writes — state setters, texture accessors, surface init. The real
work is roughly 15 functions: GXP reflection, the scene pipeline, and the GXP
shader translator, which is a compiler in its own right. See
[`docs/HLE.md`](docs/HLE.md).

## Imports are bound, so firmware calls say what they are

A module never calls firmware directly. It calls a **stub** inside its own
`.text` that the loader patches at load time, so the recompiler sees an ordinary
`BL` to an ordinary address. Left unbound, every firmware call looks like an
internal call to a function whose body is placeholder filler — and recompiling
that filler would translate it and then "return" into whatever it happened to
be.

Pairing the import NID table with the entry table gives the stub address for
each function, so calls bind at emit time:

```
$ armrecomp emit uncharted.elf recomp_funcs.c 100 path/to/vita-headers/db/360
  translated    6161  (69.80%)
  import calls    49  bound to firmware

wrote recomp_funcs_imports.c
  524 import stubs, each trapping by name
```

```c
void vita_hle_sceGxmMapFragmentUsseMemory(void);
```

and in the companion file, one default per import:

```c
/* SceRtcUser::sceRtcGetCurrentTick  stub 0x814B83D0 */
void vita_hle_sceRtcGetCurrentTick(void) { vita_trap_import(0x814B83D0, 0x23F79274); }
```

That is what makes the HLE **incrementally implementable**. The generated C
links from the first build, and an unimplemented firmware call names exactly
which function the game wanted — rather than failing to link, or silently
returning zero. Implementing one means removing its stub and providing a real
body in the link.

## Why the HLE is written rather than borrowed

Vita3K is **GPLv2** — its README attributes the choice to *"external
dependencies, most notably Unicorn"*, a CPU emulator, which is exactly the
component a static recompiler exists to replace. That gives no relicensing room,
and there is no LGPL escape: the arrangement that works for
[`xboxrecomp`](https://github.com/sp00nznet/xboxrecomp), extracting LGPL-2.1
components from xemu, depends on **QEMU deliberately dual-tracking its hardware
model under LGPL** so it can be embedded. Vita3K has no equivalent.

What does carry over is everything else — independently implemented algorithms
with credit, and functional facts (NIDs, struct layouts, enum values, calling
conventions) which are not copyrightable and are most of what the shallow 85
need. Vita3K stays a **behavioural oracle**: separate process, compared against,
never linked.

## Documentation

- [`docs/DECRYPT.md`](docs/DECRYPT.md) — the SELF container, what is encrypted
  and what is not, and why the QA corpus needs no keys.
- [`docs/HLE.md`](docs/HLE.md) — the firmware surface, measured, and the order
  of work.
- [`ROADMAP.md`](ROADMAP.md) — phased plan.

## Credits & references

All code here is original, but it stands on a great deal of prior
reverse-engineering. With thanks to:

- **[VitaSDK / vita-headers](https://github.com/vitasdk)** — the MIT-licensed
  homebrew SDK and the NID database, without which the import table is just
  hashes.
- **[Vita3K](https://github.com/Vita3K/Vita3K)** — the best public description
  of Vita behaviour that exists. Used as a behavioural oracle and as
  documentation. **Reference only; no code copied.**
- The **Vita homebrew and reverse-engineering community**, whose published work
  on the SELF format, the module info structures and the NID scheme is what
  makes any of this tractable.

> Running a game requires a dump that **you** own. No game data, no firmware, and
> no keys ship in this repo.

## License

MIT — see [`LICENSE`](LICENSE). Independent, non-commercial preservation work;
not affiliated with or endorsed by Sony Interactive Entertainment.
