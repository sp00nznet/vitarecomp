# Roadmap

Six phases. Each one ends with something runnable and measured, not a milestone
that is declared done.

## Phase 1 — the container stack ✅

Identify any layer from dump to module and report what stands between here and
decodable ARM, with no key material.

- [x] SCE/SELF header, appinfo, ELF32 header, program headers, segment table
- [x] Bounds-checking on every offset read out of the file
- [x] Named refusal for PFS-encrypted retail dumps
- [x] Encryption flag cross-checked against observed zlib headers
- [x] Synthetic `ctest` suite, with a guard against `NDEBUG` silently disabling it

**Established:** QA/prototype builds carry plaintext, zlib-compressed segments.
The corpus needs no decryption. See [`DECRYPT.md`](DECRYPT.md).

## Phase 2 — inflate and reassemble ✅

Turn a SELF into a plain ELF32 on disk.

- [x] DEFLATE + zlib, written rather than vendored (RFC 1951/1950), keeping the
      "no external dependencies" promise intact
- [x] Segment reassembly into a valid ELF32 using the plaintext program headers
- [x] Verify: inflated size matches `p_filesz`, Adler-32 matches, total matches
      `elf_filesize`, and `e_entry` resolves into a `PF_X` segment
- [x] `armrecomp extract` — SELF in, ELF out
- [x] **15/15 modules in the corpus extract and round-trip**, from 236 KB
      (`libfios2.suprx`) to 53 MB (*Volume*)

**Not in scope, now or later:** key derivation, key extraction, the PFS layer.

## Phase 3 — the decoder ✅ (classification; operands land in phase 5)

- [x] ARMv7-A and Thumb-2, both instruction sets, with correct **width**
      determination — the output that must never be wrong, since one bad width
      desynchronises every instruction after it
- [x] Control flow: branch/call/return/indirect, targets computed, conditionality
      and interworking flagged
- [x] IT blocks distinguished from the NOP hints sharing their encoding space
- [x] VFP / NEON identified as a class even where not translated
- [x] `armrecomp cover` — coverage, class histogram, and instruction-set
      determination
- [ ] Full operand decoding (deferred to phase 5, where the emitter needs it)
- [ ] Literal-pool identification — currently counted as unknown rather than
      recognised as data, which is why the unknown rate is an upper bound

**Established across 16 modules:** every one is Thumb-2 dominant, and
**NEON/SIMD is 0.71–5.34%** of instructions. The vector unit is not the
obstacle on this platform.

## Phase 4 — function discovery ✅ (seeded; boundaries need work)

- [x] `.sce_module_info` parsing — `e_entry` points at this structure, **not at
      code**
- [x] Import/export table walking; `armrecomp funcs` reports the HLE work list
- [x] Recursive descent carrying instruction-set state, since a seed without a
      mode is worthless
- [x] Linear harvest of `BL`/`BLX` targets
- [x] Pointer-shape recovery, prologue-filtered, counted separately as the
      heuristic it is
- [x] `armrecomp discover`
- [ ] `SCE_RELA` relocation seeding — not applicable to `ET_SCE_EXEC` modules,
      which is the whole launch-window catalogue, but needed for 2015+ titles
- [ ] Jump-table recognition — 17,970 indirect call sites remain unresolved
- [ ] Function *boundary* quality: extents currently absorb tail calls

## Phase 5 — the emitter ✅

- [x] Full operand decoding for the 16-bit Thumb core (the phase 3 gap): shifts,
      immediate and register ALU, high-register forms, every load/store
      addressing mode, PUSH/POP register lists, extends, `REV`, `CBZ`/`CBNZ`,
      `IT`
- [x] ARM → readable C, one function at a time, with the disassembly as comments
- [x] Conditional execution and flag semantics, in the runtime rather than
      inlined at each site
- [x] Literal-pool loads folded to constants at translation time
- [x] Anything untranslated emits a **named run-time trap**, never silence
- [x] **Verified: generated C compiles, links against the runtime, and runs**
- [x] **32-bit Thumb operand decoding** — data processing (shifted register and
      modified immediate), `MOVW`/`ADDW`/`SUBW`, load/store, shift-by-register,
      `MUL`, `PUSH.W`/`POP.W`. Translation **69.80% → 86.18%**
- [x] **`MOVT` and `LDRD`/`STRD`** — translation **86.18% → 89.44%**
- [x] **A host**: ELF segment loader, guest memory, stack, and `module_start`
      called for real. `VITARECOMP_TRACE=1` logs and continues instead of
      aborting, so one run names many missing pieces
- [x] **Runtime dispatch** — a sorted address→function table, so `BX Rm` and
      `BLX Rm` become real transfers. The module has ~18,000 indirect sites;
      without this the program cannot leave `module_start`
- [x] **Scalar VFP** — the float register file with single/double aliasing,
      `VLDR`/`VSTR`, arithmetic, `VABS`/`VNEG`/`VSQRT`, `VCMP` with proper
      unordered-NaN semantics, `VMRS`, `VMOV` core↔VFP, and `VCVT`.
      Translation **92.04% → 95.64%**
- [x] **Wide branches** — `b.w` and `b<cond>.w` decoded their targets correctly
      and then trapped anyway, because the decoder never set `op`. Translation
      **95.65% → 97.47%**
- [ ] Branch targets promoted to functions — 4,736 remaining (0.31%)
- [x] **Bitfield ops** — `SBFX`/`UBFX`/`BFI`/`BFC`, 655 (0.47%). The group's
      5-bit op field is shared with `MOVW`/`MOVT`/`ADDW`, and the field
      position is encoded three ways across the four instructions. `SSAT`/
      `USAT` share the group and are named separately, since they are not
      bitfield work. Out-of-range extracts and `msb < lsb` keep trapping
      rather than being clamped
- [x] **The scalar VFP remainder** — `VPUSH`/`VPOP`/`VLDM`/`VSTM` and the
      multiply-accumulate forms. Translation **97.47% → 97.87%**
- [x] **`VLDR` from a literal pool** — it emitted a bare `pc`, so the generated
      C did not compile at all once a VFP literal appeared. Fixed at the shared
      `address()` helper, which also cured the U bit being ignored for the T32
      `[rN, #-imm]` form. Found only by building at scale
- [x] **Verified at scale**: 1,500 functions → 15 MB of C → compiles, links,
      and runs, reaching the first indirect transfer at `0x8100B936`
- [ ] Advanced SIMD (NEON) — 9,646 instructions (0.63%), and now genuinely the
      only hard piece left. *Advanced SIMD and NEON are the same instruction
      set — ARM's formal name and the marketing one — so this is one job.*
- [ ] ARM (A32) operand decoding — a small minority of this corpus. The A32
      media space is also currently classed `A_UNDEF`, which is wrong: `op == 3`
      with bit 4 set is media, not an undefined encoding
- [ ] `MLA`/`MLS`, general `LDM`/`STM` — long tail

**Whole-module translation: 98.86%** (19,120 functions, 1,532,679 instructions).
Measure the whole module, not a prefix: the first 1,500 functions report 98.33%,
and functions are emitted in address order, so a prefix is not a sample.

## Phase 6 — the runtime and HLE (in progress)

- [x] CPU state, memory, semantic helpers (landed with phase 5)
- [x] **NID resolution against the MIT `vita-headers` database** — 519 of 524
      imports resolved (99.0%) from 9,274 known functions
- [x] The HLE work list sized and shaped: see [`HLE.md`](HLE.md)
- [x] **Bind imports.** A call to a stub emits `vita_hle_sceGxmDraw()` rather
      than `vita_func_814BB75C()`, and a generated companion file gives every
      import a default that traps by name — so the output links from the first
      build and each firmware call announces itself
- [x] **Route indirect transfers through the import table.** Imports bound on
      a direct `BL`, but `module_start` reaches its first firmware call
      *through a pointer*, so that path never saw it. Stubs are now merged into
      the same sorted dispatch table as functions (19,644 entries: 19,120 + 524)
      rather than getting a second lookup. `vita_dispatch_init` refuses an
      unsorted table, since an unsorted one silently fails to find entries that
      are present — indistinguishable from missing coverage
- [x] **Traps name the firmware function**, not just its NID. A NID is a hash;
      "implement 0xBFE02B3A" is not a task anyone can start
- [ ] The shallow ~92 of `SceGxm`: state setters, texture accessors, mapping
- [ ] `SceLibc` / `SceLibm` (96 functions), largely host-forwardable
- [ ] `sceKernel` — threads, memory blocks, sync primitives
- [ ] GXP reflection, then the scene pipeline
- [ ] GXP shader translation — a compiler, and the largest single piece

**Measured, not estimated:** `SceGxm` is 107 functions, but ~85 of them are
struct field writes. The real work is ~15 functions, one of which is a shader
compiler. Deferring the online-only libraries takes the whole target from 524 to
roughly 412.

## Per-title repos

The toolkit is the product; a game brought up on it lives in its own repo
consuming this one as a submodule. Selection criteria, now that phase 1 has
established what the input path actually is:

1. **A QA/prototype build exists** — plaintext segments, no keys, no PFS.
2. **Small `.text`** — less to reach 100% decode coverage on.
3. **2D** — `sceGxm` is the deepest part of phase 6; a title that leans on it
   lightly gets to "runs" sooner.
4. **Low NEON density** — measurable with `cover` before committing.
