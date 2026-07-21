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
The corpus needs no decryption. See [`docs/DECRYPT.md`](docs/DECRYPT.md).

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

## Phase 4 — function discovery

- [ ] Recursive descent from the entry point and the module's export table
- [ ] Linear harvest of `BL` targets
- [ ] `SCE_RELA` relocation seeding — the principled way to recover stored
      function pointers (callbacks, vtables, thread entries) that no
      control-flow scan can see
- [ ] Jump-table recognition
- [ ] `armrecomp funcs` — the import list, which *is* the HLE work list

## Phase 5 — the emitter

- [ ] ARM → readable C, one function at a time, with the disassembly as comments
- [ ] Conditional execution and flag semantics (ARM's `NZCV` is far more
      pervasive than MIPS's compare-and-branch; getting carry/overflow wrong is
      the class of bug that surfaces only in arithmetic-heavy code)
- [ ] Anything untranslated emits a **named run-time trap**, never silence
- [ ] Verify: generated C compiles, links against the runtime, and runs

## Phase 6 — the runtime and HLE

- [ ] CPU state, memory, semantic helpers
- [ ] `sceKernel` — threads, memory blocks, sync primitives
- [ ] `sceGxm` — the hard one. A programmable pipeline, mapped onto a host
      graphics API rather than reimplemented as a fixed-function display list.
- [ ] `sceCtrl`, `sceDisplay`, `sceAudio`
- [ ] NID resolution against the MIT `vita-headers` database

## Per-title repos

The toolkit is the product; a game brought up on it lives in its own repo
consuming this one as a submodule. Selection criteria, now that phase 1 has
established what the input path actually is:

1. **A QA/prototype build exists** — plaintext segments, no keys, no PFS.
2. **Small `.text`** — less to reach 100% decode coverage on.
3. **2D** — `sceGxm` is the deepest part of phase 6; a title that leans on it
   lightly gets to "runs" sooner.
4. **Low NEON density** — measurable with `cover` before committing.
