# vitarecomp

### *The Vita has one good emulator. It has no static recompiler.*

> Static recompilation toolkit for PlayStation Vita titles.
> Turn ARM into native C. No emulator required, no keys required.

---

## What Is This?

**vitarecomp** is an open-source toolkit that provides the analysis tools,
recompiler, and runtime needed to **statically recompile PlayStation Vita games
into native executables**.

Instead of interpreting or dynamically recompiling ARM instructions at runtime
(what Vita3K does), we take the opposite approach: **translate everything ahead
of time** into C that compiles with any modern compiler on any modern platform.

This is the same philosophy behind:
- [N64Recomp](https://github.com/N64Recomp/N64Recomp) (N64 → native)
- [UnleashedRecomp](https://github.com/hedge-dev/UnleashedRecomp) (Xbox 360 → native)
- [ps3recomp](https://github.com/sp00nznet/ps3recomp) (PS3 → native)
- [psprecomp](https://github.com/sp00nznet/psprecomp) (PSP → native)

`vitarecomp` is the reusable toolkit. Games brought up on it live in separate
repos that consume this one as a submodule — that split is deliberate: the
toolkit is the thing other people fork to recompile *their* Vita game.

> **No game data here.** Dumps, `eboot.bin`, `.suprx` modules, VPKs and any key
> material are all `.gitignore`d. This repo is the recompiler, the runtime, and
> docs — bring your own dump.

## Why Vita?

The Vita is a better target than its reputation suggests:

- **One documented CPU.** A quad-core ARM Cortex-A9 running ARMv7-A. ARM is the
  most widely documented architecture there is, and unlike the PSP's Allegrex it
  has no vendor-specific opcode divergences to rediscover.
- **A documented OS boundary.** Games call `sceKernel*` / `sceGxm*` / `sceCtrl*`
  by NID through a module import table. That is a *library* surface, not a
  hardware surface, which means it can be implemented as HLE C rather than
  emulated — and the NID→name mapping is published and MIT-licensed.
- **A corpus that needs no decryption.** Every segment of every QA/prototype
  build measured so far is plaintext, zlib-compressed only. The whole pipeline
  can be built and validated with no key material entering the picture. See
  [docs/CORPUS.md](docs/CORPUS.md).

## The Challenge

| Component | What It Is | Why It's Hard |
|-----------|-----------|---------------|
| **Cortex-A9** | ARMv7-A, Thumb-2 dominant | Two instruction sets interleaved; one bad width desynchronises every instruction after it |
| **NEON** | 128-bit SIMD | The only genuinely hard piece left — but 0.63% of instructions once scalar VFP is handled, not the wall its reputation suggests |
| **SELF container** | SCE-wrapped ELF | Not the PS3 layout; every field after `0x20` is shifted by `0x10` |
| **`.sce_module_info`** | Module metadata | `e_entry` points *at this structure*, not at code — and it mixes segment-relative with absolute addressing |
| **`sceGxm`** | The GPU API | 107 imported functions, one of which is a shader compiler |
| **`ET_SCE_EXEC`** | Statically linked modules | No relocations to mine, so function-pointer recovery is heuristic — and this is the entire launch window |

## Architecture

```
include/vitarecomp/   runtime API — cpu, mem, dispatch, vfp, loader
src/                  runtime — CPU state, memory, semantic helpers, traps
tools/armrecomp/      the toolkit:
                        container.c  SELF / ELF / velf parsing
                        inflate.c    DEFLATE + zlib, written not vendored
                        decode.c     ARMv7-A + Thumb-2 decoder
                        module.c     .sce_module_info, import/export tables
                        analyze.c    function discovery
                        nids.c       NID → name against vita-headers
                        emit.c       ARM → C
tests/                ctest — synthetic, no game data
docs/                 the detail
```

## How It Works

```
  dump / .vpk ──► armrecomp ──► eboot.bin / *.suprx      peel the container
                  (zip · dir)    (a SCE\0-wrapped ELF)    stack down to a module
                      │
                      ▼
              ┌────────────────────┐   segment table is PLAINTEXT; segments are
              │  inflate           │   zlib. QA builds need no keys at all.
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

Stage-by-stage detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Status

**Phases 1–5 complete, phase 6 (HLE) in progress.** The full pipeline runs end
to end — SELF → ELF → decode → discover → emit → compile → link → run — with no
key material anywhere in it.

| Phase | What | Status |
|---|---|---|
| **1 — Container stack** | SCE/SELF, appinfo, ELF32, program headers, segment table; bounds-checked, named refusal for PFS retail dumps, encryption flag cross-checked against zlib headers | ✅ Complete |
| **2 — Inflate & reassemble** | DEFLATE + zlib written not vendored; **15/15 corpus modules extract and round-trip**, 236 KB → 53 MB | ✅ Complete |
| **3 — Decoder** | ARMv7-A + Thumb-2, width determination, control flow, IT blocks, NEON/VFP classed; `armrecomp cover` over 16 modules | ✅ Complete |
| **4 — Discovery** | `.sce_module_info`, import/export tables, recursive descent carrying mode state, pointer-shape recovery over **both code and data** segments, with pointer tables read as tables; 20,989 functions | ✅ Complete |
| **5 — Emitter** | ARM → readable C, literal folding, run-time dispatch, scalar VFP, wide branches. **Generated C compiles, links, and runs** | ✅ Complete |
| **6 — Runtime & HLE** | Runtime landed; NID resolution 519/524 (99.0%); imports bound so every firmware call traps *by name*. `sceGxm` / `sceKernel` / `SceLibc` bodies outstanding | 🔨 In progress |

**Translation rate on *Uncharted: Fight for Fortune*: 98.87% of instructions**,
measured over the whole module — all 20,989 discovered functions, 1,583,445
instructions. The rest emit named traps, never silence:

```
still trapping, by kind:
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

NEON is the largest remaining bucket at 0.63%, so about **99.4% is reachable
without touching the vector unit**. Breakdown in
[docs/TRANSLATION.md](docs/TRANSLATION.md).

The `sbfx`/`bfi` residue is deliberate: those 11 are extracts running off the
end of the register, which is UNPREDICTABLE and comes from a linear sweep over
literal pools. They trap rather than being clamped.

**Verified end to end at scale.** `emit` 1,500 functions → 15 MB of C →
compiles, links against the runtime, and runs. It loads the ELF's own segments
into guest memory, registers the dispatch table, calls `module_start`, and
reaches the C++ runtime init — where it stops on the first firmware function
the game actually wants:

```
vitarecomp: unimplemented firmware import SceLibc::__cxa_set_dso_handle_main
            at 0x814B9590 (NID 0xBFE02B3A)
```

That is the intended state for phase 6: the translation is done talking, and
what remains is HLE. Indirect transfers resolve through the same table as
direct ones — 19,644 entries for this module, 19,120 functions and 524 import
stubs merged and sorted — because a module reaches firmware through pointers as
well as through `BL`, and `module_start` makes its very first firmware call
that way.

## Documentation

| Document | What It Covers |
|----------|---------------|
| **[Architecture](docs/ARCHITECTURE.md)** | The pipeline stage by stage: container, inflate, decode, discovery, emit, runtime. Address conventions, indirect dispatch, import binding, and why each runtime helper exists |
| **[Translation](docs/TRANSLATION.md)** | Coverage figures, `ThumbExpandImm` and its traps, what is still trapping ranked by value, the NEON/VFP breakdown |
| **[Corpus](docs/CORPUS.md)** | The 15 measured modules, the plaintext finding, the `ET_SCE_EXEC` → `ET_SCE_RELEXEC` era split and why it makes the launch window the hard case |
| **[Decryption](docs/DECRYPT.md)** | The SELF container, what is encrypted and what is not, and why the QA corpus needs no keys |
| **[HLE](docs/HLE.md)** | The firmware surface, measured, and the order of work |
| **[Lessons](docs/LESSONS.md)** | Corrections and bugs found by running rather than reasoning: `MOVT`, the wrong dominant-instruction-set metric, the SIMD undercount, the PS3-layout SELF header |
| **[Roadmap](docs/ROADMAP.md)** | The six phases, checked off against what actually runs |

## Getting Started

> **Prerequisites**: CMake and a C compiler (MSVC on Windows; gcc/clang
> elsewhere). The core has **no external dependencies** — a fresh clone builds
> with nothing installed.

```powershell
git clone https://github.com/sp00nznet/vitarecomp.git
cd vitarecomp

cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release
# -> build/tools/armrecomp/Release/armrecomp.exe
# -> the vitarecomp runtime static library
```

```
armrecomp info     <file>                       identify a module, report its structure
armrecomp extract  <self> <out.elf>             SELF in, plain ELF32 out
armrecomp cover    <elf>                        coverage, class histogram, instruction set
armrecomp funcs    <elf> [nid-db]               the HLE work list, from the import table
armrecomp discover <elf>                        function discovery
armrecomp emit     <elf> <out.c> <n> [nid-db]   translate to C
```

`info` accepts a SELF (`eboot.bin`, `*.suprx`) or a plain ELF/velf. The optional
NID database is a path to
[vita-headers](https://github.com/vitasdk/vita-headers) `db/360` — **loaded at
run time, not vendored**: bundling it would be permitted, but it is data, and
keeping it external means the toolkit carries no third-party source and a newer
database needs no rebuild.

## Picking a Title

The toolkit is the product; a game brought up on it lives in its own repo
consuming this one as a submodule. Selection criteria, all measurable before
committing:

1. **A QA/prototype build exists** — plaintext segments, no keys, no PFS.
2. **Small `.text`** — less to reach full decode coverage on.
3. **2D** — `sceGxm` is the deepest part of phase 6; a title that leans on it
   lightly gets to "runs" sooner.
4. **Low NEON density** — `armrecomp cover` reports it.

| Title | Why | Status |
|---|---|---|
| ***Uncharted: Fight for Fortune*** (2012-11-01) | 5.6 MB `.text`, `ET_SCE_EXEC`, a turn-based card game — light on `sceGxm` | 20,989 functions emitted, **98.87% translated**, 524 imports bound, compiles and runs |

## Relationship to Other Projects

| Project | License | How it is used |
|---|---|---|
| [vita-headers](https://github.com/vitasdk/vita-headers) | MIT | The NID database — the published mapping from import NIDs to function names. The reference for the HLE work list. |
| [VitaSDK](https://github.com/vitasdk) | MIT | Headers and the published ABI for `sceGxm` / `sceKernel` / `sceCtrl`. |
| **[Vita3K](https://github.com/Vita3K/Vita3K)** | **GPLv2** | **Oracle only** — run as a separate process and compared against. No code copied, linked, or vendored. |
| [psprecomp](https://github.com/sp00nznet/psprecomp) | MIT | Sibling project for PSP. Same "`module_start` is not the program" shape, same oracle arrangement with PPSSPP. |
| [ps3recomp](https://github.com/sp00nznet/ps3recomp) | MIT | Sibling project for PS3. Same project structure and conventions. |

**Vita3K's license is the constraint that most shapes the runtime.** It is
GPLv2, so the usual "chop the emulator into a link library" move is not
available if the toolkit is to stay MIT — and the part you would most want from
it (the `sceGxm` and kernel HLE) is exactly the part you would be tempted to
vendor. There is no LGPL escape either: the arrangement that works for
[xboxrecomp](https://github.com/sp00nznet/xboxrecomp), extracting LGPL-2.1
components from xemu, depends on QEMU deliberately dual-tracking its hardware
model under LGPL so it can be embedded. Vita3K has no equivalent.

What does carry over is everything else — independently implemented algorithms
with credit, and functional facts (NIDs, struct layouts, enum values, calling
conventions) which are not copyrightable and are most of what the shallow work
needs.

*Licenses above are the working understanding and are re-checked before any code
or data from a project is actually used.*

## Contributing

The gaps are named and ranked, which makes them pick-up-able:

- **NEON** — ~1,300 instructions, the only genuinely hard piece left in the emitter
- **Branch-target promotion** — a discovery fix, 0.65%
- **`SceLibc` / `SceLibm`** — 72 of 96 left, largely host-forwardable
- **Data-segment pointer recovery** — 551 static constructors are invisible to
  discovery because shape recovery only scans the executable segment
- **`sceGxm`** — ~85 shallow state setters, then the scene pipeline
- **GXP shader translation** — a compiler, and the largest single piece
- **A true negative for the corpus** — a module known to be encrypted, that the
  parser correctly refuses

## Credits & References

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

## Legal

This project contains no proprietary Sony code, encryption keys, or copyrighted
material. It provides clean-room implementations of system library interfaces
based on publicly documented behaviour. Running a game requires a dump that
**you** own. Key derivation, key extraction, and the PFS layer are out of scope,
now and later.

## License

MIT — see [LICENSE](LICENSE). Independent, non-commercial preservation work; not
affiliated with or endorsed by Sony Interactive Entertainment.
