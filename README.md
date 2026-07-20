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

**Not started:** the ARMv7/Thumb-2 decoder, function discovery, the C emitter,
the HLE layer. This is phase 1 of six.

## The finding that shapes the project: QA builds are not encrypted

Every Vita executable is wrapped in a SELF container that *supports* encryption.
The question that matters is which modules actually *use* it — and because the
segment table is plaintext, that is answerable with no key material at all.

Across a corpus of QA/prototype builds and app-bundled system modules, **every
segment is plaintext**, zlib-compressed only:

| Module | Size | `.text` | Entry | `e_type` | Encrypted |
|---|---:|---:|---|---|---:|
| Uncharted: Fight for Fortune (2012-11-01) | 2,871,472 | 5,656,372 | `0x004BA470` | `SCE_EXEC` | **0** |
| Titan Souls (2015-04-01) | 1,680,560 | 3,053,164 | `0x002B36E8` | `SCE_RELEXEC` | **0** |
| Shovel Knight (2015-04-08) | 2,306,752 | 3,582,384 | `0x00306030` | `SCE_RELEXEC` | **0** |
| Super Blackout (2015-07-26) | 1,571,696 | — | `0x00209488` | `SCE_RELEXEC` | **0** |
| Super Meat Boy (2015-09-18) | 945,600 | — | `0x0014A1F4` | `SCE_RELEXEC` | **0** |
| Volume (2015-12-09) | 17,110,432 | — | `0x025D0660` | `SCE_RELEXEC` | **0** |
| `libc.suprx` | 202,560 | 326,740 | `0x0003B4F8` | `SCE_RELEXEC` | **0** |
| `libfios2.suprx` | 116,928 | — | `0x00022878` | `SCE_RELEXEC` | **0** |

### Static vs relocatable is the split that matters

`e_type` is not cosmetic. `ET_SCE_RELEXEC` modules carry `PT_SCE_RELA`
segments, and a relocation naming a word that holds an address **is** a stored
function pointer — thread entries, callbacks, vtables. Mining them is
enumeration, not guesswork, and on PSP it moved coverage from 75% to 89%.

`ET_SCE_EXEC` modules are statically linked: absolute addresses need no
patching, so there are no relocations to mine. Uncharted: Fight for Fortune is
the only module measured so far that is static — it has **no `SCE_RELA`
segments at all**, where every other module has two. Recovering its function
pointers falls back to recognising them by shape (in range, instruction-aligned,
decodes as an instruction), which is a heuristic and is kept labelled as one.

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

## Documentation

- [`docs/DECRYPT.md`](docs/DECRYPT.md) — the SELF container, what is encrypted
  and what is not, and why the QA corpus needs no keys.
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
