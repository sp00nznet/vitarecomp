# Encryption — and the corpus that does not need it

Every Vita executable is wrapped in a `SCE\0` SELF container. The question that
decides this project's shape is not *whether* SELF supports encryption — it does
— but **which modules actually use it**, and that turns out to be a question you
can answer with no key material at all, because the segment table is plaintext.

## The three layers

```
  .vpk / dump directory
        │
        ├── sce_pfs/          ← PFS layer, if present (retail NoNpDrm dumps)
        │                       encrypted with a per-title klicensee
        │
        └── eboot.bin         ← SELF container
                 │              header, appinfo, ELF header, program headers
                 │              and segment table are ALL PLAINTEXT
                 │
                 └── segments  ← optionally zlib-compressed
                                 optionally encrypted
```

The middle column is the important one. In a SELF, only segment *contents* can
be encrypted. Everything describing them is in the clear, so `armrecomp info`
can report exactly what a module is and what stands between it and the decoder
without touching a key.

## The measurement

`armrecomp info` on a QA build of *Titan Souls* (2015-04-01):

```
segment encryption:
  0   1501685    bytes  zlib      plain
  1   4707       bytes  zlib      plain
  2   166184     bytes  zlib      plain
  3   2674       bytes  zlib      plain
  4   422        bytes  zlib      plain

no encrypted segments — this module can go straight to the decoder.
```

**Every segment is plaintext.** They are only zlib-compressed.

That is a large enough claim to deserve an independent check, because a parser
that reads the encryption flag backwards would report exactly this for a fully
encrypted module. Two landmarks confirm it:

1. **Every segment begins `78 9c`** — the zlib header for default compression.
   Five independent offsets landing on valid zlib magic is not something
   ciphertext does.
2. **Offset `0x1000` holds a plaintext ELF header**, whose `e_entry` of
   `0x002B36E8` matches the value the parser read independently from the
   plaintext ELF header at `0xA0`.

The flag encoding reads backwards, which is worth stating plainly because it is
the obvious place to introduce this bug:

| Field | `1` | `2` |
|---|---|---|
| `compression` | stored | **zlib** |
| `encryption` | **encrypted** | **plain** |

`encryption == 2` means *not encrypted*. A parser that assumes `1 == true`
reports every retail module as plaintext and hands random bytes to the decoder.

## A correction worth recording

The SELF header layout this parser was first built against was the **PS3** one,
which is widely published and looks authoritative. Vita's differs: it inserts
`self_filesize` and a padding qword at `0x20`, shifting every field after it by
`0x10`.

Under the PS3 layout, `elf_offset` is read from `0x30` — which on a real Vita
module contains `4`. Not a garbage value, not an obviously wrong one: a small
plausible offset that looks like a real answer. The parse then failed on ELF
magic, but it could just as easily have found something and reported it.

What caught it was that the ELF header is **independently locatable**: scanning
the file for `7F 45 4C 46` finds it at `0xA0`, which is the field at `0x40`.
Structure that can be cross-checked against a landmark in the file is worth more
than structure that merely parses.

The synthetic unit test did not catch this, and could not have — it was built
from the same wrong layout as the parser, so it agreed with the bug and passed.
That is the general limit of synthetic tests on a reverse-engineered format, and
the reason a real module is in the loop from phase 1.

## What this means for the project

**The QA and prototype corpus needs no decryption at all.** This is the same
result [`psprecomp`](https://github.com/sp00nznet/psprecomp) found on PSP
prototype and test-sample discs, and it has the same consequence: the entire
pipeline — parse, decode, discover, emit, compile, link — can be built and
validated end to end without any key material entering the picture.

Retail is a different matter, and honestly so:

| Source | Container | Needs |
|---|---|---|
| QA / prototype builds | SELF, **plaintext segments** | nothing — zlib inflate only |
| Retail NoNpDrm dumps | PFS + SELF | a per-title klicensee from the dumping console |
| Sony system modules (`*.suprx`) | SELF | firmware keys |

A NoNpDrm eboot is ciphertext from byte zero — no magic, nothing to parse. It is
refused by name rather than parsed into plausible garbage:

```
$ armrecomp info eboot.bin
format:   unknown

error:    unrecognised container (no SCE\0 or ELF magic) — if this came from a
          NoNpDrm dump it is PFS-encrypted; see docs/DECRYPT.md
```

## Keys are never bundled

**No key material is distributed with this toolkit**, and none is derived by it.

This is not merely a licensing preference. The PSP's KIRK constants are fixed
values that have been public since the console's active life, so `psprecomp` can
reasonably treat "the user supplies keys" as one-time setup. The Vita's retail
PFS layer is different in kind: it needs a **per-title klicensee derived from the
console that produced the dump**. There is no fixed constant to supply.

So for retail content the external-tool route is not a temporary unblock the way
`pspdecrypt` is for PSP — it is structural, and it stays outside this repo.

What `vitarecomp` will implement in-house, following the `psprecomp` pattern
exactly:

- [x] Plaintext container parsing — SCE header, appinfo, ELF, program headers,
      segment table. **Done**, and validated against a real module.
- [ ] zlib inflate for plaintext-but-compressed segments. This is the only thing
      standing between the QA corpus and the decoder, and it is a dependency,
      not a research problem.
- [ ] Segment reassembly into a valid ELF32 from the plaintext program headers.
- [ ] `.sce_module_info` parsing and NID import/export resolution against the
      MIT-licensed [`vita-headers`](https://github.com/vitasdk/vita-headers)
      database.

What it will not implement: key derivation, key extraction, or the PFS layer.

## How we will know it worked

Decryption and decompression can both appear to succeed and produce plausible
garbage, so the check is layered — each step catches something the previous one
might not:

1. **Declared size.** The reassembled ELF must be exactly `elf_filesize` bytes,
   the value the plaintext SCE header declares.
2. **It parses.** The phase-1 ELF parser must accept it, with a sane `e_type`
   (`ET_EXEC` or `ET_SCE_RELEXEC`) and at least one `PT_LOAD`.
3. **The entry point lands in code.** `e_entry` must fall inside a `PF_X`
   segment.
4. **The opcode histogram is code-shaped.** Random bytes decode as ARM at a
   surprisingly high rate, but they produce a *flat* histogram; real compiled
   code does not. This is the check that catches subtly-wrong output.
5. **Cross-check.** The same module processed by an independent implementation
   must be byte-identical.
