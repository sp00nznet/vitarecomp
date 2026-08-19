# The corpus

Fifteen measured modules, what they establish about the input path, and why the
launch-window catalogue is the hard case rather than the easy one.

## QA builds are not encrypted

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
see [`DECRYPT.md`](DECRYPT.md).

## Reassembly is checkable, not merely plausible

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

