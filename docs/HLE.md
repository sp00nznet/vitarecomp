# The HLE layer — measured, not estimated

The firmware surface a module needs is not a matter of opinion: the module's own
import table names every function it calls, and the MIT
[vita-headers](https://github.com/vitasdk/vita-headers) NID database turns those
hashes back into names.

```
$ armrecomp funcs uncharted.elf path/to/vita-headers/db/360
nid db:   154 files, 9274 functions
module:   cardgame
firmware libraries needed (524 functions across 39 libraries):
...
resolved 519 of 524 imported functions (99.0%)
```

**519 of 524 resolved.** That is the HLE work list, derived rather than guessed.

## Why the database is loaded, not vendored

`vita-headers` is MIT, so bundling it would be permitted. It is loaded from a
directory at run time anyway, because it is *data*: the toolkit stays free of
third-party source, a newer database needs no rebuild, and a module targeting a
different firmware needs a different directory rather than a different binary.

## SceGxm is 107 functions, and that number is misleading

`SceGxm` is the largest single import — over a fifth of everything. But the
count flattens together work that differs by orders of magnitude:

| Group | Count | Depth |
|---|---:|---|
| State setters (`sceGxmSet*`) | 28 | Struct writes |
| Texture accessors (`sceGxmTexture*`) | 20 | Struct field get/set |
| Shader & program | 23 | **Mixed — see below** |
| Render target / colour surface / depth-stencil | 14 | Struct init and bind |
| Memory mapping | 7 | Map guest pages GPU-visible |
| Sync / display | 6 | Fences and flip |
| Scene, draw, context, lifecycle | 9 | **The pipeline itself** |

Roughly **85 of the 107 are shallow** — they write a field in a structure the
driver later reads. They need care about layout and nothing else.

The real work is in two places.

### 1. GXP shader translation

```
sceGxmShaderPatcherCreateVertexProgram
sceGxmShaderPatcherCreateFragmentProgram
sceGxmShaderPatcherRegisterProgram
sceGxmShaderPatcherGetProgramFromId
```

These consume **GXP**, Sony's compiled shader container, and must produce
something a host GPU will execute. That is a compiler, and it is the single
largest piece of work in the project — Vita3K's equivalent took years.

### 2. GXP reflection

```
sceGxmProgramFindParameterByName        sceGxmProgramParameterGetCategory
sceGxmProgramParameterGetType           sceGxmProgramParameterGetComponentCount
sceGxmProgramParameterGetArraySize      sceGxmProgramParameterGetResourceIndex
sceGxmProgramGetDefaultUniformBufferSize
```

The game asks the driver about its own shaders — where a uniform lives, what
type it is, how big the default buffer is. This needs the GXP container parsed
but not translated, so it is bounded and mechanical once the format is mapped.

### 3. The pipeline

`sceGxmInitialize`, `sceGxmCreateContext`, `sceGxmBeginScene`, `sceGxmDraw`,
`sceGxmDrawInstanced`, `sceGxmEndScene`, `sceGxmMidSceneFlush`. The Vita is a
tile-based deferred renderer, and scene semantics are where that shows: what is
resolved when, and what a mid-scene flush guarantees.

**So the honest shape is ~15 functions of real work, one of which is a compiler
project, and ~92 that are shallow.**

## Why this is written rather than borrowed

Vita3K is **GPLv2** — confirmed from its own README, which says the choice is
*"largely dictated by external dependencies, most notably Unicorn"*. Unicorn is
a CPU emulator: precisely the component a static recompiler exists to replace.
The licence is therefore downstream of a part this project would never touch,
but that gives no relicensing room, because contributors licensed their work
into the GPLv2 whole.

There is no LGPL escape here. The approach that works for
[`xboxrecomp`](https://github.com/sp00nznet/xboxrecomp) — extracting
LGPL-2.1 components from xemu, which the LGPL expressly permits linking into MIT
code — depends on **QEMU deliberately dual-tracking its hardware model under
LGPL** so it can be embedded. xemu inherits that. Vita3K has no equivalent, and
nothing in it is offered under LGPL.

What does carry over is the rest of that arrangement, unchanged:

| Tier | Applies here? |
|---|---|
| LGPL components, linked | **No** — none exist for Vita |
| Independently implemented algorithms, credited | **Yes** |
| Functional facts: NIDs, struct layouts, enum values, register semantics | **Yes** |

That last row is not a consolation prize. Structure layouts, GXP container
format, enum values and calling conventions are functional facts rather than
expression, and they are most of what the shallow 92 functions need.

Vita3K stays what it has been throughout: a **behavioural oracle**, run as a
separate process and compared against. No code copied, linked, or vendored.

## Order of work

1. **Bind imports.** Route recompiled calls into a NID-keyed dispatch table, so
   an unimplemented import is a named trap rather than an unresolved symbol.
2. **The shallow 92.** State setters, texture accessors, memory mapping — bulk
   but not depth.
3. **`SceLibc` / `SceLibm` (96 functions).** Largely forwardable to the host C
   library.
4. **GXP reflection.** Bounded once the container format is mapped.
5. **The pipeline.** `BeginScene`/`Draw`/`EndScene` against a host graphics API.
6. **GXP shader translation.** The compiler. Last, because everything above can
   be built and tested against a stub that returns a fixed shader.

## What a single-player bring-up does not need

`SceNet`, `SceNpMatching2`, `SceHttp`, `SceNpBasic`, `SceNpScore`, `SceNetCtl`,
`SceNpUtility`, `SceNpMessage`, `SceNpManager`, `SceNpTrophy` — **112 functions
that exist only for online play and trophies.** Deferring them takes the target
from 524 to roughly 412, and is the same call `psprecomp` made about WTF's
ad-hoc networking path.
