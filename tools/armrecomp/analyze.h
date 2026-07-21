/* analyze.h — function discovery.
 *
 * Recursive descent from seeds, carrying instruction-set state. Mode is the
 * part with no PSP analogue: a seed is worthless without knowing whether its
 * target is ARM or Thumb, and decoding a Thumb function as ARM produces
 * plausible instructions rather than an obvious failure.
 *
 * Where the seeds come from, in increasing order of what they find:
 *
 *   1. module_start, from .sce_module_info
 *   2. the export entry table
 *   3. a linear harvest of BL/BLX targets
 *   4. pointer-shape recovery for stored function pointers
 *
 * Step 4 is a HEURISTIC and is reported separately for that reason. On
 * ET_SCE_RELEXEC modules the relocations enumerate stored pointers exactly; on
 * ET_SCE_EXEC modules — which is every Vita launch-window title, and therefore
 * every exclusive worth recompiling — there are no relocations and shape is all
 * there is.
 */

#ifndef ARMRECOMP_ANALYZE_H
#define ARMRECOMP_ANALYZE_H

#include "decode.h"
#include "module.h"

typedef struct {
    uint32_t addr;          /* virtual address                      */
    arm_mode mode;
    uint32_t end;           /* highest address reached from here    */
    uint32_t insns;
    uint8_t  from_heuristic;
} vf_func;

typedef struct {
    vf_func *funcs;
    uint32_t count;
    uint32_t cap;

    uint8_t *seen;          /* one bit per 2 bytes: instruction start  */
    uint32_t seen_bytes;

    uint32_t insns_total;   /* instructions reached                    */
    uint32_t bytes_covered;
    uint32_t seeds_entry;
    uint32_t seeds_export;
    uint32_t seeds_call;
    uint32_t seeds_shape;
    uint32_t rejected_shape;
    uint32_t simd_insns;
    uint32_t indirect_sites;
} vf_result;

/* Discover functions in the image's executable segment. Returns 0 on success.
 * The caller frees with vf_free(). */
int vf_discover(const vm_image *img, const vm_module *mod, vf_result *out);

void vf_free(vf_result *r);

#endif /* ARMRECOMP_ANALYZE_H */
