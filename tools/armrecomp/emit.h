/* emit.h — turning discovered functions into C. */

#ifndef ARMRECOMP_EMIT_H
#define ARMRECOMP_EMIT_H

#include "analyze.h"
#include "nids.h"

#include <stdio.h>

/* What is still trapping, by kind.
 *
 * "31% untranslated" is not actionable; "MOVT is 40% of what is left" is. This
 * table is what turns the question of where to spend effort next from a guess
 * into a ranked list — and it is how MOVT was found to be worth far more than
 * its instruction count suggested. */
#define EM_MAX_TRAP_KINDS 64

typedef struct {
    const char *what;      /* mnemonic, or the class when unnamed */
    uint32_t    count;
} em_trap_kind;

typedef struct {
    uint32_t funcs;
    uint32_t insns;
    uint32_t translated;   /* emitted as real C            */
    uint32_t trapped;      /* emitted as a named trap      */
    uint32_t literals;     /* literal-pool loads folded to constants */
    uint32_t import_calls; /* call sites bound to a firmware import  */
    uint32_t imports_used; /* distinct imports actually reached      */

    /* Addresses discovery registered as functions that are really import
     * stubs. The stub wins in the dispatch table; this counts how often
     * discovery walked into the import table and believed what it found. */
    uint32_t stub_shadowed;

    em_trap_kind traps[EM_MAX_TRAP_KINDS];
    uint32_t     trap_kinds;
    uint32_t     traps_other;   /* beyond the table's capacity */
} emit_stats;

/* Emit discovered functions to `out`. `limit` caps the number emitted (0 for
 * all), which matters for bring-up: 19k functions is 133 MB of C, and getting
 * a few hundred to compile and link proves the translation is valid C long
 * before the whole module is worth building. */
int em_emit(const vm_image *img, const vm_module *mod, const nid_db *db,
            const vf_result *disc, FILE *out, FILE *imports,
            uint32_t limit, emit_stats *st);

#endif /* ARMRECOMP_EMIT_H */
