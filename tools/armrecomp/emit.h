/* emit.h — turning discovered functions into C. */

#ifndef ARMRECOMP_EMIT_H
#define ARMRECOMP_EMIT_H

#include "analyze.h"

#include <stdio.h>

typedef struct {
    uint32_t funcs;
    uint32_t insns;
    uint32_t translated;   /* emitted as real C            */
    uint32_t trapped;      /* emitted as a named trap      */
    uint32_t literals;     /* literal-pool loads folded to constants */
} emit_stats;

/* Emit discovered functions to `out`. `limit` caps the number emitted (0 for
 * all), which matters for bring-up: 19k functions is 133 MB of C, and getting
 * a few hundred to compile and link proves the translation is valid C long
 * before the whole module is worth building. */
int em_emit(const vm_image *img, const vm_module *mod, const vf_result *disc,
            FILE *out, uint32_t limit, emit_stats *st);

#endif /* ARMRECOMP_EMIT_H */
