/* nids.h — resolving import NIDs to function names.
 *
 * A Vita module imports firmware functions by NID: the first four bytes of the
 * SHA-1 of the function's name. The hash is one-way, so the names come from the
 * community's published database rather than from the binary.
 *
 * The database is vita-headers (MIT), which makes it usable here without any
 * of the licence tension that surrounds Vita3K. It is a data file, not code —
 * loaded at run time from a directory, never compiled in — so the toolkit
 * carries no third-party source and a newer database needs no rebuild.
 *
 * Without this, `funcs` can only report that a module needs 107 functions from
 * library 0xF76B66BD. With it, it reports which 107, which is the difference
 * between knowing the size of the HLE job and knowing its shape.
 */

#ifndef ARMRECOMP_NIDS_H
#define ARMRECOMP_NIDS_H

#include <stddef.h>
#include <stdint.h>

typedef struct nid_db nid_db;

/* Load every *.yml in `dir`. Returns NULL if the directory cannot be read;
 * a partially parsed database is still returned, because a missing name is a
 * cosmetic loss and refusing to run over it would be worse. */
nid_db *nid_db_load(const char *dir, int *files_loaded, int *entries_loaded);
void    nid_db_free(nid_db *db);

/* Both return NULL when unknown, never a placeholder — an unresolved NID must
 * look unresolved. */
const char *nid_func_name(const nid_db *db, uint32_t lib_nid, uint32_t func_nid);
const char *nid_lib_name (const nid_db *db, uint32_t lib_nid);

#endif /* ARMRECOMP_NIDS_H */
