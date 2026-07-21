/* nids.c — a line-based reader for the vita-headers NID database.
 *
 * The format is regular enough that a YAML library would be a dependency bought
 * for nothing: two-space indentation, one `key: value` per line, and the only
 * structure that matters is which indent level a line sits at.
 *
 *   modules:
 *     SceGxm:                        <- 4 spaces, module
 *       libraries:
 *         SceGxm:                    <- 8 spaces, library
 *           nid: 0xF76B66BD
 *           functions:
 *             sceGxmBeginScene: 0x8734FF4E   <- 12 spaces, function
 *
 * Parsing by indent means a file that does not match the expected shape yields
 * nothing rather than nonsense, which is the right failure for a lookup table.
 */

#include "nids.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <dirent.h>
#endif

typedef struct {
    uint32_t lib_nid;
    uint32_t func_nid;
    char     name[64];
} nid_entry;

typedef struct {
    uint32_t lib_nid;
    char     name[64];
} lib_entry;

struct nid_db {
    nid_entry *funcs;
    size_t     nfuncs, cfuncs;
    lib_entry *libs;
    size_t     nlibs, clibs;
};

static void add_func(nid_db *db, uint32_t lib, uint32_t fn, const char *name) {
    if (db->nfuncs == db->cfuncs) {
        db->cfuncs = db->cfuncs ? db->cfuncs * 2 : 4096;
        db->funcs = (nid_entry *)realloc(db->funcs, db->cfuncs * sizeof(nid_entry));
    }
    nid_entry *e = &db->funcs[db->nfuncs++];
    e->lib_nid = lib;
    e->func_nid = fn;
    snprintf(e->name, sizeof(e->name), "%s", name);
}

static void add_lib(nid_db *db, uint32_t lib, const char *name) {
    for (size_t i = 0; i < db->nlibs; i++)
        if (db->libs[i].lib_nid == lib) return;
    if (db->nlibs == db->clibs) {
        db->clibs = db->clibs ? db->clibs * 2 : 256;
        db->libs = (lib_entry *)realloc(db->libs, db->clibs * sizeof(lib_entry));
    }
    lib_entry *e = &db->libs[db->nlibs++];
    e->lib_nid = lib;
    snprintf(e->name, sizeof(e->name), "%s", name);
}

/* Count leading spaces, which is the only structural signal in the file. */
static int indent_of(const char *s) {
    int n = 0;
    while (s[n] == ' ') n++;
    return n;
}

/* Split "  key: value" into key and value, both trimmed. Returns 0 if the line
 * is blank, a comment, or has no colon. */
static int split_kv(char *line, char **key, char **val) {
    char *p = line;
    while (*p == ' ') p++;
    if (*p == '\0' || *p == '#' || *p == '\n' || *p == '\r') return 0;

    char *colon = strchr(p, ':');
    if (!colon) return 0;
    *colon = '\0';

    char *v = colon + 1;
    while (*v == ' ') v++;
    char *end = v + strlen(v);
    while (end > v && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ')) *--end = '\0';

    *key = p;
    *val = v;
    return 1;
}

static void parse_file(nid_db *db, const char *path, int *entries) {
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[512];
    char cur_lib_name[64] = {0};
    uint32_t cur_lib_nid = 0;
    int in_functions = 0;
    int lib_indent = -1;

    while (fgets(line, sizeof(line), f)) {
        int ind = indent_of(line);
        char *key, *val;
        if (!split_kv(line, &key, &val)) continue;

        /* A library header: an indented name with no value, sitting under
         * `libraries:`. Its own nid arrives on a following line. */
        if (val[0] == '\0') {
            if (strcmp(key, "libraries") == 0) { lib_indent = ind + 2; continue; }
            if (strcmp(key, "functions") == 0) { in_functions = 1; continue; }
            if (lib_indent >= 0 && ind == lib_indent) {
                snprintf(cur_lib_name, sizeof(cur_lib_name), "%s", key);
                cur_lib_nid = 0;
                in_functions = 0;
            }
            continue;
        }

        if (!in_functions && strcmp(key, "nid") == 0 && cur_lib_name[0]) {
            cur_lib_nid = (uint32_t)strtoul(val, NULL, 0);
            if (cur_lib_nid) add_lib(db, cur_lib_nid, cur_lib_name);
            continue;
        }

        if (in_functions && cur_lib_nid) {
            uint32_t fn = (uint32_t)strtoul(val, NULL, 0);
            if (fn) { add_func(db, cur_lib_nid, fn, key); (*entries)++; }
        }
    }

    fclose(f);
}

nid_db *nid_db_load(const char *dir, int *files_loaded, int *entries_loaded) {
    nid_db *db = (nid_db *)calloc(1, sizeof(nid_db));
    if (!db) return NULL;

    int files = 0, entries = 0;
    char path[1024];

#ifdef _WIN32
    snprintf(path, sizeof(path), "%s\\*.yml", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(path, &fd);
    if (h == INVALID_HANDLE_VALUE) { free(db); return NULL; }
    do {
        snprintf(path, sizeof(path), "%s\\%s", dir, fd.cFileName);
        parse_file(db, path, &entries);
        files++;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(dir);
    if (!d) { free(db); return NULL; }
    struct dirent *de;
    while ((de = readdir(d))) {
        size_t n = strlen(de->d_name);
        if (n < 5 || strcmp(de->d_name + n - 4, ".yml") != 0) continue;
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        parse_file(db, path, &entries);
        files++;
    }
    closedir(d);
#endif

    if (files_loaded)   *files_loaded = files;
    if (entries_loaded) *entries_loaded = entries;
    return db;
}

void nid_db_free(nid_db *db) {
    if (!db) return;
    free(db->funcs);
    free(db->libs);
    free(db);
}

const char *nid_func_name(const nid_db *db, uint32_t lib_nid, uint32_t func_nid) {
    if (!db) return NULL;
    for (size_t i = 0; i < db->nfuncs; i++)
        if (db->funcs[i].func_nid == func_nid && db->funcs[i].lib_nid == lib_nid)
            return db->funcs[i].name;
    /* A NID is a hash of the name alone, so the same function exported by more
     * than one library keeps the same NID. Falling back to a library-agnostic
     * match resolves those rather than reporting them unknown. */
    for (size_t i = 0; i < db->nfuncs; i++)
        if (db->funcs[i].func_nid == func_nid) return db->funcs[i].name;
    return NULL;
}

const char *nid_lib_name(const nid_db *db, uint32_t lib_nid) {
    if (!db) return NULL;
    for (size_t i = 0; i < db->nlibs; i++)
        if (db->libs[i].lib_nid == lib_nid) return db->libs[i].name;
    return NULL;
}
