/* module.h — .sce_module_info, and the export/import tables it points at.
 *
 * e_entry does NOT point at code on Vita. It points at this structure, which
 * then names the real entry points and the module's export and import tables.
 * Treating e_entry as a code address puts the decoder in the middle of a string
 * table — on Uncharted: Fight for Fortune it lands on the module name
 * "cardgame" — and every function discovered from that seed is fiction.
 *
 * This is psprecomp's "module_start is not the program" in a sharper form: here
 * the ELF entry point is not even in .text.
 *
 * The import table is the reason this file matters beyond seeding discovery.
 * It names every firmware function the module calls, by library and NID, which
 * is the HLE work list derived rather than guessed at.
 */

#ifndef ARMRECOMP_MODULE_H
#define ARMRECOMP_MODULE_H

#include <stddef.h>
#include <stdint.h>

/* Offsets inside the module tables are relative to the segment base, not
 * absolute, so both bases are needed to resolve one. */
typedef struct {
    uint32_t file;            /* p_offset  */
    uint32_t vaddr;           /* p_vaddr   */
    uint32_t len;             /* p_filesz  */
} vm_seg;

#define VM_MAX_DATA_SEGS 8

typedef struct {
    const uint8_t *data;      /* the whole ELF file                     */
    size_t         size;
    uint32_t       seg_file;  /* p_offset of the executable segment     */
    uint32_t       seg_vaddr; /* p_vaddr of the executable segment      */
    uint32_t       seg_len;   /* p_filesz                               */

    /* The other PT_LOAD segments — the writable data the module ships with.
     *
     * These are for SCANNING ONLY, and are deliberately NOT reachable through
     * vm_va(). That is the whole point of keeping them in a separate list:
     * vm_va backs literal-pool folding, and folding a word out of writable
     * data would bake a value into the generated C that the program changes at
     * run time. Reading data here to find function POINTERS is safe in a way
     * that reading it for VALUES is not.
     *
     * They matter because the C++ static-constructor table lives here, not in
     * .text — so a discovery pass that only sweeps the executable segment
     * cannot see the first code the program runs. */
    vm_seg         data_segs[VM_MAX_DATA_SEGS];
    uint32_t       data_seg_count;
} vm_image;

typedef struct {
    uint16_t attributes;
    uint16_t version;         /* 0x0101                                 */
    char     name[28];
    uint8_t  type;
    uint32_t gp_value;
    uint32_t export_top, export_end;
    uint32_t import_top, import_end;
    uint32_t module_nid;
    uint32_t tls_start, tls_filesz, tls_memsz;
    uint32_t module_start, module_stop;
    uint32_t exidx_top, exidx_end;
    uint32_t extab_top, extab_end;
} vm_module_info;

/* One imported library, and the functions taken from it. */
typedef struct {
    uint32_t library_nid;
    char     name[64];
    uint16_t num_funcs;
    uint16_t num_vars;
    uint32_t func_nid_table;    /* segment-relative */
    uint32_t func_entry_table;
} vm_import;

/* One imported function, at the address the module actually calls.
 *
 * A module never calls firmware directly. It calls a STUB inside its own .text,
 * which the loader patches at load time to reach the real function. So the
 * recompiler sees an ordinary BL to an ordinary address, and the only way to
 * know that address means "SceGxmDraw" rather than "some function of ours" is
 * this table. Without it every firmware call looks like an internal call to a
 * function whose body is a placeholder the loader was supposed to overwrite. */
typedef struct {
    uint32_t addr;        /* stub address in .text, Thumb bit cleared */
    uint32_t lib_nid;
    uint32_t func_nid;
} vm_stub;

#define VM_MAX_IMPORTS 256

typedef struct {
    vm_module_info info;
    int            have_info;
    vm_import      imports[VM_MAX_IMPORTS];
    int            import_count;
    int            import_truncated;   /* more than VM_MAX_IMPORTS present */
    uint32_t       total_func_imports;

    vm_stub       *stubs;              /* sorted by addr; free with vm_free() */
    uint32_t       stub_count;
} vm_module;

void vm_free(vm_module *m);

/* Look up a call target. Returns NULL when the address is not an import stub. */
const vm_stub *vm_find_stub(const vm_module *m, uint32_t addr);

/* Parse the module info at `entry` (the raw e_entry value; the segment index in
 * its top two bits is honoured). Returns 0 on success. */
int vm_parse(const vm_image *img, uint32_t entry, vm_module *out,
             char *err, size_t errsz);

/* Two resolvers, because the module uses two conventions and they are not
 * interchangeable:
 *
 *   vm_ptr  — segment-RELATIVE offset. Used by the .sce_module_info header
 *             fields: export_top, import_top, module_start, and friends.
 *   vm_va   — ABSOLUTE virtual address. Used by every pointer stored *inside*
 *             an export or import entry: library_name, the NID tables, the
 *             entry tables.
 *
 * Resolving an absolute address as if it were relative does not fault; it
 * simply fails the bounds check and yields nothing, so the symptom is a table
 * of unnamed libraries rather than an error. Keeping the two as separate
 * functions makes the choice explicit at every call site. */
const uint8_t *vm_ptr(const vm_image *img, uint32_t off, uint32_t need);
const uint8_t *vm_va(const vm_image *img, uint32_t vaddr, uint32_t need);

#endif /* ARMRECOMP_MODULE_H */
