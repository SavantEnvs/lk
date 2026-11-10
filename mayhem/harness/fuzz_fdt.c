// libfdt (external/lib/fdt): the flat device tree reader/writer LK platforms use to consume a
// bootloader-supplied DTB.
#include <libfdt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void walk_node(const void *fdt, int node, int depth) {
    int len;
    (void)fdt_get_name(fdt, node, &len);
    (void)fdt_getprop(fdt, node, "compatible", &len);
    (void)fdt_getprop(fdt, node, "reg", &len);
    (void)fdt_get_phandle(fdt, node);
    (void)fdt_address_cells(fdt, node);
    (void)fdt_size_cells(fdt, node);
    (void)fdt_stringlist_count(fdt, node, "compatible");

    int prop;
    fdt_for_each_property_offset(prop, fdt, node) {
        const char *name;
        const void *val = fdt_getprop_by_offset(fdt, prop, &name, &len);
        if (val && len > 0)
            (void)((const volatile uint8_t *)val)[len - 1];
        if (name)
            (void)strlen(name);
    }

    char path[256];
    (void)fdt_get_path(fdt, node, path, sizeof(path));

    if (depth > 32)
        return;
    int sub;
    fdt_for_each_subnode(sub, fdt, node)
        walk_node(fdt, sub, depth + 1);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // libfdt's contract is a blob of at least fdt_totalsize() bytes at an aligned address.
    void *fdt = malloc(size ? size : 1);
    if (!fdt)
        return -1;
    memcpy(fdt, data, size);

    // fdt_check_header() does not check the alignment the format requires of the reserve map (8) and
    // the structure block (4); the accessors then do aligned loads from those offsets.
    if (size < sizeof(struct fdt_header) || fdt_check_header(fdt) != 0 || fdt_totalsize(fdt) > size ||
        (fdt_off_mem_rsvmap(fdt) & 7) != 0 || (fdt_off_dt_struct(fdt) & 3) != 0) {
        free(fdt);
        return -1;
    }

    // Read-only access the way a bootloader does it, with no full validation first.
    walk_node(fdt, 0, 0);
    int n = fdt_num_mem_rsv(fdt);
    for (int i = 0; i < n; i++) {
        uint64_t addr, sz;
        (void)fdt_get_mem_rsv(fdt, i, &addr, &sz);
    }
    (void)fdt_path_offset(fdt, "/soc");
    (void)fdt_path_offset(fdt, "/chosen");
    (void)fdt_node_offset_by_compatible(fdt, -1, "riscv");
    (void)fdt_node_offset_by_phandle(fdt, 1);
    (void)fdt_get_alias(fdt, "serial0");

    // Edit a validated tree.
    if (fdt_check_full(fdt, size) == 0) {
        size_t cap = size + 512;
        void *copy = malloc(cap);
        if (copy && fdt_open_into(fdt, copy, cap) == 0) {
            int off = fdt_add_subnode(copy, 0, "mayhem");
            if (off >= 0) {
                (void)fdt_setprop_u32(copy, off, "val", 0x1234);
                (void)fdt_appendprop_string(copy, off, "str", "x");
                (void)fdt_delprop(copy, off, "val");
            }
            int first = fdt_first_subnode(copy, 0);
            if (first >= 0)
                (void)fdt_del_node(copy, first);
            (void)fdt_pack(copy);
            (void)fdt_check_full(copy, cap);
        }
        free(copy);
    }

    free(fdt);
    return 0;
}
