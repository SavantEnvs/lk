// Known-answer probe for mayhem/test.sh: fixed inputs through the real LK modules, asserting parsed
// values. Prints one "PASS <name>" or "FAIL <name>" line per check; test.sh counts them.
#include <lib/cmdline.h>
#include <lib/devicetree.h>
#include <lib/elf.h>
#include <lib/miniz.h>
#include <libfdt.h>
#include <lk/err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void check(const char *name, int ok) {
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
}

static uint8_t dtb[512];

static int build_dtb(void) {
    void *f = dtb;
    if (fdt_create(f, sizeof(dtb)) || fdt_finish_reservemap(f) || fdt_begin_node(f, ""))
        return -1;
    fdt_property_u32(f, "#address-cells", 1);
    fdt_begin_node(f, "soc");
    fdt_property_string(f, "compatible", "lk,test");
    fdt_property_u32(f, "reg", 0x1000);
    fdt_end_node(f);
    fdt_end_node(f);
    return fdt_finish(f);
}

struct dt_count { int nodes, props; int saw_reg; int saw_compat; };

static int dt_node(int depth, const char *name, void *cookie) {
    struct dt_count *c = cookie;
    c->nodes++;
    (void)depth; (void)name;
    return 0;
}

static int dt_prop(const char *name, u8 *data, u32 size, void *cookie) {
    struct dt_count *c = cookie;
    c->props++;
    if (!strcmp(name, "reg") && size == 4 && dt_rd32(data) == 0x1000)
        c->saw_reg = 1;
    if (!strcmp(name, "compatible") && size == 8 && !memcmp(data, "lk,test", 8))
        c->saw_compat = 1;
    return 0;
}

static void test_fdt(void) {
    check("fdt build", build_dtb() == 0);
    check("fdt check_full", fdt_check_full(dtb, sizeof(dtb)) == 0);
    int soc = fdt_path_offset(dtb, "/soc");
    check("fdt path /soc", soc > 0);
    int len = 0;
    const char *compat = fdt_getprop(dtb, soc, "compatible", &len);
    check("fdt compatible", compat && len == 8 && !strcmp(compat, "lk,test"));
    const fdt32_t *reg = fdt_getprop(dtb, soc, "reg", &len);
    check("fdt reg", reg && len == 4 && fdt32_to_cpu(*reg) == 0x1000);
    check("fdt missing node", fdt_path_offset(dtb, "/nope") == -FDT_ERR_NOTFOUND);
    uint8_t bad[sizeof(dtb)];
    memcpy(bad, dtb, sizeof(dtb));
    bad[0] ^= 0xff;
    check("fdt bad magic", fdt_check_header(bad) == -FDT_ERR_BADMAGIC);
}

static void test_devicetree(void) {
    devicetree_t dt;
    struct dt_count c;
    memset(&dt, 0, sizeof(dt));
    memset(&c, 0, sizeof(c));
    int rc = dt_init(&dt, dtb, fdt_totalsize(dtb));
    check("devicetree init", rc == 0);
    rc = dt_walk(&dt, dt_node, dt_prop, &c);
    check("devicetree walk", rc == 0 && c.nodes == 2 && c.props == 3);
    check("devicetree reg value", c.saw_reg);
    check("devicetree compatible value", c.saw_compat);
    dtb[0] = 0;
    check("devicetree bad magic", dt_init(&dt, dtb, fdt_totalsize(dtb)) < 0);
}

static void test_miniz(void) {
    static const uint8_t z[] = {
        0x78, 0xda, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0xc0, 0x41, 0x96, 0xe7, 0x17, 0xe5, 0xa4,
        0x70, 0x01, 0x00, 0xf9, 0x06, 0x0d, 0x37 };
    static const char want[] = "hello hello hello hello hello world\n";
    size_t n = 0;
    void *out = tinfl_decompress_mem_to_heap(z, sizeof(z), &n, TINFL_FLAG_PARSE_ZLIB_HEADER);
    check("miniz inflate known zlib stream", out && n == sizeof(want) - 1 && !memcmp(out, want, n));
    free(out);

    uint8_t bad[sizeof(z)];
    memcpy(bad, z, sizeof(z));
    bad[3] ^= 0xff;
    bad[10] ^= 0xff;
    out = tinfl_decompress_mem_to_heap(bad, sizeof(bad), &n,
                                       TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_COMPUTE_ADLER32);
    check("miniz rejects corrupted stream", out == NULL || n != sizeof(want) - 1 || memcmp(out, want, n) != 0);
    free(out);

    uint8_t big[2000];
    for (size_t i = 0; i < sizeof(big); i++)
        big[i] = (uint8_t)("lk kernel"[i % 9]);
    size_t clen = 0, blen = 0;
    void *c = tdefl_compress_mem_to_heap(big, sizeof(big), &clen, 128);
    check("miniz deflate shrinks repetitive data", c && clen < sizeof(big) / 4);
    void *b = c ? tinfl_decompress_mem_to_heap(c, clen, &blen, 0) : NULL;
    check("miniz round trip", b && blen == sizeof(big) && !memcmp(b, big, blen));
    free(b);
    free(c);
}

struct elf_one { void *p; };
static status_t elf_alloc(elf_handle_t *h, void **ptr, size_t len, uint num, uint flags) {
    (void)flags; (void)num;
    struct elf_one *o = h->mem_alloc_hook_arg;
    o->p = calloc(1, len);
    *ptr = o->p;
    return o->p ? NO_ERROR : ERR_NO_MEMORY;
}

static void test_elf(void) {
    uint8_t img[64 + 56 + 8];
    memset(img, 0, sizeof(img));
    struct Elf64_Ehdr *eh = (void *)img;
    memcpy(eh->e_ident, ELF_MAGIC, 4);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_ident[EI_DATA] = ELFDATA2LSB;
    eh->e_ident[EI_VERSION] = EV_CURRENT;
    eh->e_machine = EM_X86_64;
    eh->e_entry = 0x1234;
    eh->e_phoff = 64;
    eh->e_phentsize = sizeof(struct Elf64_Phdr);
    eh->e_phnum = 1;
    struct Elf64_Phdr *ph = (void *)(img + 64);
    ph->p_type = PT_LOAD;
    ph->p_offset = 64 + 56;
    ph->p_filesz = 8;
    ph->p_memsz = 16;
    memcpy(img + 64 + 56, "LKELFSEG", 8);

    elf_handle_t h;
    struct elf_one one = { 0 };
    check("elf open", elf_open_handle_memory(&h, img, sizeof(img)) == NO_ERROR);
    h.mem_alloc_hook = elf_alloc;
    h.mem_alloc_hook_arg = &one;
    check("elf load", elf_load(&h) == NO_ERROR);
    check("elf entry", h.entry == 0x1234);
    check("elf segment bytes", one.p && !memcmp(one.p, "LKELFSEG", 8));
    check("elf bss zeroed", one.p && ((uint8_t *)one.p)[8] == 0 && ((uint8_t *)one.p)[15] == 0);
    elf_close_handle(&h);
    free(one.p);

    img[0] = 0;
    check("elf bad magic", elf_open_handle_memory(&h, img, sizeof(img)) == NO_ERROR && elf_load(&h) == ERR_NOT_FOUND);
    elf_close_handle(&h);
}

static void test_cmdline(void) {
    static const char line[] = "foo=bar debug nofoo count=42 name=\"a b\" hex=0x10";
    cmdline_reset_for_testing();
    check("cmdline init", cmdline_init(line, sizeof(line) - 1) == 0);
    const char *v;
    size_t n;
    check("cmdline value", cmdline_get_value("foo", &v, &n) == 0 && n == 3 && !memcmp(v, "bar", 3));
    check("cmdline bare variable", cmdline_is_present("debug"));
    check("cmdline absent", !cmdline_is_present("missing") && cmdline_get_value("missing", &v, &n) == ERR_NOT_FOUND);
    uint32_t u = 0;
    check("cmdline uint32", cmdline_get_uint32("count", &u) == 0 && u == 42);
    check("cmdline hex", cmdline_get_uint32("hex", &u) == 0 && u == 16);
    char s[16];
    size_t actual = 0;
    check("cmdline quoted string", cmdline_get_string("name", s, sizeof(s), &actual) == 0 && !strcmp(s, "a b") && actual == 3);
    cmdline_reset_for_testing();
}

int main(void) {
    test_fdt();
    test_devicetree();
    test_miniz();
    test_elf();
    test_cmdline();
    return 0;
}
