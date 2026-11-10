// lib/cmdline: the Linux-style kernel command line parser. Every word of the input is also used
// as a variable name to query, so the lookups see the same quoting and escape cases.
#include <ctype.h>
#include <lib/cmdline.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cmdline_reset_for_testing();
    // The parser keeps the pointer, so give it a buffer of exactly this size.
    char *buf = malloc(size ? size : 1);
    if (!buf)
        return -1;
    memcpy(buf, data, size);
    if (cmdline_init(buf, size) != 0) {
        free(buf);
        return -1;
    }

    char name[64];
    size_t i = 0;
    while (i < size) {
        while (i < size && (isspace((unsigned char)buf[i]) || buf[i] == '='))
            i++;
        size_t n = 0;
        while (i < size && !isspace((unsigned char)buf[i]) && buf[i] != '=') {
            if (n < sizeof(name) - 1)
                name[n++] = buf[i];
            i++;
        }
        name[n] = 0;
        if (n == 0)
            continue;

        const char *val;
        size_t vlen;
        bool b;
        char sbuf[32];
        size_t actual;
        uint32_t u32;
        uint64_t u64;
        int iv;
        (void)cmdline_get_value(name, &val, &vlen);
        (void)cmdline_is_present(name);
        (void)cmdline_get_bool(name, &b);
        (void)cmdline_get_string(name, sbuf, sizeof(sbuf), &actual);
        (void)cmdline_get_uint32(name, &u32);
        (void)cmdline_get_uint64(name, &u64);
        (void)cmdline_get_int(name, &iv);
    }
    (void)cmdline_get_raw_string();
    (void)cmdline_get_raw_size();

    cmdline_reset_for_testing();
    free(buf);
    return 0;
}
