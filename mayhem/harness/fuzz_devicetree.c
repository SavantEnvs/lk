// lib/devicetree: LK's own minimal DTB walker.
#include <lib/devicetree.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct walk_state {
    size_t sum;
    const u8 *buf;
    size_t total;
};

static int node_cb(int depth, const char *name, void *cookie) {
    (void)depth;
    ((struct walk_state *)cookie)->sum += strlen(name);
    return 0;
}

// dt_init's sslice() can wrap `off + len` in u32 and accept a strings/structure slice that lies outside
// the blob, and dt_walk hands the callback `strings + str` and a data pointer from those slices without
// checking them. The callback therefore bounds both against the blob itself (the real allocation), not
// against the library's slices, before it reads; the library's own out-of-bounds reads stay reported in
// the library (su32/sstring/sslice).
static int prop_cb(const char *name, u8 *data, u32 size, void *cookie) {
    struct walk_state *st = cookie;
    uintptr_t base = (uintptr_t)st->buf;
    uintptr_t n = (uintptr_t)name;
    if (n < base || n - base >= st->total || !memchr(name, 0, st->total - (size_t)(n - base)))
        return 0;
    st->sum += strlen(name);
    if (data && size > 0) {
        uintptr_t d = (uintptr_t)data;
        if (d < base || d - base > st->total || size > st->total - (size_t)(d - base))
            return 0;
        st->sum += data[size - 1];
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    void *buf = malloc(size ? size : 1);
    if (!buf)
        return -1;
    memcpy(buf, data, size);

    devicetree_t dt;
    memset(&dt, 0, sizeof(dt));
    struct walk_state st;
    if (dt_init(&dt, buf, (u32)size) == 0) {
        st.sum = 0;
        st.buf = buf;
        st.total = size;
        dt_walk(&dt, node_cb, prop_cb, &st);
    } else {
        free(buf);
        return -1;
    }
    free(buf);
    return 0;
}
