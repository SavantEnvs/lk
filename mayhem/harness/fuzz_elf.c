// lib/elf: the LK ELF program loader, reading from memory and placing PT_LOAD segments through an
// allocation hook the way an embedder with a real allocator does.
#include <lib/elf.h>
#include <lk/err.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SEGMENTS 16
#define MAX_SEGMENT_BYTES (16u << 20)

struct seg_state {
    void *ptrs[MAX_SEGMENTS];
    uint refuse_at;
};

static status_t alloc_hook(elf_handle_t *handle, void **ptr, size_t len, uint num, uint flags) {
    (void)flags;
    struct seg_state *st = handle->mem_alloc_hook_arg;
    // The embedder's allocator refuses what it cannot back.
    if (num == st->refuse_at || len > MAX_SEGMENT_BYTES)
        return ERR_NO_MEMORY;
    void *p = malloc(len ? len : 1);
    if (!p)
        return ERR_NO_MEMORY;
    st->ptrs[num] = p;
    *ptr = p;
    return NO_ERROR;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    elf_handle_t handle;
    struct seg_state st;
    memset(&st, 0, sizeof(st));
    // e_ident[EI_PAD] (byte 9) is ignored by the loader; it picks which segment the allocator refuses
    // (0 = none), so the allocation-failure return is taken after every possible number of segments.
    // e_phnum <= 16 is enforced by elf_load, so `num` always indexes ptrs[].
    st.refuse_at = (size > 9 ? data[9] : 0u) - 1u;

    if (elf_open_handle_memory(&handle, data, size) != NO_ERROR)
        return -1;
    handle.mem_alloc_hook = alloc_hook;
    handle.mem_alloc_hook_arg = &st;

    // elf_load's error returns are the loader's defined answer for a malformed or unloadable image, and
    // the code under test; returning -1 for them would make libFuzzer discard the coverage of every
    // header-verification and segment-failure path, so the status is deliberately not turned into -1.
    (void)elf_load(&handle);
    elf_close_handle(&handle);
    for (int i = 0; i < MAX_SEGMENTS; i++)
        free(st.ptrs[i]);
    return 0;
}
