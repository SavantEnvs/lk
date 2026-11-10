// external/lib/miniz: tinfl inflate (raw deflate and zlib streams) and a tdefl/tinfl round trip.
#include <lib/miniz.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1)
        return -1;
    int flags = data[0] & (TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_COMPUTE_ADLER32);
    const uint8_t *in = data + 1;
    size_t in_len = size - 1;

    // Streaming inflate through a 32K wrapping window, capped at 256 KiB of output (eight trips
    // around the window) so a deflate bomb costs a bounded amount of work per input.
    {
        tinfl_decompressor decomp;
        uint8_t window[TINFL_LZ_DICT_SIZE];
        memset(window, 0, sizeof(window));
        tinfl_init(&decomp);
        size_t consumed = 0, produced = 0, total = 0, out_pos = 0;
        tinfl_status st;
        do {
            size_t in_n = in_len - consumed;
            size_t out_n = sizeof(window) - out_pos;
            st = tinfl_decompress(&decomp, in + consumed, &in_n, window, window + out_pos, &out_n,
                                  flags & ~TINFL_FLAG_HAS_MORE_INPUT);
            consumed += in_n;
            produced = out_n;
            if (in_n == 0 && produced == 0)
                break;
            total += produced;
            out_pos = (out_pos + produced) & (sizeof(window) - 1);
        } while (st == TINFL_STATUS_HAS_MORE_OUTPUT && total < (256u << 10));
    }
    size_t out_len = 0;

    uint8_t small[256];
    (void)tinfl_decompress_mem_to_mem(small, sizeof(small), in, in_len, flags);

    // Round trip: whatever bytes we are given must survive compress + decompress.
    size_t comp_len = 0;
    void *comp = tdefl_compress_mem_to_heap(in, in_len, &comp_len, (data[0] >> 4) & 0xfff);
    if (comp) {
        size_t back_len = 0;
        void *back = tinfl_decompress_mem_to_heap(comp, comp_len, &back_len, 0);
        if ((in_len && !back) || back_len != in_len || (in_len && memcmp(back, in, in_len) != 0))
            __builtin_trap();
        free(back);
        free(comp);
    }
    return 0;
}
