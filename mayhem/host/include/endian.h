// Host shim: host <endian.h> plus the LK LE/BE conversion macros.
#pragma once
#include_next <endian.h>
#include <stdint.h>

static inline uint64_t SWAP_64(uint64_t x) { return __builtin_bswap64(x); }
static inline uint32_t SWAP_32(uint32_t x) { return __builtin_bswap32(x); }
static inline uint16_t SWAP_16(uint16_t x) { return __builtin_bswap16(x); }
#define LE64(val) (val)
#define LE32(val) (val)
#define LE16(val) (val)
#define BE64(val) SWAP_64(val)
#define BE32(val) SWAP_32(val)
#define BE16(val) SWAP_16(val)
#define LE64SWAP(val) (val)
