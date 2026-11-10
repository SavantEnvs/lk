// Host shim: the host libc's <sys/types.h> plus the LK scalar typedefs from lib/libc/include/sys/types.h.
#pragma once
#include_next <sys/types.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>

typedef int status_t;
typedef uintptr_t addr_t;
typedef uintptr_t vaddr_t;
typedef uintptr_t paddr_t;
typedef uint32_t lk_time_t;
typedef unsigned long long lk_bigtime_t;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
