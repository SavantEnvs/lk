// Host shim: the only arch hooks the host-built modules use.
#pragma once
#include <stddef.h>
#include <sys/types.h>
static inline void arch_sync_cache_range(addr_t start, size_t len) { (void)start; (void)len; }
static inline uint arch_curr_cpu_num(void) { return 0; }
