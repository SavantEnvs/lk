// Host support for the LK modules built into the fuzz harnesses.
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <lk/debug.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void assert_fail(const char *file, int line, const char *expression) {
    fprintf(stderr, "ASSERT FAILED at %s:%d: %s\n", file, line, expression);
    abort();
}

void assert_fail_msg(const char *file, int line, const char *expression, const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "ASSERT FAILED at %s:%d: %s: ", file, line, expression);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    abort();
}

void panic(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "PANIC: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    abort();
}

void hexdump(const void *ptr, size_t len) { (void)ptr; (void)len; }
void hexdump8_ex(const void *ptr, size_t len, uint64_t disp_addr_start) { (void)ptr; (void)len; (void)disp_addr_start; }
FILE *get_panic_fd(void) { return stderr; }
