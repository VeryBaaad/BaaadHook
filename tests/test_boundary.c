/**
 * Copyright (c) 2026 VeryBaaad <verybaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE 1

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "bhinline.h"

#define CHECK(condition)                                                                 \
    do {                                                                                 \
        if (!(condition)) {                                                              \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,          \
                    #condition);                                                         \
            return 1;                                                                    \
        }                                                                                \
    } while (0)

#if defined(__x86_64__)

static int (*bh_boundary_original)(void);

static int bh_boundary_replacement(void) {
    return bh_boundary_original() + 100;
}

static const uint8_t bh_boundary_code[] = {
    0xF3, 0x0F, 0x1E, 0xFA,
    0xB8, 0x2A, 0x00, 0x00, 0x00,
    0xC3,
};

int main(void) {
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *mapping;
    uint8_t *target;
    int (*target_function)(void);
    void *original = NULL;
    int status;

    mapping = (uint8_t *)mmap(NULL, page_size * 2, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);

    target = mapping + page_size - sizeof(bh_boundary_code);
    memcpy(target, bh_boundary_code, sizeof(bh_boundary_code));

    CHECK(munmap(mapping + page_size, page_size) == 0);
    CHECK(mprotect(mapping, page_size, PROT_READ | PROT_EXEC) == 0);

    target_function = (int (*)(void))target;
    CHECK(target_function() == 42);

    status = bh_inline_hook((void *)target, (void *)bh_boundary_replacement,
                            &original);
    if (status != BH_INLINE_OK) {
        fprintf(stderr, "boundary inline hook failed: %s (%d)\n",
                bh_inline_strerror(status), status);
        (void)munmap(mapping, page_size);
        return 1;
    }
    CHECK(original != NULL);
    bh_boundary_original = (int (*)(void))original;
    CHECK(target_function() == 142);

    CHECK(bh_inline_unhook((void *)target) == BH_INLINE_OK);
    CHECK(target_function() == 42);

    CHECK(munmap(mapping, page_size) == 0);
    puts("boundary tests passed");
    return 0;
}

#else

int main(void) {
    puts("boundary tests skipped: x86_64 only");
    return 0;
}

#endif
