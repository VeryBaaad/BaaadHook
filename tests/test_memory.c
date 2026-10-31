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

#include "bh_internal.h"

#define CHECK(condition)                                                                 \
    do {                                                                                 \
        if (!(condition)) {                                                              \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,          \
                    #condition);                                                         \
            return 1;                                                                    \
        }                                                                                \
    } while (0)

static int test_write_code_restores_partial_pages(void) {
    size_t page_size = bh__page_size();
    uint8_t *mapping;
    uint8_t source[16];
    int prot = 0;

    mapping = (uint8_t *)mmap(NULL, page_size * 2, PROT_READ,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);
    CHECK(munmap(mapping + page_size, page_size) == 0);

    memset(source, 0x5A, sizeof(source));
    CHECK(bh__write_code(mapping + page_size - 8, source, sizeof(source)) != 0);
    CHECK(bh__protect_query((uintptr_t)mapping, &prot) == 0);
    CHECK(prot == PROT_READ);

    CHECK(munmap(mapping, page_size) == 0);
    return 0;
}

static int test_write_code_across_pages(void) {
    size_t page_size = bh__page_size();
    uint8_t *mapping;
    uint8_t *destination;
    uint8_t source[32];
    size_t i;

    mapping = (uint8_t *)mmap(NULL, page_size * 2, PROT_READ,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);

    for (i = 0; i < sizeof(source); i++) {
        source[i] = (uint8_t)(i + 1u);
    }
    destination = mapping + page_size - 8;
    CHECK(bh__write_code(destination, source, sizeof(source)) == 0);
    CHECK(memcmp(destination, source, sizeof(source)) == 0);

    for (i = 0; i < 2; i++) {
        int prot = 0;
        CHECK(bh__protect_query((uintptr_t)(mapping + i * page_size), &prot) == 0);
        CHECK(prot == PROT_READ);
    }

    CHECK(munmap(mapping, page_size * 2) == 0);
    return 0;
}

static int test_write_pointer_restores_protection(void) {
    size_t page_size = bh__page_size();
    uintptr_t *mapping;
    int prot = 0;

    mapping = (uintptr_t *)mmap(NULL, page_size, PROT_READ,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);

    CHECK(bh__write_pointer(mapping, (uintptr_t)0x12345678u) == 0);
    CHECK(*mapping == (uintptr_t)0x12345678u);
    CHECK(bh__protect_query((uintptr_t)mapping, &prot) == 0);
    CHECK(prot == PROT_READ);

    CHECK(munmap(mapping, page_size) == 0);
    return 0;
}

static int test_alloc_near_range(void) {
    size_t page_size = bh__page_size();
    size_t allocation_size = page_size * 2;
    void *allocation;

    allocation = bh__alloc_near((uintptr_t)&test_alloc_near_range,
                                allocation_size, (size_t)0x40000000u);
    CHECK(allocation != NULL);
    CHECK(((uintptr_t)allocation & (uintptr_t)(page_size - 1u)) == 0);
    CHECK(bh__is_mapped_range((uintptr_t)allocation, allocation_size));
    CHECK(bh__free_pages(allocation, allocation_size) == 0);
    return 0;
}

int main(void) {
    CHECK(test_write_code_restores_partial_pages() == 0);
    CHECK(test_write_code_across_pages() == 0);
    CHECK(test_write_pointer_restores_protection() == 0);
    CHECK(test_alloc_near_range() == 0);
    puts("memory tests passed");
    return 0;
}
