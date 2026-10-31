/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#ifndef BAAADHOOK_BH_INTERNAL_H
#define BAAADHOOK_BH_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#  define BH_HIDDEN __attribute__((visibility("hidden")))
#  define BH_UNUSED __attribute__((unused))
#  define BH_NOINLINE __attribute__((noinline))
#else
#  define BH_HIDDEN
#  define BH_UNUSED
#  define BH_NOINLINE
#endif

typedef struct bh_arch_info {
    size_t patch_size;
    size_t relay_size;
    size_t max_distance;
} bh_arch_info_t;

BH_HIDDEN int bh_arch_query(bh_arch_info_t *info);

BH_HIDDEN size_t bh_arch_patch_size(uintptr_t target, int thumb);

BH_HIDDEN size_t bh_arch_entry_prefix(const uint8_t *bytes, size_t size);

BH_HIDDEN int bh_arch_relocate(const uint8_t *src_bytes, uintptr_t src_address,
                               size_t min_bytes, int thumb,
                               void *dst, size_t dst_capacity,
                               size_t *out_len, size_t *copied);

BH_HIDDEN int bh_arch_emit_relay(void *relay, size_t capacity,
                                 const void *dest, int thumb);

BH_HIDDEN int bh_arch_emit_patch(void *target, const void *dest,
                                 const void *relay, int thumb,
                                 void *out, size_t capacity);

BH_HIDDEN size_t bh__page_size(void);

BH_HIDDEN void *bh__alloc_near(uintptr_t target, size_t size,
                               size_t max_distance);

BH_HIDDEN int bh__free_pages(void *ptr, size_t size);

BH_HIDDEN int bh__protect_query(uintptr_t address, int *prot);
BH_HIDDEN int bh__is_mapped_range(uintptr_t address, size_t size);
BH_HIDDEN int bh__is_executable_range(uintptr_t address, size_t size);

BH_HIDDEN int bh__copy_code(void *dst, const void *src, size_t size);

BH_HIDDEN int bh__copy_code_partial(void *dst, const void *src, size_t size,
                                    size_t *copied);

BH_HIDDEN int bh__write_code(void *dst, const void *src, size_t size);

BH_HIDDEN int bh__write_code_ex(void *dst, const void *src, size_t size,
                                int preserve_bti);

BH_HIDDEN int bh__page_has_bti(uintptr_t address);

BH_HIDDEN int bh__write_pointer(void *address, uintptr_t value);
BH_HIDDEN int bh__cas_pointer(void *address, uintptr_t expected,
                              uintptr_t desired);

BH_HIDDEN uintptr_t bh__read_pointer(const void *address);

BH_HIDDEN void bh__flush_cache(void *address, size_t size);

BH_HIDDEN int bh__make_executable(void *address, size_t size);

static inline size_t bh__align_up(size_t value, size_t alignment) {
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static inline uintptr_t bh__align_down_ptr(uintptr_t value, size_t alignment) {
    return value & ~((uintptr_t)alignment - 1u);
}

static inline int bh__address_in_range(uintptr_t address, uintptr_t start,
                                       uintptr_t end) {
    return address >= start && address < end;
}

#endif /* BAAADHOOK_BH_INTERNAL_H */
