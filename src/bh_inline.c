/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE 1

#include "bhinline.h"
#include "bh_internal.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define BH_INLINE_MAX_PATCH 32u

typedef struct bh_inline_record {
    uintptr_t target;
    void *target_argument;
    void *replacement;
    void *mapping;
    void *trampoline;
    void *relay;
    uint8_t original_bytes[BH_INLINE_MAX_PATCH];
    size_t patch_size;
    size_t trampoline_length;
    size_t mapping_size;
    int thumb;
    int active;
    struct bh_inline_record *next;
} bh_inline_record_t;

static pthread_mutex_t bh_inline_lock = PTHREAD_MUTEX_INITIALIZER;
static bh_inline_record_t *bh_inline_records = NULL;

static uintptr_t bh_inline_normalize(uintptr_t address) {
#if defined(__arm__)
    return address & ~(uintptr_t)1u;
#else
    return address;
#endif
}

static int bh_inline_is_thumb(uintptr_t address) {
#if defined(__arm__)
    return (int)(address & 1u);
#else
    (void)address;
    return 0;
#endif
}

static bh_inline_record_t *bh_inline_find_active(uintptr_t target) {
    bh_inline_record_t *record = bh_inline_records;
    while (record != NULL) {
        if (record->active && record->target == target) {
            return record;
        }
        record = record->next;
    }
    return NULL;
}

static void bh_inline_record_destroy(bh_inline_record_t *record) {
    if (record == NULL) {
        return;
    }
    if (record->mapping != NULL) {
        (void)bh__free_pages(record->mapping, record->mapping_size);
    }
    free(record);
}

static int bh_inline_overlaps(uintptr_t target, size_t patch_size) {
    bh_inline_record_t *record = bh_inline_records;
    while (record != NULL) {
        if (record->active) {
            uintptr_t record_end = record->target + record->patch_size;
            uintptr_t target_end = target + patch_size;
            if (target < record_end && record->target < target_end) {
                return 1;
            }
        }
        record = record->next;
    }
    return 0;
}

int bh_inline_hook(void *target_argument, void *replacement, void **original) {
    bh_arch_info_t arch;
    bh_inline_record_t *record = NULL;
    uintptr_t target;
    uintptr_t target_address;
    uint8_t original_bytes[BH_INLINE_MAX_PATCH];
    uint8_t patch_bytes[BH_INLINE_MAX_PATCH];
    void *mapping = NULL;
    size_t page_size;
    size_t mapping_size;
    size_t code_capacity;
    size_t patch_size;
    size_t trampoline_length = 0;
    size_t copied = 0;
    size_t relay_offset;
    void *relay = NULL;
    int thumb;
    void *installed_trampoline = NULL;
    int status = BH_INLINE_OK;

    if (target_argument == NULL || replacement == NULL) {
        return BH_INLINE_ERROR_INVALID_ARGUMENT;
    }

    target = bh_inline_normalize((uintptr_t)target_argument);
    target_address = target;
    thumb = bh_inline_is_thumb((uintptr_t)target_argument);

    if (bh_arch_query(&arch) != 0 || arch.patch_size == 0 ||
        arch.patch_size > BH_INLINE_MAX_PATCH) {
        return BH_INLINE_ERROR_ARCHITECTURE;
    }
    patch_size = bh_arch_patch_size(target_address, thumb);
    if (patch_size == 0 || patch_size > BH_INLINE_MAX_PATCH ||
        patch_size > arch.patch_size) {
        return BH_INLINE_ERROR_ARCHITECTURE;
    }

    if (!bh__is_executable_range(target_address, patch_size)) {
        return BH_INLINE_ERROR_NOT_EXECUTABLE;
    }

    page_size = bh__page_size();
    mapping_size = page_size;
    if (arch.relay_size >= mapping_size) {
        return BH_INLINE_ERROR_OUT_OF_RANGE;
    }
    code_capacity = mapping_size - arch.relay_size - 16u;

    pthread_mutex_lock(&bh_inline_lock);
    if (bh_inline_find_active(target) != NULL ||
        bh_inline_overlaps(target, patch_size)) {
        status = BH_INLINE_ERROR_ALREADY_HOOKED;
        goto fail;
    }

    if (bh__copy_code(original_bytes, (const void *)target_address,
                      sizeof(original_bytes)) != 0) {
        status = BH_INLINE_ERROR_MEMORY_PROTECTION;
        goto fail;
    }

    mapping = bh__alloc_near(target, mapping_size, arch.max_distance);
    if (mapping == NULL) {
        status = BH_INLINE_ERROR_OUT_OF_MEMORY;
        goto fail;
    }

    if (bh_arch_relocate(original_bytes, target_address, patch_size, thumb,
                         mapping, code_capacity, &trampoline_length,
                         &copied) != 0) {
        status = BH_INLINE_ERROR_UNSUPPORTED;
        goto fail;
    }
    if (trampoline_length == 0 || copied < patch_size) {
        status = BH_INLINE_ERROR_UNSUPPORTED;
        goto fail;
    }

    if (arch.relay_size != 0) {
        relay_offset = bh__align_up(trampoline_length, 16u);
        if (relay_offset + arch.relay_size > mapping_size) {
            status = BH_INLINE_ERROR_OUT_OF_RANGE;
            goto fail;
        }
        relay = (uint8_t *)mapping + relay_offset;
        if (bh_arch_emit_relay(relay, mapping_size - relay_offset, replacement,
                               thumb) != (int)arch.relay_size) {
            status = BH_INLINE_ERROR_ARCHITECTURE;
            goto fail;
        }
    }

    if (bh_arch_emit_patch((void *)target_address, replacement, relay, thumb,
                           patch_bytes, sizeof(patch_bytes)) !=
        (int)patch_size) {
        status = BH_INLINE_ERROR_ARCHITECTURE;
        goto fail;
    }

    if (bh__make_executable(mapping, mapping_size) != 0) {
        status = BH_INLINE_ERROR_MEMORY_PROTECTION;
        goto fail;
    }

    record = (bh_inline_record_t *)calloc(1, sizeof(*record));
    if (record == NULL) {
        status = BH_INLINE_ERROR_OUT_OF_MEMORY;
        goto fail;
    }

    record->target = target;
    record->target_argument = target_argument;
    record->replacement = replacement;
    record->mapping = mapping;
    record->trampoline = thumb ? (void *)((uintptr_t)mapping | 1u) : mapping;
    record->relay = relay;
    record->patch_size = patch_size;
    record->trampoline_length = trampoline_length;
    record->mapping_size = mapping_size;
    record->thumb = thumb;
    record->active = 1;
    memcpy(record->original_bytes, original_bytes, patch_size);

    if (bh__write_code((void *)target_address, patch_bytes, patch_size) != 0) {
        status = BH_INLINE_ERROR_MEMORY_PROTECTION;
        goto fail;
    }

    installed_trampoline = record->trampoline;
    record->next = bh_inline_records;
    bh_inline_records = record;
    record = NULL;
    pthread_mutex_unlock(&bh_inline_lock);

    if (original != NULL) {
        *original = installed_trampoline;
    }

    return BH_INLINE_OK;

fail:
    pthread_mutex_unlock(&bh_inline_lock);
    if (record != NULL) {
        free(record);
    }
    if (mapping != NULL) {
        (void)bh__free_pages(mapping, mapping_size);
    }
    return status;
}

int bh_inline_unhook(void *target_argument) {
    bh_inline_record_t **link;
    bh_inline_record_t *record = NULL;
    uintptr_t target;
    int result;

    if (target_argument == NULL) {
        return BH_INLINE_ERROR_INVALID_ARGUMENT;
    }
    target = bh_inline_normalize((uintptr_t)target_argument);

    pthread_mutex_lock(&bh_inline_lock);
    link = &bh_inline_records;
    while (*link != NULL) {
        if ((*link)->active && (*link)->target == target) {
            record = *link;
            break;
        }
        link = &(*link)->next;
    }
    if (record == NULL) {
        pthread_mutex_unlock(&bh_inline_lock);
        return BH_INLINE_ERROR_NOT_HOOKED;
    }
    result = bh__write_code((void *)record->target, record->original_bytes,
                            record->patch_size);
    if (result == 0) {
        record->active = 0;
        *link = record->next;
        record->next = NULL;
    }
    pthread_mutex_unlock(&bh_inline_lock);

    if (result != 0) {
        return BH_INLINE_ERROR_MEMORY_PROTECTION;
    }
    bh_inline_record_destroy(record);
    return BH_INLINE_OK;
}

int bh_inline_unhook_all(void) {
    bh_inline_record_t **link;
    bh_inline_record_t *retired = NULL;
    int count = 0;

    pthread_mutex_lock(&bh_inline_lock);
    link = &bh_inline_records;
    while (*link != NULL) {
        bh_inline_record_t *record = *link;

        if (record->active) {
            if (bh__write_code((void *)record->target, record->original_bytes,
                               record->patch_size) != 0) {
                link = &record->next;
                continue;
            }
            record->active = 0;
            count++;
        }

        *link = record->next;
        record->next = retired;
        retired = record;
    }
    pthread_mutex_unlock(&bh_inline_lock);

    while (retired != NULL) {
        bh_inline_record_t *next = retired->next;
        bh_inline_record_destroy(retired);
        retired = next;
    }
    return count;
}

int bh_inline_is_hooked(const void *target_argument) {
    uintptr_t target;
    int result;

    if (target_argument == NULL) {
        return 0;
    }
    target = bh_inline_normalize((uintptr_t)target_argument);
    pthread_mutex_lock(&bh_inline_lock);
    result = bh_inline_find_active(target) != NULL;
    pthread_mutex_unlock(&bh_inline_lock);
    return result;
}

void *bh_inline_get_original(const void *target_argument) {
    bh_inline_record_t *record;
    uintptr_t target;
    void *result = NULL;

    if (target_argument == NULL) {
        return NULL;
    }
    target = bh_inline_normalize((uintptr_t)target_argument);
    pthread_mutex_lock(&bh_inline_lock);
    record = bh_inline_find_active(target);
    if (record != NULL) {
        result = record->trampoline;
    }
    pthread_mutex_unlock(&bh_inline_lock);
    return result;
}

const char *bh_inline_strerror(int status) {
    switch (status) {
        case BH_INLINE_OK:
            return "success";
        case BH_INLINE_ERROR_INVALID_ARGUMENT:
            return "invalid argument";
        case BH_INLINE_ERROR_NOT_HOOKED:
            return "address is not hooked";
        case BH_INLINE_ERROR_ALREADY_HOOKED:
            return "address or prologue is already hooked";
        case BH_INLINE_ERROR_NOT_EXECUTABLE:
            return "target is not in an executable mapping";
        case BH_INLINE_ERROR_OUT_OF_RANGE:
            return "relay/trampoline allocation is out of branch range";
        case BH_INLINE_ERROR_OUT_OF_MEMORY:
            return "out of memory";
        case BH_INLINE_ERROR_UNSUPPORTED:
            return "unsupported instruction/prologue";
        case BH_INLINE_ERROR_MEMORY_PROTECTION:
            return "unable to change memory protection";
        case BH_INLINE_ERROR_ARCHITECTURE:
            return "architecture backend error";
        default:
            return "unknown inline hook error";
    }
}

const char *bh_inline_arch_name(void) {
#if defined(__aarch64__)
    return "arm64-v8a";
#elif defined(__arm__)
    return "armeabi-v7a";
#elif defined(__x86_64__)
    return "x86_64";
#elif defined(__i386__)
    return "x86";
#elif defined(__riscv) && (__riscv_xlen == 64)
    return "riscv64";
#else
    return "unsupported";
#endif
}
