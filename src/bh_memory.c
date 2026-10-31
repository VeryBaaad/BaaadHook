/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE 1

#include "bh_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#  define MAP_ANONYMOUS MAP_ANON
#endif

typedef struct bh_map_entry {
    uintptr_t start;
    uintptr_t end;
    int prot;
} bh_map_entry_t;

static int bh__parse_maps(bh_map_entry_t **out_maps, size_t *out_count) {
    FILE *fp;
    char line[512];
    bh_map_entry_t *maps = NULL;
    size_t count = 0;
    size_t capacity = 0;

    *out_maps = NULL;
    *out_count = 0;

    fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long start = 0;
        unsigned long end = 0;
        char perms[8] = {0};
        int prot = 0;

        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3 || end <= start) {
            continue;
        }
        if (perms[0] == 'r') prot |= PROT_READ;
        if (perms[1] == 'w') prot |= PROT_WRITE;
        if (perms[2] == 'x') prot |= PROT_EXEC;

        if (count == capacity) {
            size_t new_capacity = capacity == 0 ? 128 : capacity * 2;
            bh_map_entry_t *new_maps =
                (bh_map_entry_t *)realloc(maps, new_capacity * sizeof(*new_maps));
            if (new_maps == NULL) {
                free(maps);
                fclose(fp);
                return -1;
            }
            maps = new_maps;
            capacity = new_capacity;
        }
        maps[count].start = (uintptr_t)start;
        maps[count].end = (uintptr_t)end;
        maps[count].prot = prot;
        count++;
    }

    fclose(fp);
    *out_maps = maps;
    *out_count = count;
    return 0;
}

static const bh_map_entry_t *bh__find_map(const bh_map_entry_t *maps, size_t count,
                                          uintptr_t address) {
    size_t i;
    for (i = 0; i < count; i++) {
        if (address >= maps[i].start && address < maps[i].end) {
            return &maps[i];
        }
    }
    return NULL;
}

size_t bh__page_size(void) {
    static size_t cached = 0;
    size_t value = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
    if (value == 0) {
        long queried = sysconf(_SC_PAGESIZE);
        value = queried > 0 ? (size_t)queried : 4096u;
        __atomic_store_n(&cached, value, __ATOMIC_RELEASE);
    }
    return value;
}

int bh__protect_query(uintptr_t address, int *prot) {
    bh_map_entry_t *maps = NULL;
    size_t count = 0;
    const bh_map_entry_t *entry;
    int result = -1;

    if (prot == NULL) {
        return -1;
    }
    if (bh__parse_maps(&maps, &count) != 0) {
        return -1;
    }
    entry = bh__find_map(maps, count, address);
    if (entry != NULL) {
        *prot = entry->prot;
        result = 0;
    }
    free(maps);
    return result;
}

int bh__is_mapped_range(uintptr_t address, size_t size) {
    bh_map_entry_t *maps = NULL;
    size_t count = 0;
    uintptr_t cursor;
    uintptr_t end;
    int result = 0;

    if (size == 0) {
        return 1;
    }
    if (address + size < address) {
        return 0;
    }
    if (bh__parse_maps(&maps, &count) != 0) {
        return 0;
    }

    cursor = address;
    end = address + size;
    while (cursor < end) {
        const bh_map_entry_t *entry = bh__find_map(maps, count, cursor);
        if (entry == NULL) {
            break;
        }
        cursor = entry->end;
    }
    if (cursor >= end) {
        result = 1;
    }
    free(maps);
    return result;
}

int bh__is_executable_range(uintptr_t address, size_t size) {
    bh_map_entry_t *maps = NULL;
    size_t count = 0;
    uintptr_t cursor;
    uintptr_t end;
    int result = 1;

    if (size == 0) {
        return 1;
    }
    if (address + size < address) {
        return 0;
    }
    if (bh__parse_maps(&maps, &count) != 0) {
        return 0;
    }

    cursor = address;
    end = address + size;
    while (cursor < end) {
        const bh_map_entry_t *entry = bh__find_map(maps, count, cursor);
        if (entry == NULL || (entry->prot & PROT_EXEC) == 0) {
            result = 0;
            break;
        }
        cursor = entry->end;
    }
    free(maps);
    return result;
}

void bh__flush_cache(void *address, size_t size) {
    if (address != NULL && size != 0) {
        __builtin___clear_cache((char *)address, (char *)address + size);
    }
}

int bh__copy_code(void *dst, const void *src, size_t size) {
    const uint8_t *source = (const uint8_t *)src;
    uint8_t *destination = (uint8_t *)dst;
    size_t page_size = bh__page_size();
    size_t done = 0;

    if ((dst == NULL) || (src == NULL) || size == 0) {
        return size == 0 ? 0 : -1;
    }

    while (done < size) {
        uintptr_t current = (uintptr_t)source + done;
        uintptr_t page_start = bh__align_down_ptr(current, page_size);
        size_t page_end = page_start + page_size;
        size_t chunk = size - done;
        int prot = 0;

        if ((uintptr_t)current + chunk > page_end) {
            chunk = page_end - current;
        }
        if (bh__protect_query(current, &prot) != 0) {
            return -1;
        }
        if ((prot & PROT_READ) != 0) {
            memcpy(destination + done, source + done, chunk);
        } else {
            if (mprotect((void *)page_start, page_size, prot | PROT_READ) != 0) {
                return -1;
            }
            memcpy(destination + done, source + done, chunk);
            (void)mprotect((void *)page_start, page_size, prot);
        }
        done += chunk;
    }
    return 0;
}

static void bh__restore_page_protections(uintptr_t first_page, size_t page_size,
                                         size_t page_count,
                                         const int *saved_prot) {
    size_t i;
    for (i = 0; i < page_count; i++) {
        (void)mprotect((void *)(first_page + i * page_size), page_size,
                       saved_prot[i]);
    }
}

int bh__write_code(void *dst, const void *src, size_t size) {
    uint8_t *destination = (uint8_t *)dst;
    const uint8_t *source = (const uint8_t *)src;
    size_t page_size = bh__page_size();
    uintptr_t first_page;
    uintptr_t last_page;
    size_t page_count;
    int *saved_prot = NULL;
    size_t i;
    int result = -1;

    if ((dst == NULL) || (src == NULL) || size == 0) {
        return size == 0 ? 0 : -1;
    }

    first_page = bh__align_down_ptr((uintptr_t)dst, page_size);
    last_page = bh__align_down_ptr((uintptr_t)dst + size - 1, page_size);
    page_count = ((last_page - first_page) / page_size) + 1;

    saved_prot = (int *)malloc(page_count * sizeof(int));
    if (saved_prot == NULL) {
        return -1;
    }

    for (i = 0; i < page_count; i++) {
        uintptr_t page = first_page + i * page_size;
        int prot = 0;
        if (bh__protect_query(page, &prot) != 0) {
            bh__restore_page_protections(first_page, page_size, i, saved_prot);
            goto cleanup;
        }
        saved_prot[i] = prot;
        if (mprotect((void *)page, page_size, prot | PROT_READ | PROT_WRITE) != 0) {
            bh__restore_page_protections(first_page, page_size, i, saved_prot);
            goto cleanup;
        }
    }

    memcpy(destination, source, size);
    bh__flush_cache(dst, size);

    bh__restore_page_protections(first_page, page_size, page_count, saved_prot);
    result = 0;

cleanup:
    free(saved_prot);
    return result;
}

uintptr_t bh__read_pointer(const void *address) {
    return __atomic_load_n((const uintptr_t *)address, __ATOMIC_ACQUIRE);
}

int bh__write_pointer(void *address, uintptr_t value) {
    size_t page_size = bh__page_size();
    uintptr_t page = bh__align_down_ptr((uintptr_t)address, page_size);
    int prot = 0;

    if (bh__protect_query((uintptr_t)address, &prot) != 0) {
        return -1;
    }
    if ((prot & PROT_WRITE) == 0) {
        if (mprotect((void *)page, page_size, prot | PROT_READ | PROT_WRITE) != 0) {
            return -1;
        }
    }
    __atomic_store_n((uintptr_t *)address, value, __ATOMIC_RELEASE);
    if ((prot & PROT_WRITE) == 0) {
        (void)mprotect((void *)page, page_size, prot);
    }
    return 0;
}

int bh__make_executable(void *address, size_t size) {
    size_t page_size = bh__page_size();
    uintptr_t start;
    size_t length;

    if (address == NULL || size == 0) {
        return -1;
    }
    start = bh__align_down_ptr((uintptr_t)address, page_size);
    length = bh__align_up((uintptr_t)address + size - start, page_size);
    return mprotect((void *)start, length, PROT_READ | PROT_EXEC);
}

int bh__free_pages(void *ptr, size_t size) {
    size_t page_size;
    if (ptr == NULL) {
        return 0;
    }
    page_size = bh__page_size();
    return munmap(ptr, bh__align_up(size, page_size));
}

typedef struct bh_gap {
    uintptr_t start;
    uintptr_t end;
    uintptr_t distance;
} bh_gap_t;

static uintptr_t bh__align_up_ptr(uintptr_t value, size_t alignment) {
    uintptr_t mask = (uintptr_t)alignment - 1u;
    if (value > UINTPTR_MAX - mask) {
        return UINTPTR_MAX & ~mask;
    }
    return (value + mask) & ~mask;
}

static int bh__mapping_within_distance(uintptr_t address, uintptr_t target,
                                       size_t allocation_size,
                                       size_t max_distance) {
    if (address >= target) {
        if (max_distance < allocation_size) {
            return 0;
        }
        return address - target <= max_distance - allocation_size;
    }
    return target - address <= max_distance;
}

static int bh__gap_compare(const void *lhs, const void *rhs) {
    const bh_gap_t *a = (const bh_gap_t *)lhs;
    const bh_gap_t *b = (const bh_gap_t *)rhs;
    if (a->distance < b->distance) return -1;
    if (a->distance > b->distance) return 1;
    return 0;
}

void *bh__alloc_near(uintptr_t target, size_t size, size_t max_distance) {
    bh_map_entry_t *maps = NULL;
    size_t map_count = 0;
    size_t page_size;
    size_t allocation_size;
    bh_gap_t *gaps = NULL;
    size_t gap_count = 0;
    size_t i;
    void *result = NULL;
    uintptr_t low_limit;
    uintptr_t high_limit;

    if (target == 0 || size == 0) {
        return NULL;
    }

    page_size = bh__page_size();
    if (page_size == 0 || (page_size & (page_size - 1u)) != 0) {
        return NULL;
    }
    if (size > SIZE_MAX - (page_size - 1u)) {
        return NULL;
    }
    allocation_size = bh__align_up(size, page_size);
    if (allocation_size == 0) {
        return NULL;
    }
    if (bh__parse_maps(&maps, &map_count) != 0 || map_count == 0) {
        free(maps);
        return NULL;
    }

    low_limit = max_distance > target ? 0 : target - max_distance;
    high_limit = target + max_distance;
    if (high_limit < target) {
        high_limit = UINTPTR_MAX;
    }

    gaps = (bh_gap_t *)calloc(map_count + 1, sizeof(bh_gap_t));
    if (gaps == NULL) {
        free(maps);
        return NULL;
    }

    for (i = 0; i <= map_count; i++) {
        uintptr_t gap_start;
        uintptr_t gap_end;
        uintptr_t aligned_start;
        uintptr_t aligned_end;

        if (i == 0) {
            gap_start = low_limit;
            gap_end = maps[0].start;
        } else if (i == map_count) {
            gap_start = maps[map_count - 1].end;
            gap_end = high_limit;
        } else {
            gap_start = maps[i - 1].end;
            gap_end = maps[i].start;
        }

        if (gap_end <= gap_start) {
            continue;
        }
        if (gap_end > high_limit) {
            gap_end = high_limit;
        }
        if (gap_start < low_limit) {
            gap_start = low_limit;
        }
        if (gap_end <= gap_start) {
            continue;
        }

        aligned_start = bh__align_up_ptr(gap_start, page_size);
        aligned_end = bh__align_down_ptr(gap_end, page_size);
        if (aligned_start < page_size) {
            aligned_start = page_size;
        }
        if (aligned_end <= aligned_start ||
            aligned_end - aligned_start < allocation_size) {
            continue;
        }

        gaps[gap_count].start = aligned_start;
        gaps[gap_count].end = aligned_end;
        if (target < aligned_start) {
            gaps[gap_count].distance = aligned_start - target;
        } else if (target >= aligned_end) {
            gaps[gap_count].distance = target - aligned_end;
        } else {
            gaps[gap_count].distance = 0;
        }
        gap_count++;
    }

    if (gap_count > 1) {
        qsort(gaps, gap_count, sizeof(bh_gap_t), bh__gap_compare);
    }

    for (i = 0; i < gap_count && i < 64; i++) {
        uintptr_t gap_start = gaps[i].start;
        uintptr_t gap_end = gaps[i].end;
        uintptr_t last_start = gap_end - allocation_size;
        uintptr_t hint;
        uintptr_t address;

        if (target < gap_start) {
            hint = gap_start;
        } else if (target >= gap_end) {
            hint = last_start;
        } else {
            hint = bh__align_down_ptr(target, page_size);
            if (hint < gap_start) {
                hint = gap_start;
            }
            if (hint > last_start) {
                hint = last_start;
            }
        }

        result = mmap((void *)hint, allocation_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (result == MAP_FAILED) {
            result = NULL;
            continue;
        }

        address = (uintptr_t)result;
        if (address < gap_start || address > last_start ||
            (address & (uintptr_t)(page_size - 1u)) != 0 ||
            !bh__mapping_within_distance(address, target, allocation_size,
                                         max_distance)) {
            (void)munmap(result, allocation_size);
            result = NULL;
            continue;
        }
        break;
    }

    if (result == NULL) {
        result = mmap(NULL, allocation_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (result != MAP_FAILED) {
            uintptr_t address = (uintptr_t)result;
            if ((address & (uintptr_t)(page_size - 1u)) != 0 ||
                !bh__mapping_within_distance(address, target, allocation_size,
                                             max_distance)) {
                (void)munmap(result, allocation_size);
                result = NULL;
            }
        } else {
            result = NULL;
        }
    }

    free(gaps);
    free(maps);
    return result;
}
