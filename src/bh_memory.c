/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE 1

#include "bh_internal.h"

#include <elf.h>
#include <errno.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#  define MAP_ANONYMOUS MAP_ANON
#endif

#if defined(__aarch64__)
#  define BH_PROT_BTI 0x10
#  ifndef PT_GNU_PROPERTY
#    define PT_GNU_PROPERTY 0x6474e553
#  endif
#  ifndef NT_GNU_PROPERTY_TYPE_0
#    define NT_GNU_PROPERTY_TYPE_0 5
#  endif
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

#if defined(__aarch64__)

typedef struct bh_gnu_property {
    uint32_t pr_type;
    uint32_t pr_datasz;
} bh_gnu_property_t;

typedef struct bh_bti_query {
    uintptr_t address;
    int found;
} bh_bti_query_t;

static int bh__gnu_note_has_bti(uintptr_t note, size_t size) {
    uintptr_t cursor = note;
    uintptr_t end = note + size;

    if (end < note) {
        return 0;
    }
    while (cursor + sizeof(ElfW(Nhdr)) <= end) {
        const ElfW(Nhdr) *header = (const ElfW(Nhdr) *)cursor;
        size_t namesz = header->n_namesz;
        size_t descsz = header->n_descsz;
        uintptr_t name = cursor + sizeof(*header);
        uintptr_t desc = name + ((namesz + 3u) & ~(size_t)3u);
        uintptr_t next = desc + ((descsz + 3u) & ~(size_t)3u);

        if (next <= cursor || next > end) {
            break;
        }
        if (header->n_type == NT_GNU_PROPERTY_TYPE_0 && namesz >= 3 &&
            memcmp((const void *)name, "GNU", 3) == 0) {
            uintptr_t prop = desc;
            uintptr_t prop_end = desc + descsz;

            while (prop + sizeof(bh_gnu_property_t) <= prop_end) {
                const bh_gnu_property_t *entry =
                    (const bh_gnu_property_t *)prop;
                size_t datasz = entry->pr_datasz;
                size_t align = sizeof(uintptr_t);
                uintptr_t data = prop + sizeof(*entry);
                uintptr_t next_prop =
                    data + ((datasz + align - 1u) & ~(align - 1u));

                if (next_prop <= prop || next_prop > prop_end) {
                    break;
                }
                if (entry->pr_type == 0xc0000000u && datasz >= 4) {
                    uint32_t flags = 0;
                    memcpy(&flags, (const void *)data, sizeof(flags));
                    if ((flags & 1u) != 0) {
                        return 1;
                    }
                }
                prop = next_prop;
            }
        }
        cursor = next;
    }
    return 0;
}

static int bh__bti_query_callback(struct dl_phdr_info *info, size_t size,
                                  void *data) {
    bh_bti_query_t *query = (bh_bti_query_t *)data;
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    size_t i;
    int in_executable = 0;

    (void)size;
    for (i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        uintptr_t start;
        uintptr_t end;

        if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_X) == 0) {
            continue;
        }
        start = base + (uintptr_t)phdr->p_vaddr;
        if (start < base) {
            continue;
        }
        end = start + (uintptr_t)phdr->p_memsz;
        if (end < start) {
            continue;
        }
        if (query->address >= start && query->address < end) {
            in_executable = 1;
            break;
        }
    }
    if (!in_executable) {
        return 0;
    }
    for (i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        uintptr_t note;
        size_t note_size;

        if (phdr->p_type != PT_GNU_PROPERTY) {
            continue;
        }
        note = base + (uintptr_t)phdr->p_vaddr;
        note_size = (size_t)phdr->p_memsz;
        if (bh__gnu_note_has_bti(note, note_size)) {
            query->found = 1;
            return 1;
        }
    }
    return 0;
}

#  define BH_SMAPS_LINE_SIZE 512
#  define BH_SMAPS_MAX_TOKENS 64
#  define BH_SMAPS_MAX_LINES 262144

static int bh__smaps_has_bti(uintptr_t address) {
    FILE *fp;
    char line[BH_SMAPS_LINE_SIZE];
    int in_mapping = 0;
    int result = 0;
    size_t lines = 0;

    if (address == 0) {
        return 0;
    }
    fp = fopen("/proc/self/smaps", "r");
    if (fp == NULL) {
        return 0;
    }

    while (lines < BH_SMAPS_MAX_LINES && fgets(line, sizeof(line), fp) != NULL) {
        unsigned long start = 0;
        unsigned long end = 0;
        char perms[8] = {0};

        lines++;
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3 &&
            end > start) {
            if (in_mapping) {
                break;
            }
            if (address >= (uintptr_t)start && address < (uintptr_t)end) {
                in_mapping = 1;
            }
            continue;
        }
        if (!in_mapping || strncmp(line, "VmFlags:", 8) != 0) {
            continue;
        }
        {
            char *save = NULL;
            char *token;
            size_t tokens = 0;

            for (token = strtok_r(line + 8, " \t\r\n", &save);
                 token != NULL && tokens < BH_SMAPS_MAX_TOKENS;
                 token = strtok_r(NULL, " \t\r\n", &save)) {
                tokens++;
                if (strcmp(token, "bt") == 0) {
                    result = 1;
                    break;
                }
            }
        }
        break;
    }

    fclose(fp);
    return result;
}

int bh__page_has_bti(uintptr_t address) {
    bh_bti_query_t query;

    query.address = address;
    query.found = 0;
    (void)dl_iterate_phdr(bh__bti_query_callback, &query);
    if (query.found) {
        return 1;
    }
    return bh__smaps_has_bti(address);
}

static int bh__bti_enabled(void) {
    static int cached = -1;
    int value = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);

    if (value < 0) {
        size_t page_size = bh__page_size();
        void *probe = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (probe != MAP_FAILED) {
            value = mprotect(probe, page_size,
                             PROT_READ | PROT_EXEC | BH_PROT_BTI) == 0;
            (void)munmap(probe, page_size);
        } else {
            value = 0;
        }
        __atomic_store_n(&cached, value, __ATOMIC_RELEASE);
    }
    return value;
}

#else

int bh__page_has_bti(uintptr_t address) {
    (void)address;
    return 0;
}

#endif

static int bh__page_protection(uintptr_t page, int prot) {
#if defined(__aarch64__)
    if ((prot & PROT_EXEC) != 0 && bh__bti_enabled() &&
        bh__page_has_bti(page)) {
        prot |= BH_PROT_BTI;
    }
#else
    (void)page;
#endif
    return prot;
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

static int bh__map_query(uintptr_t address, int *prot) {
    bh_map_entry_t *maps = NULL;
    size_t count = 0;
    const bh_map_entry_t *entry;
    int result = 0;

    if (bh__parse_maps(&maps, &count) != 0) {
        return -1;
    }
    entry = bh__find_map(maps, count, address);
    if (entry != NULL) {
        if (prot != NULL) {
            *prot = entry->prot;
        }
        result = 1;
    }
    free(maps);
    return result;
}

int bh__protect_query(uintptr_t address, int *prot) {
    if (prot == NULL) {
        return -1;
    }
    return bh__map_query(address, prot) == 1 ? 0 : -1;
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

static int bh__copy_code_impl(void *dst, const void *src, size_t size,
                              int allow_partial, size_t *out_copied) {
    const uint8_t *source = (const uint8_t *)src;
    uint8_t *destination = (uint8_t *)dst;
    size_t page_size = bh__page_size();
    size_t done = 0;

    if (out_copied != NULL) {
        *out_copied = 0;
    }
    if (size == 0) {
        return 0;
    }
    if ((dst == NULL) || (src == NULL)) {
        return -1;
    }

    while (done < size) {
        uintptr_t current = (uintptr_t)source + done;
        uintptr_t page_start = bh__align_down_ptr(current, page_size);
        size_t page_end = page_start + page_size;
        size_t chunk = size - done;
        int prot = 0;
        int mapped;

        if (chunk > page_end - current) {
            chunk = page_end - current;
        }

        mapped = bh__map_query(page_start, &prot);
        if (mapped < 0) {
            return -1;
        }
        if (mapped == 0) {
            if (!allow_partial) {
                return -1;
            }
            memset(destination + done, 0, size - done);
            break;
        }
        if ((prot & PROT_READ) != 0) {
            memcpy(destination + done, source + done, chunk);
        } else {
            int page_prot = bh__page_protection(page_start, prot);
            if (mprotect((void *)page_start, page_size,
                         page_prot | PROT_READ) != 0) {
                return -1;
            }
            memcpy(destination + done, source + done, chunk);
            if (mprotect((void *)page_start, page_size, page_prot) != 0) {
                return -1;
            }
        }
        done += chunk;
    }

    if (out_copied != NULL) {
        *out_copied = done;
    }
    return 0;
}

int bh__copy_code(void *dst, const void *src, size_t size) {
    return bh__copy_code_impl(dst, src, size, 0, NULL);
}

int bh__copy_code_partial(void *dst, const void *src, size_t size,
                          size_t *copied) {
    if (copied == NULL) {
        return -1;
    }
    return bh__copy_code_impl(dst, src, size, 1, copied);
}

static int bh__restore_page_protections(uintptr_t first_page, size_t page_size,
                                        size_t page_count,
                                        const int *saved_prot) {
    size_t i;
    int result = 0;
    for (i = 0; i < page_count; i++) {
        if (mprotect((void *)(first_page + i * page_size), page_size,
                     saved_prot[i]) != 0) {
            result = -1;
        }
    }
    return result;
}

int bh__write_code(void *dst, const void *src, size_t size) {
    int preserve_bti = 0;

    if (dst != NULL) {
        preserve_bti = bh__page_has_bti((uintptr_t)dst);
    }
    return bh__write_code_ex(dst, src, size, preserve_bti);
}

static int bh__write_code_atomic(uint8_t *dst, const uint8_t *src,
                                 size_t size) {
#if defined(__SANITIZE_THREAD__)
    (void)dst;
    (void)src;
    (void)size;
    return 0;
#else
    if (size == 4 && (((uintptr_t)dst) & 3u) == 0) {
        uint32_t value;
        memcpy(&value, src, sizeof(value));
        __atomic_store_n((uint32_t *)dst, value, __ATOMIC_RELEASE);
        return 1;
    }
    if (size == 8 && (((uintptr_t)dst) & 3u) == 0) {
        uint32_t prefix;
        uint32_t value;
        memcpy(&prefix, src, sizeof(prefix));
        if (__atomic_load_n((uint32_t *)dst, __ATOMIC_ACQUIRE) != prefix) {
            return 0;
        }
        memcpy(&value, src + 4, sizeof(value));
        __atomic_store_n((uint32_t *)(dst + 4), value, __ATOMIC_RELEASE);
        return 1;
    }
#if defined(__x86_64__)
    if (size == 5 && (((uintptr_t)dst) & 7u) == 0) {
        uint64_t value = 0;
        uint64_t current;

        memcpy(&value, src, 5);
        current = __atomic_load_n((uint64_t *)dst, __ATOMIC_ACQUIRE);
        for (;;) {
            uint64_t desired =
                (current & ~UINT64_C(0xFFFFFFFFFF)) | value;
            if (__atomic_compare_exchange_n((uint64_t *)dst, &current, desired,
                                            0, __ATOMIC_ACQ_REL,
                                            __ATOMIC_ACQUIRE)) {
                break;
            }
        }
        return 1;
    }
#endif
    return 0;
#endif
}

int bh__write_code_ex(void *dst, const void *src, size_t size,
                      int preserve_bti) {
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
        int page_prot;
        if (bh__protect_query(page, &prot) != 0) {
            (void)bh__restore_page_protections(first_page, page_size, i,
                                               saved_prot);
            goto cleanup;
        }
        page_prot = prot;
#if defined(__aarch64__)
        if (preserve_bti && bh__bti_enabled()) {
            page_prot |= BH_PROT_BTI;
        }
#else
        (void)preserve_bti;
#endif
        saved_prot[i] = page_prot;
        if (mprotect((void *)page, page_size,
                     page_prot | PROT_READ | PROT_WRITE) != 0) {
#if defined(__aarch64__)
            if ((page_prot & BH_PROT_BTI) != 0) {
                page_prot &= ~BH_PROT_BTI;
                saved_prot[i] = page_prot;
                if (mprotect((void *)page, page_size,
                             page_prot | PROT_READ | PROT_WRITE) != 0) {
                    (void)bh__restore_page_protections(first_page, page_size,
                                                       i, saved_prot);
                    goto cleanup;
                }
            } else
#endif
            {
                (void)bh__restore_page_protections(first_page, page_size, i,
                                                   saved_prot);
                goto cleanup;
            }
        }
    }

    if (bh__write_code_atomic(destination, source, size) == 0) {
        memcpy(destination, source, size);
    }
    bh__flush_cache(dst, size);

    if (bh__restore_page_protections(first_page, page_size, page_count,
                                     saved_prot) != 0) {
        goto cleanup;
    }
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
    int page_prot;
    int changed = 0;

    if (bh__protect_query((uintptr_t)address, &prot) != 0) {
        return -1;
    }
    page_prot = bh__page_protection(page, prot);
    if ((page_prot & PROT_WRITE) == 0) {
        if (mprotect((void *)page, page_size,
                     page_prot | PROT_READ | PROT_WRITE) != 0) {
            return -1;
        }
        changed = 1;
    }
    __atomic_store_n((uintptr_t *)address, value, __ATOMIC_RELEASE);
    if (changed && mprotect((void *)page, page_size, page_prot) != 0) {
        return -1;
    }
    return 0;
}

int bh__cas_pointer(void *address, uintptr_t expected, uintptr_t desired) {
    size_t page_size = bh__page_size();
    uintptr_t page = bh__align_down_ptr((uintptr_t)address, page_size);
    int prot = 0;
    int page_prot;
    int changed = 0;
    int result;

    if (bh__protect_query((uintptr_t)address, &prot) != 0) {
        return -1;
    }
    page_prot = bh__page_protection(page, prot);
    if ((page_prot & PROT_WRITE) == 0) {
        if (mprotect((void *)page, page_size,
                     page_prot | PROT_READ | PROT_WRITE) != 0) {
            return -1;
        }
        changed = 1;
    }
    result = __atomic_compare_exchange_n((uintptr_t *)address, &expected,
                                         desired, 0, __ATOMIC_ACQ_REL,
                                         __ATOMIC_ACQUIRE)
                 ? 1
                 : 0;
    if (changed && mprotect((void *)page, page_size, page_prot) != 0) {
        return -1;
    }
    return result;
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
                                       size_t max_distance) {
    if (address >= target) {
        return address - target <= max_distance;
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
    uintptr_t high_limit_aligned;

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
    high_limit_aligned = bh__align_down_ptr(high_limit, page_size);

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
        uintptr_t last_start;

        if (i == 0) {
            gap_start = low_limit;
            gap_end = maps[0].start;
        } else if (i == map_count) {
            gap_start = maps[map_count - 1].end;
            gap_end = UINTPTR_MAX;
        } else {
            gap_start = maps[i - 1].end;
            gap_end = maps[i].start;
        }

        if (gap_end <= gap_start) {
            continue;
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

        last_start = aligned_end - allocation_size;
        if (last_start > high_limit_aligned) {
            last_start = high_limit_aligned;
        }
        if (last_start < aligned_start) {
            continue;
        }

        gaps[gap_count].start = aligned_start;
        gaps[gap_count].end = last_start;
        if (target < aligned_start) {
            gaps[gap_count].distance = aligned_start - target;
        } else if (target > last_start) {
            gaps[gap_count].distance = target - last_start;
        } else {
            gaps[gap_count].distance = 0;
        }
        gap_count++;
    }

    if (gap_count > 1) {
        qsort(gaps, gap_count, sizeof(bh_gap_t), bh__gap_compare);
    }

    for (i = 0; i < gap_count; i++) {
        uintptr_t gap_start = gaps[i].start;
        uintptr_t gap_end = gaps[i].end;
        uintptr_t hint;
        uintptr_t address;

        if (target < gap_start) {
            hint = gap_start;
        } else if (target > gap_end) {
            hint = gap_end;
        } else {
            hint = bh__align_down_ptr(target, page_size);
            if (hint < gap_start) {
                hint = gap_start;
            }
            if (hint > gap_end) {
                hint = gap_end;
            }
        }

        result = mmap((void *)hint, allocation_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (result == MAP_FAILED) {
            result = NULL;
            continue;
        }

        address = (uintptr_t)result;
        if (address < gap_start || address > gap_end ||
            (address & (uintptr_t)(page_size - 1u)) != 0 ||
            !bh__mapping_within_distance(address, target, max_distance)) {
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
                !bh__mapping_within_distance(address, target, max_distance)) {
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
