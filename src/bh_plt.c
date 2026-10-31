/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE 1

#include "bhplt.h"
#include "bh_internal.h"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <limits.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct bh_plt_record {
    uintptr_t slot;
    uintptr_t saved_value;
    void *replacement;
    void *resolved;
    char *image;
    char *symbol;
    int active;
    struct bh_plt_record *next;
} bh_plt_record_t;

typedef struct bh_plt_candidate {
    uintptr_t slot;
    void *resolved;
    char *image;
    char *symbol;
    int is_main;
    int symbol_undefined;
} bh_plt_candidate_t;

typedef struct bh_plt_collect {
    bh_plt_candidate_t *items;
    size_t count;
    size_t capacity;
    const char *image;
    const char *symbol;
    int failed;
} bh_plt_collect_t;

static pthread_mutex_t bh_plt_lock = PTHREAD_MUTEX_INITIALIZER;
static bh_plt_record_t *bh_plt_records = NULL;

#if defined(__LP64__)
typedef Elf64_Ehdr bh_elf_ehdr_t;
typedef Elf64_Phdr bh_elf_phdr_t;
typedef Elf64_Dyn bh_elf_dyn_t;
typedef Elf64_Sym bh_elf_sym_t;
typedef Elf64_Rel bh_elf_rel_t;
typedef Elf64_Rela bh_elf_rela_t;
#  define BH_ELF_R_SYM ELF64_R_SYM
#  define BH_ELF_R_TYPE ELF64_R_TYPE
#else
typedef Elf32_Ehdr bh_elf_ehdr_t;
typedef Elf32_Phdr bh_elf_phdr_t;
typedef Elf32_Dyn bh_elf_dyn_t;
typedef Elf32_Sym bh_elf_sym_t;
typedef Elf32_Rel bh_elf_rel_t;
typedef Elf32_Rela bh_elf_rela_t;
#  define BH_ELF_R_SYM ELF32_R_SYM
#  define BH_ELF_R_TYPE ELF32_R_TYPE
#endif

#if defined(__aarch64__)
#  define BH_PLT_JUMP_SLOT R_AARCH64_JUMP_SLOT
#  define BH_PLT_GLOB_DAT R_AARCH64_GLOB_DAT
#  define BH_PLT_HAS_GLOB_DAT 1
#elif defined(__arm__)
#  define BH_PLT_JUMP_SLOT R_ARM_JUMP_SLOT
#  define BH_PLT_GLOB_DAT R_ARM_GLOB_DAT
#  define BH_PLT_HAS_GLOB_DAT 1
#elif defined(__x86_64__)
#  define BH_PLT_JUMP_SLOT R_X86_64_JUMP_SLOT
#  define BH_PLT_GLOB_DAT R_X86_64_GLOB_DAT
#  define BH_PLT_HAS_GLOB_DAT 1
#elif defined(__i386__)
#  define BH_PLT_JUMP_SLOT R_386_JMP_SLOT
#  define BH_PLT_GLOB_DAT R_386_GLOB_DAT
#  define BH_PLT_HAS_GLOB_DAT 1
#elif defined(__riscv) && (__riscv_xlen == 64)
#  define BH_PLT_JUMP_SLOT R_RISCV_JUMP_SLOT
#  define BH_PLT_GLOB_DAT R_RISCV_64
#  define BH_PLT_HAS_GLOB_DAT 1
#else
#  define BH_PLT_HAS_GLOB_DAT 0
#endif

static int bh_plt_image_matches(const char *requested, const char *path) {
    const char *base;
    size_t requested_length;
    size_t path_length;

    if (requested == NULL || requested[0] == '\0') {
        return 1;
    }
    if (path == NULL) {
        return 0;
    }
    if (strcmp(requested, path) == 0) {
        return 1;
    }

    base = strrchr(path, '/');
    if (base != NULL && strcmp(requested, base + 1) == 0) {
        return 1;
    }

    requested_length = strlen(requested);
    path_length = strlen(path);
    if (requested_length <= path_length) {
        const char *suffix = path + (path_length - requested_length);
        if (strcmp(suffix, requested) == 0) {
            if (suffix == path || suffix[-1] == '/') {
                return 1;
            }
        }
    }
    return 0;
}

static int bh_plt_add_candidate(bh_plt_collect_t *collect, uintptr_t slot,
                                const char *image, const char *symbol,
                                int is_main, int symbol_undefined) {
    bh_plt_candidate_t *candidate;
    size_t i;

    for (i = 0; i < collect->count; i++) {
        if (collect->items[i].slot == slot) {
            return 0;
        }
    }

    if (collect->count == collect->capacity) {
        size_t new_capacity = collect->capacity == 0 ? 16 : collect->capacity * 2;
        bh_plt_candidate_t *new_items = (bh_plt_candidate_t *)realloc(
            collect->items, new_capacity * sizeof(*new_items));
        if (new_items == NULL) {
            collect->failed = 1;
            return -1;
        }
        collect->items = new_items;
        collect->capacity = new_capacity;
    }

    candidate = &collect->items[collect->count];
    memset(candidate, 0, sizeof(*candidate));
    candidate->slot = slot;
    candidate->image = strdup(image != NULL ? image : "");
    candidate->symbol = strdup(symbol != NULL ? symbol : "");
    candidate->is_main = is_main;
    candidate->symbol_undefined = symbol_undefined;
    if (candidate->image == NULL || candidate->symbol == NULL) {
        free(candidate->image);
        free(candidate->symbol);
        collect->failed = 1;
        return -1;
    }
    collect->count++;
    return 0;
}

static uintptr_t bh_plt_normalize_dynamic_pointer(uintptr_t value,
                                                   uintptr_t base) {
    if (value == 0) {
        return 0;
    }
    if (base != 0 && value < base) {
        return value + base;
    }
    return value;
}

static char bh_plt_main_path[PATH_MAX];
static pthread_once_t bh_plt_main_path_once = PTHREAD_ONCE_INIT;

static void bh_plt_init_main_image_path(void) {
    ssize_t length = readlink("/proc/self/exe", bh_plt_main_path,
                              sizeof(bh_plt_main_path) - 1);
    if (length > 0) {
        bh_plt_main_path[length] = '\0';
    } else {
        bh_plt_main_path[0] = '\0';
    }
}

static const char *bh_plt_main_image_path(void) {
    (void)pthread_once(&bh_plt_main_path_once, bh_plt_init_main_image_path);
    return bh_plt_main_path;
}

static void bh_plt_scan_image(struct dl_phdr_info *info,
                              bh_plt_collect_t *collect) {
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    const char *raw_image = info->dlpi_name != NULL ? info->dlpi_name : "";
    int is_main = raw_image[0] == '\0';
    const char *image = is_main ? bh_plt_main_image_path() : raw_image;
    const bh_elf_phdr_t *dynamic_phdr = NULL;
    const bh_elf_dyn_t *dynamic = NULL;
    size_t dynamic_count = 0;
    uintptr_t strtab = 0;
    uintptr_t symtab = 0;
    uintptr_t jmprel = 0;
    size_t pltrelsz = 0;
    uintptr_t rela = 0;
    size_t relasz = 0;
    uintptr_t rel = 0;
    size_t relsz = 0;
    size_t syment = 0;
    size_t strsz = 0;
#if defined(__LP64__)
    int pltrel_is_rela = 1;
#else
    int pltrel_is_rela = 0;
#endif
    size_t i;

    if (!bh_plt_image_matches(collect->image, image)) {
        return;
    }

    for (i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dynamic_phdr = (const bh_elf_phdr_t *)&info->dlpi_phdr[i];
            break;
        }
    }
    if (dynamic_phdr == NULL) {
        return;
    }

    dynamic = (const bh_elf_dyn_t *)(base + dynamic_phdr->p_vaddr);
    dynamic_count = dynamic_phdr->p_memsz / sizeof(bh_elf_dyn_t);

    for (i = 0; i < dynamic_count; i++) {
        switch (dynamic[i].d_tag) {
            case DT_STRTAB:
                strtab = bh_plt_normalize_dynamic_pointer(
                    (uintptr_t)dynamic[i].d_un.d_ptr, base);
                break;
            case DT_SYMTAB:
                symtab = bh_plt_normalize_dynamic_pointer(
                    (uintptr_t)dynamic[i].d_un.d_ptr, base);
                break;
            case DT_STRSZ:
                strsz = (size_t)dynamic[i].d_un.d_val;
                break;
            case DT_SYMENT:
                syment = (size_t)dynamic[i].d_un.d_val;
                break;
            case DT_JMPREL:
                jmprel = bh_plt_normalize_dynamic_pointer(
                    (uintptr_t)dynamic[i].d_un.d_ptr, base);
                break;
            case DT_PLTRELSZ:
                pltrelsz = (size_t)dynamic[i].d_un.d_val;
                break;
            case DT_PLTREL:
                pltrel_is_rela = dynamic[i].d_un.d_val == DT_RELA;
                break;
            case DT_RELA:
                rela = bh_plt_normalize_dynamic_pointer(
                    (uintptr_t)dynamic[i].d_un.d_ptr, base);
                break;
            case DT_RELASZ:
                relasz = (size_t)dynamic[i].d_un.d_val;
                break;
            case DT_REL:
                rel = bh_plt_normalize_dynamic_pointer(
                    (uintptr_t)dynamic[i].d_un.d_ptr, base);
                break;
            case DT_RELSZ:
                relsz = (size_t)dynamic[i].d_un.d_val;
                break;
            case DT_NULL:
                i = dynamic_count;
                break;
            default:
                break;
        }
    }

    if (strtab == 0 || symtab == 0 || jmprel == 0 || pltrelsz == 0) {
        return;
    }
    if (syment == 0) {
        syment = sizeof(bh_elf_sym_t);
    }
    if (syment < sizeof(bh_elf_sym_t)) {
        return;
    }

    if (pltrel_is_rela) {
        const bh_elf_rela_t *rel =
            (const bh_elf_rela_t *)jmprel;
        size_t count = pltrelsz / sizeof(bh_elf_rela_t);
        for (i = 0; i < count; i++) {
            unsigned type = (unsigned)BH_ELF_R_TYPE(rel[i].r_info);
            unsigned symbol_index = (unsigned)BH_ELF_R_SYM(rel[i].r_info);
            const bh_elf_sym_t *symbol;
            const char *name;
            uintptr_t slot;
            int match = type == (unsigned)BH_PLT_JUMP_SLOT;

#if BH_PLT_HAS_GLOB_DAT
            if (type == (unsigned)BH_PLT_GLOB_DAT) match = 1;
#endif
            if (!match) continue;

            symbol = (const bh_elf_sym_t *)(symtab + symbol_index * syment);
            if (symbol->st_name == 0) continue;
            if (strsz != 0 && (size_t)symbol->st_name >= strsz) continue;
            if (strtab + symbol->st_name < strtab) continue;
            name = (const char *)(strtab + symbol->st_name);
            if (strcmp(name, collect->symbol) != 0) continue;

            slot = base + (uintptr_t)rel[i].r_offset;
            if (bh_plt_add_candidate(collect, slot, image, name, is_main,
                                     symbol->st_shndx == SHN_UNDEF) != 0) {
                return;
            }
        }
    } else {
        const bh_elf_rel_t *rel = (const bh_elf_rel_t *)jmprel;
        size_t count = pltrelsz / sizeof(bh_elf_rel_t);
        for (i = 0; i < count; i++) {
            unsigned type = (unsigned)BH_ELF_R_TYPE(rel[i].r_info);
            unsigned symbol_index = (unsigned)BH_ELF_R_SYM(rel[i].r_info);
            const bh_elf_sym_t *symbol;
            const char *name;
            uintptr_t slot;
            int match = type == (unsigned)BH_PLT_JUMP_SLOT;

#if BH_PLT_HAS_GLOB_DAT
            if (type == (unsigned)BH_PLT_GLOB_DAT) match = 1;
#endif
            if (!match) continue;

            symbol = (const bh_elf_sym_t *)(symtab + symbol_index * syment);
            if (symbol->st_name == 0) continue;
            if (strsz != 0 && (size_t)symbol->st_name >= strsz) continue;
            if (strtab + symbol->st_name < strtab) continue;
            name = (const char *)(strtab + symbol->st_name);
            if (strcmp(name, collect->symbol) != 0) continue;

            slot = base + (uintptr_t)rel[i].r_offset;
            if (bh_plt_add_candidate(collect, slot, image, name, is_main,
                                     symbol->st_shndx == SHN_UNDEF) != 0) {
                return;
            }
        }
    }

#if BH_PLT_HAS_GLOB_DAT
    if (rela != 0 && relasz >= sizeof(bh_elf_rela_t)) {
        const bh_elf_rela_t *table = (const bh_elf_rela_t *)rela;
        size_t count = relasz / sizeof(bh_elf_rela_t);
        for (i = 0; i < count; i++) {
            unsigned type = (unsigned)BH_ELF_R_TYPE(table[i].r_info);
            unsigned symbol_index = (unsigned)BH_ELF_R_SYM(table[i].r_info);
            const bh_elf_sym_t *symbol;
            const char *name;
            uintptr_t slot;

            if (type != (unsigned)BH_PLT_GLOB_DAT) continue;
            symbol = (const bh_elf_sym_t *)(symtab + symbol_index * syment);
            if (symbol->st_name == 0) continue;
            if (strsz != 0 && (size_t)symbol->st_name >= strsz) continue;
            name = (const char *)(strtab + symbol->st_name);
            if (strcmp(name, collect->symbol) != 0) continue;
            slot = base + (uintptr_t)table[i].r_offset;
            if (bh_plt_add_candidate(collect, slot, image, name, is_main,
                                     symbol->st_shndx == SHN_UNDEF) != 0) {
                return;
            }
        }
    }
    if (rel != 0 && relsz >= sizeof(bh_elf_rel_t)) {
        const bh_elf_rel_t *table = (const bh_elf_rel_t *)rel;
        size_t count = relsz / sizeof(bh_elf_rel_t);
        for (i = 0; i < count; i++) {
            unsigned type = (unsigned)BH_ELF_R_TYPE(table[i].r_info);
            unsigned symbol_index = (unsigned)BH_ELF_R_SYM(table[i].r_info);
            const bh_elf_sym_t *symbol;
            const char *name;
            uintptr_t slot;

            if (type != (unsigned)BH_PLT_GLOB_DAT) continue;
            symbol = (const bh_elf_sym_t *)(symtab + symbol_index * syment);
            if (symbol->st_name == 0) continue;
            if (strsz != 0 && (size_t)symbol->st_name >= strsz) continue;
            name = (const char *)(strtab + symbol->st_name);
            if (strcmp(name, collect->symbol) != 0) continue;
            slot = base + (uintptr_t)table[i].r_offset;
            if (bh_plt_add_candidate(collect, slot, image, name, is_main,
                                     symbol->st_shndx == SHN_UNDEF) != 0) {
                return;
            }
        }
    }
#endif
}

static int bh_plt_collect_callback(struct dl_phdr_info *info, size_t size,
                                   void *data) {
    bh_plt_collect_t *collect = (bh_plt_collect_t *)data;
    (void)size;
    bh_plt_scan_image(info, collect);
    if (collect->failed) {
        return 1;
    }
    return 0;
}

static bh_plt_record_t *bh_plt_find_slot(uintptr_t slot, int active_only) {
    bh_plt_record_t *record = bh_plt_records;
    while (record != NULL) {
        if (record->slot == slot && (!active_only || record->active)) {
            return record;
        }
        record = record->next;
    }
    return NULL;
}

static int bh_plt_record_matches(const bh_plt_record_t *record,
                                 const char *image_name, const char *symbol,
                                 void *replacement) {
    return record->active && strcmp(record->symbol, symbol) == 0 &&
           bh_plt_image_matches(image_name, record->image) &&
           (replacement == NULL || record->replacement == replacement);
}

static void *bh_plt_resolve_symbol(const char *image, const char *symbol,
                                   int is_main, int symbol_undefined) {
    void *handle = NULL;
    void *result = NULL;

    if (is_main && symbol_undefined) {
        result = dlsym(RTLD_NEXT, symbol);
        if (result != NULL) {
            return result;
        }
    }

    if (image != NULL && image[0] != '\0') {
        handle = dlopen(image, RTLD_NOW | RTLD_NOLOAD);
    }
    if (handle == NULL) {
        handle = dlopen(NULL, RTLD_NOW);
    }
    if (handle != NULL) {
        result = dlsym(handle, symbol);
        dlclose(handle);
    }
    if (result == NULL) {
        result = dlsym(RTLD_DEFAULT, symbol);
    }
    return result;
}

static void bh_plt_free_candidates(bh_plt_collect_t *collect) {
    size_t i;
    for (i = 0; i < collect->count; i++) {
        free(collect->items[i].image);
        free(collect->items[i].symbol);
    }
    free(collect->items);
    collect->items = NULL;
    collect->count = 0;
}

static void bh_plt_record_destroy(bh_plt_record_t *record) {
    if (record == NULL) {
        return;
    }
    free(record->image);
    free(record->symbol);
    free(record);
}

static bh_plt_record_t *bh_plt_rollback(bh_plt_record_t *records) {
    bh_plt_record_t *failed = NULL;

    while (records != NULL) {
        bh_plt_record_t *next = records->next;
        if (bh__write_pointer((void *)records->slot, records->saved_value) != 0) {
            records->next = failed;
            failed = records;
        } else {
            bh_plt_record_destroy(records);
        }
        records = next;
    }
    return failed;
}

int bh_plt_hook(const char *image_name, const char *symbol,
                void *replacement, void **original) {
    bh_plt_collect_t collect;
    bh_plt_record_t *new_records = NULL;
    size_t i;
    int count = 0;
    int result = 0;
    void *first_original = NULL;

    if (symbol == NULL || symbol[0] == '\0' || replacement == NULL) {
        return BH_PLT_ERROR_INVALID_ARGUMENT;
    }

    memset(&collect, 0, sizeof(collect));
    collect.image = image_name;
    collect.symbol = symbol;

    (void)dl_iterate_phdr(bh_plt_collect_callback, &collect);
    if (collect.failed) {
        bh_plt_free_candidates(&collect);
        return BH_PLT_ERROR_OUT_OF_MEMORY;
    }
    if (collect.count == 0) {
        bh_plt_free_candidates(&collect);
        return BH_PLT_ERROR_NOT_FOUND;
    }

    for (i = 0; i < collect.count; i++) {
        bh_plt_candidate_t *candidate = &collect.items[i];
        candidate->resolved = bh_plt_resolve_symbol(
            candidate->image, symbol, candidate->is_main,
            candidate->symbol_undefined);
    }

    pthread_mutex_lock(&bh_plt_lock);
    for (i = 0; i < collect.count; i++) {
        bh_plt_candidate_t *candidate = &collect.items[i];
        bh_plt_record_t *record;
        bh_plt_record_t *existing = bh_plt_find_slot(candidate->slot, 1);

        for (record = new_records; record != NULL; record = record->next) {
            if (record->slot == candidate->slot) {
                break;
            }
        }
        if (record != NULL) {
            continue;
        }

        if (existing != NULL) {
            if (existing->replacement == replacement) {
                if (first_original == NULL) first_original = existing->resolved;
                continue;
            }
            result = BH_PLT_ERROR_ALREADY_HOOKED;
            goto rollback;
        }

        record = (bh_plt_record_t *)calloc(1, sizeof(*record));
        if (record == NULL) {
            result = BH_PLT_ERROR_OUT_OF_MEMORY;
            goto rollback;
        }
        record->slot = candidate->slot;
        record->saved_value = bh__read_pointer((const void *)candidate->slot);
        record->replacement = replacement;
        record->resolved = candidate->resolved != NULL
                               ? candidate->resolved
                               : (void *)record->saved_value;
        record->image = strdup(candidate->image);
        record->symbol = strdup(symbol);
        if (record->image == NULL || record->symbol == NULL) {
            bh_plt_record_destroy(record);
            result = BH_PLT_ERROR_OUT_OF_MEMORY;
            goto rollback;
        }
        record->active = 1;

        if (bh__write_pointer((void *)candidate->slot,
                              (uintptr_t)replacement) != 0) {
            bh_plt_record_destroy(record);
            result = BH_PLT_ERROR_MEMORY_PROTECTION;
            goto rollback;
        }

        record->next = new_records;
        new_records = record;
        count++;
        if (first_original == NULL) {
            first_original = record->resolved;
        }
    }

    if (count == 0) {
        if (first_original != NULL && original != NULL) {
            *original = first_original;
        }
        pthread_mutex_unlock(&bh_plt_lock);
        bh_plt_free_candidates(&collect);
        return 0;
    }

    {
        bh_plt_record_t *tail = new_records;
        while (tail->next != NULL) tail = tail->next;
        tail->next = bh_plt_records;
        bh_plt_records = new_records;
    }
    if (original != NULL) *original = first_original;
    pthread_mutex_unlock(&bh_plt_lock);
    bh_plt_free_candidates(&collect);
    return count;

rollback:
    {
        bh_plt_record_t *failed = bh_plt_rollback(new_records);
        if (failed != NULL) {
            bh_plt_record_t *tail = failed;
            while (tail->next != NULL) {
                tail = tail->next;
            }
            tail->next = bh_plt_records;
            bh_plt_records = failed;
        }
    }
    pthread_mutex_unlock(&bh_plt_lock);
    bh_plt_free_candidates(&collect);
    return result;
}

int bh_plt_unhook(const char *image_name, const char *symbol,
                  void *replacement) {
    bh_plt_record_t **link;
    bh_plt_record_t *retired = NULL;
    int count = 0;

    if (symbol == NULL || symbol[0] == '\0') {
        return BH_PLT_ERROR_INVALID_ARGUMENT;
    }

    pthread_mutex_lock(&bh_plt_lock);
    link = &bh_plt_records;
    while (*link != NULL) {
        bh_plt_record_t *record = *link;

        if (bh_plt_record_matches(record, image_name, symbol, replacement) &&
            bh__write_pointer((void *)record->slot, record->saved_value) == 0) {
            record->active = 0;
            *link = record->next;
            record->next = retired;
            retired = record;
            count++;
            continue;
        }
        link = &record->next;
    }
    pthread_mutex_unlock(&bh_plt_lock);

    while (retired != NULL) {
        bh_plt_record_t *next = retired->next;
        bh_plt_record_destroy(retired);
        retired = next;
    }
    return count;
}

int bh_plt_unhook_all(void) {
    bh_plt_record_t **link;
    bh_plt_record_t *retired = NULL;
    int count = 0;

    pthread_mutex_lock(&bh_plt_lock);
    link = &bh_plt_records;
    while (*link != NULL) {
        bh_plt_record_t *record = *link;

        if (record->active) {
            if (bh__write_pointer((void *)record->slot, record->saved_value) != 0) {
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
    pthread_mutex_unlock(&bh_plt_lock);

    while (retired != NULL) {
        bh_plt_record_t *next = retired->next;
        bh_plt_record_destroy(retired);
        retired = next;
    }
    return count;
}

int bh_plt_is_hooked(const char *image_name, const char *symbol,
                     void *replacement) {
    bh_plt_record_t *record;
    int found = 0;

    if (symbol == NULL || symbol[0] == '\0') {
        return 0;
    }
    pthread_mutex_lock(&bh_plt_lock);
    record = bh_plt_records;
    while (record != NULL) {
        if (bh_plt_record_matches(record, image_name, symbol, replacement)) {
            found = 1;
            break;
        }
        record = record->next;
    }
    pthread_mutex_unlock(&bh_plt_lock);
    return found;
}

const char *bh_plt_strerror(int status) {
    switch (status) {
        case BH_PLT_OK:
            return "success";
        case BH_PLT_ERROR_INVALID_ARGUMENT:
            return "invalid argument";
        case BH_PLT_ERROR_NOT_FOUND:
            return "no matching relocation slot found";
        case BH_PLT_ERROR_ALREADY_HOOKED:
            return "slot is already hooked with a different replacement";
        case BH_PLT_ERROR_OUT_OF_MEMORY:
            return "out of memory";
        case BH_PLT_ERROR_MEMORY_PROTECTION:
            return "unable to change memory protection";
        default:
            return "unknown PLT hook error";
    }
}
