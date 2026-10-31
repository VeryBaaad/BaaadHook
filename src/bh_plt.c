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

#if defined(__GNUC__)
extern void *dlvsym(void *, const char *, const char *) __attribute__((weak));
#endif

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
    uintptr_t image_base;
    uintptr_t observed;
    uintptr_t original_value;
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
    const char *version;
    int failed;
} bh_plt_collect_t;

typedef struct bh_plt_version_tables {
    uintptr_t versym;
    uintptr_t verneed;
    size_t verneed_count;
    uintptr_t verdef;
    size_t verdef_count;
} bh_plt_version_tables_t;

static pthread_mutex_t bh_plt_lock = PTHREAD_MUTEX_INITIALIZER;
static bh_plt_record_t *bh_plt_records = NULL;

#if defined(__LP64__)
typedef Elf64_Ehdr bh_elf_ehdr_t;
typedef Elf64_Phdr bh_elf_phdr_t;
typedef Elf64_Dyn bh_elf_dyn_t;
typedef Elf64_Sym bh_elf_sym_t;
typedef Elf64_Rel bh_elf_rel_t;
typedef Elf64_Rela bh_elf_rela_t;
typedef Elf64_Verneed bh_elf_verneed_t;
typedef Elf64_Vernaux bh_elf_vernaux_t;
typedef Elf64_Verdef bh_elf_verdef_t;
typedef Elf64_Verdaux bh_elf_verdaux_t;
#  define BH_ELF_R_SYM ELF64_R_SYM
#  define BH_ELF_R_TYPE ELF64_R_TYPE
#  define BH_ELF_ST_TYPE ELF64_ST_TYPE
#else
typedef Elf32_Ehdr bh_elf_ehdr_t;
typedef Elf32_Phdr bh_elf_phdr_t;
typedef Elf32_Dyn bh_elf_dyn_t;
typedef Elf32_Sym bh_elf_sym_t;
typedef Elf32_Rel bh_elf_rel_t;
typedef Elf32_Rela bh_elf_rela_t;
typedef Elf32_Verneed bh_elf_verneed_t;
typedef Elf32_Vernaux bh_elf_vernaux_t;
typedef Elf32_Verdef bh_elf_verdef_t;
typedef Elf32_Verdaux bh_elf_verdaux_t;
#  define BH_ELF_R_SYM ELF32_R_SYM
#  define BH_ELF_R_TYPE ELF32_R_TYPE
#  define BH_ELF_ST_TYPE ELF32_ST_TYPE
#endif

#ifndef STT_GNU_IFUNC
#  define STT_GNU_IFUNC 10
#endif

#ifndef DT_ANDROID_REL
#  define DT_ANDROID_REL 0x6000000fu
#endif
#ifndef DT_ANDROID_RELSZ
#  define DT_ANDROID_RELSZ 0x60000010u
#endif
#ifndef DT_ANDROID_RELA
#  define DT_ANDROID_RELA 0x60000011u
#endif
#ifndef DT_ANDROID_RELASZ
#  define DT_ANDROID_RELASZ 0x60000012u
#endif

#define BH_APS2_GROUPED_BY_INFO 0x1u
#define BH_APS2_GROUPED_BY_OFFSET_DELTA 0x2u
#define BH_APS2_GROUPED_BY_ADDEND 0x4u
#define BH_APS2_HAS_ADDEND 0x8u
#define BH_APS2_MAX_RELOCATIONS (1u << 24)

#define BH_PLT_MAX_VERSION_ENTRIES 65536u
#define BH_PLT_MAX_VERSION_AUX 65536u

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
                                uintptr_t image_base, const char *image,
                                const char *symbol, int is_main,
                                int symbol_undefined) {
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
    candidate->image_base = image_base;
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

static int bh_plt_image_contains_range(const struct dl_phdr_info *info,
                                       uintptr_t base, uintptr_t address,
                                       size_t size, int required_flags) {
    size_t i;

    if (size == 0 || address + size < address) {
        return 0;
    }
    for (i = 0; i < info->dlpi_phnum; i++) {
        const bh_elf_phdr_t *phdr = (const bh_elf_phdr_t *)&info->dlpi_phdr[i];
        uintptr_t start;
        uintptr_t end;

        if (phdr->p_type != PT_LOAD ||
            (phdr->p_flags & (Elf32_Word)required_flags) !=
                (Elf32_Word)required_flags) {
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
        if (address >= start && address <= end && size <= end - address) {
            return 1;
        }
    }
    return 0;
}

static int bh_plt_image_contains(const struct dl_phdr_info *info,
                                 uintptr_t base, uintptr_t address,
                                 size_t size) {
    return bh_plt_image_contains_range(info, base, address, size, PF_R);
}

static int bh_plt_image_contains_writable(const struct dl_phdr_info *info,
                                          uintptr_t base, uintptr_t address,
                                          size_t size) {
    return bh_plt_image_contains_range(info, base, address, size,
                                       PF_R | PF_W);
}

static int bh_plt_symbol_is_function(const bh_elf_sym_t *symbol) {
    unsigned type = (unsigned)BH_ELF_ST_TYPE(symbol->st_info);
    return type == STT_FUNC || type == STT_GNU_IFUNC;
}

static const bh_elf_sym_t *bh_plt_symbol_at(const struct dl_phdr_info *info,
                                            uintptr_t base, uintptr_t symtab,
                                            size_t syment, size_t index) {
    uintptr_t address;

    if (syment == 0 || index > (UINTPTR_MAX - symtab) / syment) {
        return NULL;
    }
    address = symtab + index * syment;
    if (!bh_plt_image_contains(info, base, address, sizeof(bh_elf_sym_t))) {
        return NULL;
    }
    return (const bh_elf_sym_t *)address;
}

static int bh_plt_symbol_matches(const bh_elf_sym_t *symbol,
                                 const char *strtab, size_t strsz,
                                 const char *wanted) {
    const char *name;
    size_t remaining;
    size_t length;

    if (symbol->st_name == 0 || strsz == 0 ||
        (size_t)symbol->st_name >= strsz) {
        return 0;
    }
    name = strtab + symbol->st_name;
    remaining = strsz - (size_t)symbol->st_name;
    length = strnlen(name, remaining);
    if (length == remaining) {
        return 0;
    }
    return strlen(wanted) == length && memcmp(name, wanted, length) == 0;
}

static int bh_plt_version_name_at(const char *strtab, size_t strsz,
                                  uint32_t offset, const char **name) {
    size_t remaining;

    if (strsz == 0 || (size_t)offset >= strsz) {
        return 0;
    }
    remaining = strsz - (size_t)offset;
    if (strnlen(strtab + offset, remaining) == remaining) {
        return 0;
    }
    *name = strtab + offset;
    return 1;
}

static int bh_plt_version_offset_add(uintptr_t address, uint32_t offset,
                                     uintptr_t *result) {
    if ((uintptr_t)offset > UINTPTR_MAX - address) {
        return 0;
    }
    *result = address + (uintptr_t)offset;
    return 1;
}

static int bh_plt_verneed_lookup(const struct dl_phdr_info *info,
                                 uintptr_t base, uintptr_t verneed,
                                 size_t verneed_count, uint16_t index,
                                 const char *strtab, size_t strsz,
                                 const char **name) {
    uintptr_t address = verneed;
    size_t entry;

    if (verneed == 0 || verneed_count == 0) {
        return 0;
    }
    if (verneed_count > (size_t)BH_PLT_MAX_VERSION_ENTRIES) {
        verneed_count = (size_t)BH_PLT_MAX_VERSION_ENTRIES;
    }
    for (entry = 0; entry < verneed_count; entry++) {
        const bh_elf_verneed_t *need;
        uintptr_t aux_address;
        size_t aux_entry;

        if (!bh_plt_image_contains(info, base, address, sizeof(*need))) {
            return 0;
        }
        need = (const bh_elf_verneed_t *)address;
        if (need->vn_cnt == 0 || need->vn_aux == 0 ||
            !bh_plt_version_offset_add(address, need->vn_aux, &aux_address)) {
            return 0;
        }
        for (aux_entry = 0; aux_entry < (size_t)BH_PLT_MAX_VERSION_AUX;
             aux_entry++) {
            const bh_elf_vernaux_t *aux;

            if (!bh_plt_image_contains(info, base, aux_address,
                                       sizeof(*aux))) {
                break;
            }
            aux = (const bh_elf_vernaux_t *)aux_address;
            if (aux->vna_other == index) {
                return bh_plt_version_name_at(strtab, strsz, aux->vna_name,
                                              name);
            }
            if (aux->vna_next == 0 ||
                !bh_plt_version_offset_add(aux_address, aux->vna_next,
                                           &aux_address)) {
                break;
            }
        }
        if (need->vn_next == 0 ||
            !bh_plt_version_offset_add(address, need->vn_next, &address)) {
            break;
        }
    }
    return 0;
}

static int bh_plt_verdef_lookup(const struct dl_phdr_info *info,
                                uintptr_t base, uintptr_t verdef,
                                size_t verdef_count, uint16_t index,
                                const char *strtab, size_t strsz,
                                const char **name) {
    uintptr_t address = verdef;
    size_t entry;

    if (verdef == 0 || verdef_count == 0) {
        return 0;
    }
    if (verdef_count > (size_t)BH_PLT_MAX_VERSION_ENTRIES) {
        verdef_count = (size_t)BH_PLT_MAX_VERSION_ENTRIES;
    }
    for (entry = 0; entry < verdef_count; entry++) {
        const bh_elf_verdef_t *definition;
        uintptr_t aux_address;
        const bh_elf_verdaux_t *aux;

        if (!bh_plt_image_contains(info, base, address, sizeof(*definition))) {
            return 0;
        }
        definition = (const bh_elf_verdef_t *)address;
        if (definition->vd_ndx == index) {
            if (definition->vd_cnt == 0 || definition->vd_aux == 0 ||
                !bh_plt_version_offset_add(address, definition->vd_aux,
                                           &aux_address) ||
                !bh_plt_image_contains(info, base, aux_address,
                                       sizeof(*aux))) {
                return 0;
            }
            aux = (const bh_elf_verdaux_t *)aux_address;
            return bh_plt_version_name_at(strtab, strsz, aux->vda_name, name);
        }
        if (definition->vd_next == 0 ||
            !bh_plt_version_offset_add(address, definition->vd_next,
                                       &address)) {
            break;
        }
    }
    return 0;
}

static int bh_plt_version_index_name(
    const struct dl_phdr_info *info, uintptr_t base,
    const bh_plt_version_tables_t *tables, uint16_t index,
    const char *strtab, size_t strsz, const char **name) {
    if (bh_plt_verneed_lookup(info, base, tables->verneed,
                              tables->verneed_count, index, strtab, strsz,
                              name)) {
        return 1;
    }
    if (bh_plt_verdef_lookup(info, base, tables->verdef, tables->verdef_count,
                             index, strtab, strsz, name)) {
        return 1;
    }
    return 0;
}

static int bh_plt_symbol_version_matches(
    const struct dl_phdr_info *info, uintptr_t base,
    const bh_plt_version_tables_t *tables, unsigned symbol_index,
    const char *strtab, size_t strsz, const char *version) {
    uintptr_t address;
    uint16_t versym;
    uint16_t index;
    const char *name = NULL;

    if (version == NULL || version[0] == '\0') {
        return 1;
    }
    if (tables->versym == 0 ||
        (uintptr_t)symbol_index >
            (UINTPTR_MAX - tables->versym) / sizeof(uint16_t)) {
        return 0;
    }
    address = tables->versym + (uintptr_t)symbol_index * sizeof(uint16_t);
    if (!bh_plt_image_contains(info, base, address, sizeof(versym))) {
        return 0;
    }
    memcpy(&versym, (const void *)address, sizeof(versym));
    index = (uint16_t)(versym & 0x7fffu);
    if (index == 0 || index == 1) {
        return 0;
    }
    if (!bh_plt_version_index_name(info, base, tables, index, strtab, strsz,
                                   &name)) {
        return 0;
    }
    return strcmp(name, version) == 0;
}

static int bh_plt_slot_at(const struct dl_phdr_info *info, uintptr_t base,
                          uintptr_t offset, uintptr_t *slot) {
    uintptr_t address = base + offset;

    if (address < base) {
        return 0;
    }
    if ((address & (sizeof(uintptr_t) - 1u)) != 0) {
        return 0;
    }
    if (!bh_plt_image_contains_writable(info, base, address,
                                        sizeof(uintptr_t))) {
        return 0;
    }
    *slot = address;
    return 1;
}

#if BH_PLT_HAS_GLOB_DAT
static int bh_plt_sleb128(const uint8_t **cursor, const uint8_t *end,
                          int64_t *value) {
    const uint8_t *position = *cursor;
    uint64_t result = 0;
    unsigned shift = 0;
    uint8_t byte;

    do {
        uint8_t payload;

        if (position >= end || shift >= 64) {
            return 0;
        }
        byte = *position++;
        payload = (uint8_t)(byte & 0x7fu);
        if (shift == 63 && payload != 0 && payload != 0x7fu) {
            return 0;
        }
        result |= (uint64_t)payload << shift;
        shift += 7;
    } while ((byte & 0x80u) != 0);

    if (shift < 64 && (byte & 0x40u) != 0) {
        result |= ~(uint64_t)0 << shift;
    }
    *cursor = position;
    *value = (int64_t)result;
    return 1;
}

static int bh_plt_offset_advance(uintptr_t *offset, int64_t delta) {
    uint64_t value = (uint64_t)*offset;

    if (delta >= 0) {
        uint64_t amount = (uint64_t)delta;

        if (amount > (uint64_t)UINTPTR_MAX ||
            value > (uint64_t)UINTPTR_MAX - amount) {
            return 0;
        }
        value += amount;
    } else {
        uint64_t amount = (uint64_t)0 - (uint64_t)delta;

        if (amount > (uint64_t)UINTPTR_MAX || value < amount) {
            return 0;
        }
        value -= amount;
    }
    *offset = (uintptr_t)value;
    return 1;
}

static int bh_plt_addend_advance(int64_t *addend, int64_t delta) {
    int64_t value = *addend;

    if (delta > 0 && value > INT64_MAX - delta) {
        return 0;
    }
    if (delta < 0 && value < INT64_MIN - delta) {
        return 0;
    }
    *addend = value + delta;
    return 1;
}

static int bh_plt_aps2_read_info(const uint8_t **cursor, const uint8_t *end,
                                 uint64_t *info) {
    int64_t value;

    if (!bh_plt_sleb128(cursor, end, &value) || value < 0) {
        return 0;
    }
#if !defined(__LP64__)
    if ((uint64_t)value > (uint64_t)UINT32_MAX) {
        return 0;
    }
#endif
    *info = (uint64_t)value;
    return 1;
}

static void bh_plt_scan_android_relocs(
    const struct dl_phdr_info *info, uintptr_t base, bh_plt_collect_t *collect,
    uintptr_t relocs, size_t relocsz, int is_rela, uintptr_t symtab,
    size_t syment, uintptr_t strtab, size_t strsz,
    const bh_plt_version_tables_t *versions, const char *image, int is_main) {
    const uint8_t *cursor;
    const uint8_t *end;
    int64_t total;
    int64_t initial_offset;
    uintptr_t offset;
    int64_t addend = 0;
    uint64_t seen = 0;

    if (relocs == 0 || relocsz < 8) {
        return;
    }
    if (!bh_plt_image_contains(info, base, relocs, relocsz)) {
        return;
    }
    cursor = (const uint8_t *)relocs;
    end = cursor + relocsz;
    if (memcmp(cursor, "APS2", 4) != 0) {
        return;
    }
    cursor += 4;
    if (!bh_plt_sleb128(&cursor, end, &total) ||
        !bh_plt_sleb128(&cursor, end, &initial_offset)) {
        return;
    }
    if (total < 0 || (uint64_t)total > (uint64_t)BH_APS2_MAX_RELOCATIONS ||
        initial_offset < 0 ||
        (uint64_t)initial_offset > (uint64_t)UINTPTR_MAX) {
        return;
    }
    offset = (uintptr_t)initial_offset;

    while (seen < (uint64_t)total) {
        int64_t group_size_value;
        int64_t group_flags_value;
        int64_t group_offset_delta = 0;
        uint64_t group_info = 0;
        uint64_t group_size;
        uint32_t group_flags;
        unsigned addend_mode = 0;
        uint64_t index;

        if (!bh_plt_sleb128(&cursor, end, &group_size_value) ||
            !bh_plt_sleb128(&cursor, end, &group_flags_value)) {
            return;
        }
        if (group_size_value <= 0 || group_flags_value < 0 ||
            (uint64_t)group_flags_value > (uint64_t)UINT32_MAX) {
            return;
        }
        group_size = (uint64_t)group_size_value;
        group_flags = (uint32_t)group_flags_value;
        if (group_size > (uint64_t)total - seen) {
            return;
        }
        if (!is_rela && (group_flags & BH_APS2_HAS_ADDEND) != 0) {
            return;
        }

        if ((group_flags & BH_APS2_GROUPED_BY_OFFSET_DELTA) != 0 &&
            !bh_plt_sleb128(&cursor, end, &group_offset_delta)) {
            return;
        }
        if ((group_flags & BH_APS2_GROUPED_BY_INFO) != 0 &&
            !bh_plt_aps2_read_info(&cursor, end, &group_info)) {
            return;
        }
        if (is_rela) {
            addend_mode = group_flags &
                          (BH_APS2_HAS_ADDEND | BH_APS2_GROUPED_BY_ADDEND);
            if (addend_mode ==
                (BH_APS2_HAS_ADDEND | BH_APS2_GROUPED_BY_ADDEND)) {
                int64_t delta;

                if (!bh_plt_sleb128(&cursor, end, &delta) ||
                    !bh_plt_addend_advance(&addend, delta)) {
                    return;
                }
            } else if (addend_mode != BH_APS2_HAS_ADDEND) {
                addend = 0;
            }
        }

        for (index = 0; index < group_size; index++) {
            uint64_t r_info;
            unsigned type;
            unsigned symbol_index;
            const bh_elf_sym_t *symbol;
            uintptr_t slot;

            if ((group_flags & BH_APS2_GROUPED_BY_OFFSET_DELTA) != 0) {
                if (!bh_plt_offset_advance(&offset, group_offset_delta)) {
                    return;
                }
            } else {
                int64_t delta;

                if (!bh_plt_sleb128(&cursor, end, &delta) ||
                    !bh_plt_offset_advance(&offset, delta)) {
                    return;
                }
            }

            if ((group_flags & BH_APS2_GROUPED_BY_INFO) != 0) {
                r_info = group_info;
            } else if (!bh_plt_aps2_read_info(&cursor, end, &r_info)) {
                return;
            }

            if (is_rela && addend_mode == BH_APS2_HAS_ADDEND) {
                int64_t delta;

                if (!bh_plt_sleb128(&cursor, end, &delta) ||
                    !bh_plt_addend_advance(&addend, delta)) {
                    return;
                }
            }

            type = (unsigned)BH_ELF_R_TYPE(r_info);
            if (type != (unsigned)BH_PLT_GLOB_DAT) {
                continue;
            }
            if (is_rela && addend != 0) {
                continue;
            }
            if ((uint64_t)BH_ELF_R_SYM(r_info) > (uint64_t)UINT_MAX) {
                continue;
            }
            symbol_index = (unsigned)BH_ELF_R_SYM(r_info);
            symbol = bh_plt_symbol_at(info, base, symtab, syment, symbol_index);
            if (symbol == NULL) {
                continue;
            }
            if (!bh_plt_symbol_is_function(symbol)) {
                continue;
            }
            if (!bh_plt_symbol_matches(symbol, (const char *)strtab, strsz,
                                       collect->symbol)) {
                continue;
            }
            if (!bh_plt_symbol_version_matches(info, base, versions,
                                               symbol_index,
                                               (const char *)strtab, strsz,
                                               collect->version)) {
                continue;
            }
            if (!bh_plt_slot_at(info, base, offset, &slot)) {
                continue;
            }
            if (bh_plt_add_candidate(collect, slot, base, image,
                                     collect->symbol, is_main,
                                     symbol->st_shndx == SHN_UNDEF) != 0) {
                return;
            }
        }

        seen += group_size;
    }
}
#endif

static void bh_plt_scan_image(struct dl_phdr_info *info,
                              bh_plt_collect_t *collect) {
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    const char *raw_image = info->dlpi_name != NULL ? info->dlpi_name : "";
    int is_main = raw_image[0] == '\0';
    const char *image = is_main ? bh_plt_main_image_path() : raw_image;
    const bh_elf_phdr_t *dynamic_phdr = NULL;
    const bh_elf_dyn_t *dynamic = NULL;
    uintptr_t dynamic_address;
    size_t dynamic_count = 0;
    uintptr_t strtab = 0;
    uintptr_t symtab = 0;
    uintptr_t jmprel = 0;
    size_t pltrelsz = 0;
    uintptr_t rela = 0;
    size_t relasz = 0;
    uintptr_t rel = 0;
    size_t relsz = 0;
    uintptr_t android_relocs = 0;
    size_t android_relocsz = 0;
    int android_is_rela = 0;
    size_t syment = 0;
    size_t strsz = 0;
    bh_plt_version_tables_t versions;
#if defined(__LP64__)
    int pltrel_is_rela = 1;
#else
    int pltrel_is_rela = 0;
#endif
    size_t i;

    memset(&versions, 0, sizeof(versions));

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

    dynamic_address = base + (uintptr_t)dynamic_phdr->p_vaddr;
    if (dynamic_address < base) {
        return;
    }
    if (!bh_plt_image_contains(info, base, dynamic_address,
                               (size_t)dynamic_phdr->p_memsz)) {
        return;
    }
    dynamic = (const bh_elf_dyn_t *)dynamic_address;
    dynamic_count = (size_t)dynamic_phdr->p_memsz / sizeof(bh_elf_dyn_t);

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
            case DT_ANDROID_REL:
                android_relocs = bh_plt_normalize_dynamic_pointer(
                    (uintptr_t)dynamic[i].d_un.d_ptr, base);
                android_is_rela = 0;
                break;
            case DT_ANDROID_RELSZ:
                android_relocsz = (size_t)dynamic[i].d_un.d_val;
                break;
            case DT_ANDROID_RELA:
                android_relocs = bh_plt_normalize_dynamic_pointer(
                    (uintptr_t)dynamic[i].d_un.d_ptr, base);
                android_is_rela = 1;
                break;
            case DT_ANDROID_RELASZ:
                android_relocsz = (size_t)dynamic[i].d_un.d_val;
                break;
            case DT_VERSYM:
                versions.versym = bh_plt_normalize_dynamic_pointer(
                    (uintptr_t)dynamic[i].d_un.d_ptr, base);
                break;
            case DT_VERNEED:
                versions.verneed = bh_plt_normalize_dynamic_pointer(
                    (uintptr_t)dynamic[i].d_un.d_ptr, base);
                break;
            case DT_VERNEEDNUM:
                versions.verneed_count = (size_t)dynamic[i].d_un.d_val;
                break;
            case DT_VERDEF:
                versions.verdef = bh_plt_normalize_dynamic_pointer(
                    (uintptr_t)dynamic[i].d_un.d_ptr, base);
                break;
            case DT_VERDEFNUM:
                versions.verdef_count = (size_t)dynamic[i].d_un.d_val;
                break;
            case DT_NULL:
                i = dynamic_count;
                break;
            default:
                break;
        }
    }

    if (strtab == 0 || symtab == 0 || strsz == 0) {
        return;
    }
    if (syment == 0) {
        syment = sizeof(bh_elf_sym_t);
    }
    if (syment < sizeof(bh_elf_sym_t)) {
        return;
    }
    if (!bh_plt_image_contains(info, base, strtab, strsz)) {
        return;
    }
    if (!bh_plt_image_contains(info, base, symtab, sizeof(bh_elf_sym_t))) {
        return;
    }
    if (versions.versym != 0 &&
        !bh_plt_image_contains(info, base, versions.versym,
                               sizeof(uint16_t))) {
        versions.versym = 0;
    }
    if (versions.verneed != 0 &&
        !bh_plt_image_contains(info, base, versions.verneed,
                               sizeof(bh_elf_verneed_t))) {
        versions.verneed = 0;
        versions.verneed_count = 0;
    }
    if (versions.verdef != 0 &&
        !bh_plt_image_contains(info, base, versions.verdef,
                               sizeof(bh_elf_verdef_t))) {
        versions.verdef = 0;
        versions.verdef_count = 0;
    }

    if (jmprel != 0 && pltrelsz != 0 &&
        bh_plt_image_contains(info, base, jmprel, pltrelsz)) {
        if (pltrel_is_rela) {
            const bh_elf_rela_t *table = (const bh_elf_rela_t *)jmprel;
            size_t count = pltrelsz / sizeof(bh_elf_rela_t);
            for (i = 0; i < count; i++) {
                unsigned type = (unsigned)BH_ELF_R_TYPE(table[i].r_info);
                unsigned symbol_index = (unsigned)BH_ELF_R_SYM(table[i].r_info);
                const bh_elf_sym_t *symbol;
                uintptr_t slot;
                int glob_dat = 0;
                int match;

#if BH_PLT_HAS_GLOB_DAT
                if (type == (unsigned)BH_PLT_GLOB_DAT) {
                    if (table[i].r_addend != 0) continue;
                    glob_dat = 1;
                }
#endif
                match = type == (unsigned)BH_PLT_JUMP_SLOT || glob_dat;
                if (!match) continue;
                symbol = bh_plt_symbol_at(info, base, symtab, syment,
                                          symbol_index);
                if (symbol == NULL) continue;
                if (glob_dat && !bh_plt_symbol_is_function(symbol)) continue;
                if (!bh_plt_symbol_matches(symbol, (const char *)strtab, strsz,
                                           collect->symbol)) continue;
                if (!bh_plt_symbol_version_matches(info, base, &versions,
                                                   symbol_index,
                                                   (const char *)strtab, strsz,
                                                   collect->version)) continue;
                if (!bh_plt_slot_at(info, base, (uintptr_t)table[i].r_offset,
                                    &slot)) continue;
                if (bh_plt_add_candidate(collect, slot, base, image,
                                         collect->symbol, is_main,
                                         symbol->st_shndx == SHN_UNDEF) != 0) {
                    return;
                }
            }
        } else {
            const bh_elf_rel_t *table = (const bh_elf_rel_t *)jmprel;
            size_t count = pltrelsz / sizeof(bh_elf_rel_t);
            for (i = 0; i < count; i++) {
                unsigned type = (unsigned)BH_ELF_R_TYPE(table[i].r_info);
                unsigned symbol_index = (unsigned)BH_ELF_R_SYM(table[i].r_info);
                const bh_elf_sym_t *symbol;
                uintptr_t slot;
                int glob_dat = 0;
                int match;

#if BH_PLT_HAS_GLOB_DAT
                if (type == (unsigned)BH_PLT_GLOB_DAT) glob_dat = 1;
#endif
                match = type == (unsigned)BH_PLT_JUMP_SLOT || glob_dat;
                if (!match) continue;
                symbol = bh_plt_symbol_at(info, base, symtab, syment,
                                          symbol_index);
                if (symbol == NULL) continue;
                if (glob_dat && !bh_plt_symbol_is_function(symbol)) continue;
                if (!bh_plt_symbol_matches(symbol, (const char *)strtab, strsz,
                                           collect->symbol)) continue;
                if (!bh_plt_symbol_version_matches(info, base, &versions,
                                                   symbol_index,
                                                   (const char *)strtab, strsz,
                                                   collect->version)) continue;
                if (!bh_plt_slot_at(info, base, (uintptr_t)table[i].r_offset,
                                    &slot)) continue;
                if (bh_plt_add_candidate(collect, slot, base, image,
                                         collect->symbol, is_main,
                                         symbol->st_shndx == SHN_UNDEF) != 0) {
                    return;
                }
            }
        }
    }

#if BH_PLT_HAS_GLOB_DAT
    if (rela != 0 && relasz >= sizeof(bh_elf_rela_t) &&
        bh_plt_image_contains(info, base, rela, relasz)) {
        const bh_elf_rela_t *table = (const bh_elf_rela_t *)rela;
        size_t count = relasz / sizeof(bh_elf_rela_t);
        for (i = 0; i < count; i++) {
            unsigned type = (unsigned)BH_ELF_R_TYPE(table[i].r_info);
            unsigned symbol_index = (unsigned)BH_ELF_R_SYM(table[i].r_info);
            const bh_elf_sym_t *symbol;
            uintptr_t slot;

            if (type != (unsigned)BH_PLT_GLOB_DAT) continue;
            if (table[i].r_addend != 0) continue;
            symbol = bh_plt_symbol_at(info, base, symtab, syment, symbol_index);
            if (symbol == NULL) continue;
            if (!bh_plt_symbol_is_function(symbol)) continue;
            if (!bh_plt_symbol_matches(symbol, (const char *)strtab, strsz,
                                       collect->symbol)) continue;
            if (!bh_plt_symbol_version_matches(info, base, &versions,
                                               symbol_index,
                                               (const char *)strtab, strsz,
                                               collect->version)) continue;
            if (!bh_plt_slot_at(info, base, (uintptr_t)table[i].r_offset,
                                &slot)) continue;
            if (bh_plt_add_candidate(collect, slot, base, image,
                                     collect->symbol, is_main,
                                     symbol->st_shndx == SHN_UNDEF) != 0) {
                return;
            }
        }
    }
    if (rel != 0 && relsz >= sizeof(bh_elf_rel_t) &&
        bh_plt_image_contains(info, base, rel, relsz)) {
        const bh_elf_rel_t *table = (const bh_elf_rel_t *)rel;
        size_t count = relsz / sizeof(bh_elf_rel_t);
        for (i = 0; i < count; i++) {
            unsigned type = (unsigned)BH_ELF_R_TYPE(table[i].r_info);
            unsigned symbol_index = (unsigned)BH_ELF_R_SYM(table[i].r_info);
            const bh_elf_sym_t *symbol;
            uintptr_t slot;

            if (type != (unsigned)BH_PLT_GLOB_DAT) continue;
            symbol = bh_plt_symbol_at(info, base, symtab, syment, symbol_index);
            if (symbol == NULL) continue;
            if (!bh_plt_symbol_is_function(symbol)) continue;
            if (!bh_plt_symbol_matches(symbol, (const char *)strtab, strsz,
                                       collect->symbol)) continue;
            if (!bh_plt_symbol_version_matches(info, base, &versions,
                                               symbol_index,
                                               (const char *)strtab, strsz,
                                               collect->version)) continue;
            if (!bh_plt_slot_at(info, base, (uintptr_t)table[i].r_offset,
                                &slot)) continue;
            if (bh_plt_add_candidate(collect, slot, base, image,
                                     collect->symbol, is_main,
                                     symbol->st_shndx == SHN_UNDEF) != 0) {
                return;
            }
        }
    }
    if (android_relocs != 0 && android_relocsz != 0) {
        bh_plt_scan_android_relocs(info, base, collect, android_relocs,
                                   android_relocsz, android_is_rela, symtab,
                                   syment, strtab, strsz, &versions, image,
                                   is_main);
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

static void *bh_plt_symbol_lookup(void *handle, const char *symbol,
                                  const char *version) {
    if (version != NULL && version[0] != '\0') {
#if defined(__GNUC__)
        if (dlvsym != NULL) {
            return dlvsym(handle, symbol, version);
        }
#endif
    }
    return dlsym(handle, symbol);
}

static void *bh_plt_resolve_symbol(const char *image, const char *symbol,
                                   const char *version, int is_main,
                                   int symbol_undefined) {
    void *handle = NULL;
    void *result = NULL;
    int flags = RTLD_NOW;
    int nodelete = 0;

#ifdef RTLD_NODELETE
    flags |= RTLD_NODELETE;
    nodelete = 1;
#endif

    if (is_main && symbol_undefined) {
        result = bh_plt_symbol_lookup(RTLD_NEXT, symbol, version);
        if (result != NULL) {
            return result;
        }
    }

    if (image != NULL && image[0] != '\0') {
        handle = dlopen(image, flags | RTLD_NOLOAD);
        if (handle == NULL && nodelete) {
            handle = dlopen(image, RTLD_NOW | RTLD_NOLOAD);
        }
    }
    if (handle == NULL) {
        handle = dlopen(NULL, flags);
        if (handle == NULL && nodelete) {
            handle = dlopen(NULL, RTLD_NOW);
        }
    }
    if (handle != NULL) {
        result = bh_plt_symbol_lookup(handle, symbol, version);
        dlclose(handle);
    }
    if (is_main && result != NULL) {
        return result;
    }
    if (result == NULL) {
        result = bh_plt_symbol_lookup(RTLD_DEFAULT, symbol, version);
    }
    return result;
}

static int bh_plt_observed_same_image(uintptr_t observed, uintptr_t slot,
                                      uintptr_t image_base) {
    Dl_info dli;
    Dl_info slot_dli;

    if (observed == 0 || dladdr((void *)observed, &dli) == 0) {
        return -1;
    }
    if ((uintptr_t)dli.dli_fbase == image_base) {
        return 1;
    }
    if (image_base == 0 && dladdr((void *)slot, &slot_dli) != 0 &&
        (uintptr_t)slot_dli.dli_fbase == (uintptr_t)dli.dli_fbase) {
        return 1;
    }
    return 0;
}

static uintptr_t bh_plt_original_value(uintptr_t observed, uintptr_t slot,
                                       uintptr_t image_base, void *resolved) {
    if (bh_plt_observed_same_image(observed, slot, image_base) == 0) {
        return observed;
    }
    return (uintptr_t)resolved;
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

static void bh_plt_retire_record(bh_plt_record_t *record,
                                 bh_plt_record_t **retired) {
    bh_plt_record_t **link = &bh_plt_records;

    while (*link != NULL) {
        if (*link == record) {
            *link = record->next;
            break;
        }
        link = &(*link)->next;
    }
    record->active = 0;
    record->next = *retired;
    *retired = record;
}

static void bh_plt_destroy_records(bh_plt_record_t *records) {
    while (records != NULL) {
        bh_plt_record_t *next = records->next;
        bh_plt_record_destroy(records);
        records = next;
    }
}

static bh_plt_record_t *bh_plt_rollback(bh_plt_record_t *records) {
    bh_plt_record_t *failed = NULL;

    while (records != NULL) {
        bh_plt_record_t *next = records->next;
        int status = bh__cas_pointer((void *)records->slot,
                                     (uintptr_t)records->replacement,
                                     records->saved_value);
        if (status == 1 || status == 0) {
            bh_plt_record_destroy(records);
        } else {
            records->next = failed;
            failed = records;
        }
        records = next;
    }
    return failed;
}

int bh_plt_hook_version(const char *image_name, const char *symbol,
                        const char *version, void *replacement,
                        void **original) {
    bh_plt_collect_t collect;
    bh_plt_record_t *new_records = NULL;
    bh_plt_record_t *retired = NULL;
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
    collect.version = version;

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
            candidate->image, symbol, version, candidate->is_main,
            candidate->symbol_undefined);
        candidate->observed =
            bh__read_pointer((const void *)candidate->slot);
        candidate->original_value = bh_plt_original_value(
            candidate->observed, candidate->slot, candidate->image_base,
            candidate->resolved);
    }

    pthread_mutex_lock(&bh_plt_lock);
    for (i = 0; i < collect.count; i++) {
        bh_plt_candidate_t *candidate = &collect.items[i];
        bh_plt_record_t *existing = bh_plt_find_slot(candidate->slot, 1);

        if (existing != NULL) {
            uintptr_t current =
                bh__read_pointer((const void *)candidate->slot);
            if (current != (uintptr_t)existing->replacement) {
                bh_plt_retire_record(existing, &retired);
                existing = NULL;
            }
        }

        if (existing != NULL) {
            if (existing->replacement != replacement) {
                result = BH_PLT_ERROR_ALREADY_HOOKED;
                goto rollback;
            }
            if (first_original == NULL) {
                first_original = existing->resolved;
            }
        } else {
            uintptr_t current =
                bh__read_pointer((const void *)candidate->slot);

            if (current != candidate->observed) {
                if (candidate->observed != (uintptr_t)replacement) {
                    result = BH_PLT_ERROR_ALREADY_HOOKED;
                    goto rollback;
                }
                candidate->observed = current;
                candidate->original_value = bh_plt_original_value(
                    current, candidate->slot, candidate->image_base,
                    candidate->resolved);
            }
        }
    }

    if (first_original == NULL) {
        for (i = 0; i < collect.count; i++) {
            bh_plt_candidate_t *candidate = &collect.items[i];
            if (bh_plt_find_slot(candidate->slot, 1) == NULL) {
                first_original = (void *)candidate->original_value;
                break;
            }
        }
    }
    if (original != NULL && first_original != NULL) {
        __atomic_store_n(original, first_original, __ATOMIC_RELEASE);
    }

    for (i = 0; i < collect.count; i++) {
        bh_plt_candidate_t *candidate = &collect.items[i];
        bh_plt_record_t *record;
        bh_plt_record_t *existing = bh_plt_find_slot(candidate->slot, 1);
        int status;

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
        record->saved_value = candidate->observed;
        record->replacement = replacement;
        record->resolved = (void *)candidate->original_value;
        record->image = strdup(candidate->image);
        record->symbol = strdup(symbol);
        if (record->image == NULL || record->symbol == NULL) {
            bh_plt_record_destroy(record);
            result = BH_PLT_ERROR_OUT_OF_MEMORY;
            goto rollback;
        }
        record->active = 1;

        status = bh__cas_pointer((void *)candidate->slot,
                                 candidate->observed,
                                 (uintptr_t)replacement);
        if (status != 1) {
            bh_plt_record_destroy(record);
            result = status == 0 ? BH_PLT_ERROR_ALREADY_HOOKED
                                 : BH_PLT_ERROR_MEMORY_PROTECTION;
            goto rollback;
        }

        record->next = new_records;
        new_records = record;
        count++;
    }

    if (count == 0) {
        pthread_mutex_unlock(&bh_plt_lock);
        bh_plt_destroy_records(retired);
        bh_plt_free_candidates(&collect);
        return 0;
    }

    {
        bh_plt_record_t *tail = new_records;
        while (tail->next != NULL) tail = tail->next;
        tail->next = bh_plt_records;
        bh_plt_records = new_records;
    }
    pthread_mutex_unlock(&bh_plt_lock);
    bh_plt_destroy_records(retired);
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
    bh_plt_destroy_records(retired);
    bh_plt_free_candidates(&collect);
    return result;
}

int bh_plt_hook(const char *image_name, const char *symbol,
                void *replacement, void **original) {
    return bh_plt_hook_version(image_name, symbol, NULL, replacement, original);
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

        if (bh_plt_record_matches(record, image_name, symbol, replacement)) {
            int status = bh__cas_pointer((void *)record->slot,
                                         (uintptr_t)record->replacement,
                                         record->saved_value);
            if (status == 1 || status == 0) {
                record->active = 0;
                *link = record->next;
                record->next = retired;
                retired = record;
                if (status == 1) {
                    count++;
                }
                continue;
            }
        }
        link = &record->next;
    }
    pthread_mutex_unlock(&bh_plt_lock);

    bh_plt_destroy_records(retired);
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
            int status = bh__cas_pointer((void *)record->slot,
                                         (uintptr_t)record->replacement,
                                         record->saved_value);
            if (status < 0) {
                link = &record->next;
                continue;
            }
            record->active = 0;
            if (status == 1) {
                count++;
            }
        }

        *link = record->next;
        record->next = retired;
        retired = record;
    }
    pthread_mutex_unlock(&bh_plt_lock);

    bh_plt_destroy_records(retired);
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
            if (bh__read_pointer((const void *)record->slot) ==
                (uintptr_t)record->replacement) {
                found = 1;
                break;
            }
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
