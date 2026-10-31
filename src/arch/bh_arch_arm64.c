/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE 1

#include "bh_internal.h"

#if defined(__aarch64__)

#include <stdint.h>
#include <string.h>

#define BH_ARM64_NOP 0xD503201Fu
#define BH_ARM64_BTI_C 0xD503245Fu
#define BH_ARM64_BR_X16 0xD61F0200u
#define BH_ARM64_BLR_X16 0xD63F0200u

static uint32_t bh_arm64_rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int64_t bh_arm64_sign_extend(uint64_t value, unsigned bits) {
    uint64_t sign = 1ull << (bits - 1u);
    return (int64_t)((value ^ sign) - sign);
}

static int bh_arm64_emit_u32(uint8_t *dst, size_t capacity, size_t *offset,
                             uint32_t value) {
    if (*offset + 4 > capacity) return -1;
    dst[*offset + 0] = (uint8_t)value;
    dst[*offset + 1] = (uint8_t)(value >> 8);
    dst[*offset + 2] = (uint8_t)(value >> 16);
    dst[*offset + 3] = (uint8_t)(value >> 24);
    *offset += 4;
    return 0;
}

static int bh_arm64_emit_u64(uint8_t *dst, size_t capacity, size_t *offset,
                             uint64_t value) {
    int i;
    if (*offset + 8 > capacity) return -1;
    for (i = 0; i < 8; i++) {
        dst[*offset + i] = (uint8_t)(value >> (i * 8));
    }
    *offset += 8;
    return 0;
}

static int bh_arm64_align8(uint8_t *dst, size_t capacity, size_t *offset) {
    while ((*offset & 7u) != 0) {
        if (bh_arm64_emit_u32(dst, capacity, offset, BH_ARM64_NOP) != 0)
            return -1;
    }
    return 0;
}

static int bh_arm64_emit_ldr_x16(uint8_t *dst, size_t capacity, size_t *offset,
                                 uint32_t literal_offset) {
    uint32_t imm19 = literal_offset >> 2;
    return bh_arm64_emit_u32(dst, capacity, offset,
                             0x58000000u | ((imm19 & 0x7FFFFu) << 5) | 16u);
}

static int bh_arm64_emit_b(uint8_t *dst, size_t capacity, size_t *offset,
                           uintptr_t from, uintptr_t target) {
    int64_t displacement = (int64_t)target - (int64_t)from;
    if ((displacement & 3) != 0 || displacement < -(1ll << 27) ||
        displacement >= (1ll << 27)) {
        return -1;
    }
    return bh_arm64_emit_u32(dst, capacity, offset,
                             0x14000000u |
                                 (((uint32_t)(displacement >> 2)) & 0x03FFFFFFu));
}

static int bh_arm64_emit_abs_jump(uint8_t *dst, size_t capacity, size_t *offset,
                                  uintptr_t target) {
    if (bh_arm64_align8(dst, capacity, offset) != 0) return -1;
    size_t base = *offset;
    if (bh_arm64_emit_ldr_x16(dst, capacity, offset, 8) != 0) return -1;
    if (bh_arm64_emit_u32(dst, capacity, offset, BH_ARM64_BR_X16) != 0) return -1;
    if (bh_arm64_emit_u64(dst, capacity, offset, (uint64_t)target) != 0) return -1;
    (void)base;
    return 0;
}

static int bh_arm64_emit_abs_call(uint8_t *dst, size_t capacity, size_t *offset,
                                  uintptr_t target) {
    if (bh_arm64_align8(dst, capacity, offset) != 0) return -1;
    size_t base = *offset;
    if (bh_arm64_emit_ldr_x16(dst, capacity, offset, 16) != 0) return -1;
    if (bh_arm64_emit_u32(dst, capacity, offset, BH_ARM64_BLR_X16) != 0) return -1;
    if (bh_arm64_emit_b(dst, capacity, offset, (uintptr_t)dst + *offset,
                        (uintptr_t)dst + base + 24) != 0)
        return -1;
    if (bh_arm64_emit_u32(dst, capacity, offset, BH_ARM64_NOP) != 0) return -1;
    if (bh_arm64_emit_u64(dst, capacity, offset, (uint64_t)target) != 0) return -1;
    return 0;
}

static int bh_arm64_emit_conditional(uint8_t *dst, size_t capacity, size_t *offset,
                                     uint32_t branch_insn, uintptr_t target) {
    if (bh_arm64_align8(dst, capacity, offset) != 0) return -1;
    size_t base = *offset;
    uint32_t inverted = branch_insn;

    if ((branch_insn & 0xFF000010u) == 0x54000000u) {
        inverted ^= 1u;
        inverted = (inverted & ~(0x7FFFFu << 5)) | (6u << 5);
    } else if ((branch_insn & 0x7E000000u) == 0x34000000u) {
        inverted ^= (1u << 24);
        inverted = (inverted & ~(0x7FFFFu << 5)) | (6u << 5);
    } else if ((branch_insn & 0x7E000000u) == 0x36000000u) {
        inverted ^= (1u << 24);
        inverted = (inverted & ~(0x3FFFu << 5)) | (6u << 5);
    } else {
        return -1;
    }

    if (bh_arm64_emit_u32(dst, capacity, offset, inverted) != 0) return -1;
    if (bh_arm64_emit_ldr_x16(dst, capacity, offset, 12) != 0) return -1;
    if (bh_arm64_emit_u32(dst, capacity, offset, BH_ARM64_BR_X16) != 0) return -1;
    if (bh_arm64_emit_u32(dst, capacity, offset, BH_ARM64_NOP) != 0) return -1;
    if (bh_arm64_emit_u64(dst, capacity, offset, (uint64_t)target) != 0) return -1;
    (void)base;
    return 0;
}

static int bh_arm64_emit_materialize(uint8_t *dst, size_t capacity, size_t *offset,
                                     unsigned rt, uint64_t value) {
    if (bh_arm64_align8(dst, capacity, offset) != 0) return -1;
    if (rt > 31) {
        return -1;
    }
    if (bh_arm64_emit_u32(dst, capacity, offset,
                          0x58000040u | rt) != 0) /* ldr xRt, #8 */
        return -1;
    if (bh_arm64_emit_b(dst, capacity, offset, (uintptr_t)dst + *offset,
                        (uintptr_t)dst + *offset + 12) != 0)
        return -1;
    if (bh_arm64_emit_u64(dst, capacity, offset, value) != 0) return -1;
    return 0;
}

static int bh_arm64_emit_literal_load(uint8_t *dst, size_t capacity, size_t *offset,
                                      uint32_t insn, uintptr_t address) {
    if (bh_arm64_align8(dst, capacity, offset) != 0) return -1;
    unsigned v = (insn >> 26) & 1u;
    unsigned opc = (insn >> 30) & 3u;
    unsigned rt = insn & 0x1Fu;
    uint32_t load;

    if (v == 0) {
        if (opc == 0) {
            load = 0xB9400000u | (16u << 5) | rt;
        } else if (opc == 1) {
            load = 0xF9400000u | (16u << 5) | rt;
        } else if (opc == 2) {
            load = 0xB9800000u | (16u << 5) | rt;
        } else {
            return bh_arm64_emit_u32(dst, capacity, offset, BH_ARM64_NOP);
        }
    } else {
        if (opc == 0) {
            load = 0xBD400000u | (16u << 5) | rt;
        } else if (opc == 1) {
            load = 0xFD400000u | (16u << 5) | rt;
        } else if (opc == 2) {
            load = 0x3DC00000u | (16u << 5) | rt;
        } else {
            return -1;
        }
    }

    if (bh_arm64_emit_ldr_x16(dst, capacity, offset, 16) != 0) return -1;
    if (bh_arm64_emit_u32(dst, capacity, offset, load) != 0) return -1;
    if (bh_arm64_emit_b(dst, capacity, offset, (uintptr_t)dst + *offset,
                        (uintptr_t)dst + *offset + 16) != 0)
        return -1;
    if (bh_arm64_emit_u32(dst, capacity, offset, BH_ARM64_NOP) != 0) return -1;
    if (bh_arm64_emit_u64(dst, capacity, offset, (uint64_t)address) != 0) return -1;
    return 0;
}

int bh_arch_query(bh_arch_info_t *info) {
    if (info == NULL) return -1;
    info->patch_size = 4;
    info->relay_size = 16;
    info->max_distance = (size_t)0x06000000u;
    return 0;
}

size_t bh_arch_patch_size(uintptr_t target, int thumb) {
    (void)target;
    (void)thumb;
    return 4;
}

int bh_arch_relocate(const uint8_t *src_bytes, uintptr_t src_address,
                     size_t min_bytes, int thumb, void *dst, size_t dst_capacity,
                     size_t *out_len, size_t *copied) {
    size_t source_offset = 0;
    size_t output_offset = 0;
    (void)thumb;

    if (src_bytes == NULL || dst == NULL || out_len == NULL || copied == NULL ||
        min_bytes == 0) {
        return -1;
    }

    if (bh_arm64_emit_u32((uint8_t *)dst, dst_capacity, &output_offset,
                          BH_ARM64_BTI_C) != 0) {
        return -1;
    }

    while (source_offset < min_bytes) {
        uint32_t insn;
        uintptr_t instruction_address;
        const uint8_t *source;

        if (source_offset + 4 > 32) {
            return -1;
        }
        source = src_bytes + source_offset;
        insn = bh_arm64_rd32(source);
        instruction_address = src_address + source_offset;

        if ((insn & 0x7C000000u) == 0x14000000u) {
            int64_t displacement = bh_arm64_sign_extend(insn & 0x03FFFFFFu, 26) << 2;
            uintptr_t target = (uintptr_t)((int64_t)instruction_address + displacement);
            if ((insn & 0x80000000u) != 0) {
                if (bh_arm64_emit_abs_call((uint8_t *)dst, dst_capacity, &output_offset,
                                           target) != 0)
                    return -1;
            } else {
                if (bh_arm64_emit_abs_jump((uint8_t *)dst, dst_capacity, &output_offset,
                                           target) != 0)
                    return -1;
            }
        } else if ((insn & 0xFF000010u) == 0x54000000u) {
            int64_t displacement = bh_arm64_sign_extend((insn >> 5) & 0x7FFFFu, 19) << 2;
            uintptr_t target = (uintptr_t)((int64_t)instruction_address + displacement);
            if (bh_arm64_emit_conditional((uint8_t *)dst, dst_capacity, &output_offset,
                                          insn, target) != 0)
                return -1;
        } else if ((insn & 0x7E000000u) == 0x34000000u) {
            int64_t displacement = bh_arm64_sign_extend((insn >> 5) & 0x7FFFFu, 19) << 2;
            uintptr_t target = (uintptr_t)((int64_t)instruction_address + displacement);
            if (bh_arm64_emit_conditional((uint8_t *)dst, dst_capacity, &output_offset,
                                          insn, target) != 0)
                return -1;
        } else if ((insn & 0x7E000000u) == 0x36000000u) {
            int64_t displacement = bh_arm64_sign_extend((insn >> 5) & 0x3FFFu, 14) << 2;
            uintptr_t target = (uintptr_t)((int64_t)instruction_address + displacement);
            if (bh_arm64_emit_conditional((uint8_t *)dst, dst_capacity, &output_offset,
                                          insn, target) != 0)
                return -1;
        } else if ((insn & 0x9F000000u) == 0x10000000u ||
                   (insn & 0x9F000000u) == 0x90000000u) {
            uint64_t immlo = (insn >> 29) & 3u;
            uint64_t immhi = (insn >> 5) & 0x7FFFFu;
            int64_t displacement = bh_arm64_sign_extend((immhi << 2) | immlo, 21);
            uint64_t value;
            unsigned rd = insn & 0x1Fu;
            if ((insn & 0x80000000u) != 0) {
                displacement <<= 12;
                value = (uint64_t)(((instruction_address & ~(uintptr_t)0xFFFu) +
                                    (uintptr_t)displacement));
            } else {
                value = (uint64_t)((int64_t)instruction_address + displacement);
            }
            if (bh_arm64_emit_materialize((uint8_t *)dst, dst_capacity, &output_offset,
                                          rd, value) != 0)
                return -1;
        } else if ((insn & 0x3B000000u) == 0x18000000u) {
            int64_t displacement = bh_arm64_sign_extend((insn >> 5) & 0x7FFFFu, 19) << 2;
            uintptr_t target = (uintptr_t)((int64_t)instruction_address + displacement);
            if (bh_arm64_emit_literal_load((uint8_t *)dst, dst_capacity, &output_offset,
                                           insn, target) != 0)
                return -1;
        } else {
            if (bh_arm64_emit_u32((uint8_t *)dst, dst_capacity, &output_offset,
                                  insn) != 0) {
                return -1;
            }
        }

        source_offset += 4;
    }

    if (bh_arm64_emit_abs_jump((uint8_t *)dst, dst_capacity, &output_offset,
                               src_address + source_offset) != 0) {
        return -1;
    }

    *out_len = output_offset;
    *copied = source_offset;
    return 0;
}

int bh_arch_emit_relay(void *relay, size_t capacity, const void *dest, int thumb) {
    uint8_t *bytes = (uint8_t *)relay;
    size_t offset = 0;
    uintptr_t from = (uintptr_t)relay;
    uintptr_t to = (uintptr_t)dest;
    int64_t displacement = (int64_t)to - (int64_t)from;
    (void)thumb;

    if (relay == NULL || dest == NULL || capacity < 16) {
        return -1;
    }
    if ((displacement & 3) == 0 && displacement >= -(1ll << 27) &&
        displacement < (1ll << 27)) {
        if (bh_arm64_emit_b(bytes, capacity, &offset, from, to) != 0) return -1;
    } else {
        if (bh_arm64_emit_abs_jump(bytes, capacity, &offset, to) != 0) return -1;
    }
    while (offset < 16) {
        if (bh_arm64_emit_u32(bytes, capacity, &offset, BH_ARM64_NOP) != 0) return -1;
    }
    return 16;
}

int bh_arch_emit_patch(void *target, const void *dest, const void *relay,
                       int thumb, void *out, size_t capacity) {
    uintptr_t to = relay != NULL ? (uintptr_t)relay : (uintptr_t)dest;
    uintptr_t from = (uintptr_t)target;
    int64_t displacement = (int64_t)to - (int64_t)from;
    uint8_t *bytes = (uint8_t *)out;
    (void)thumb;

    if (target == NULL || out == NULL || capacity < 4) {
        return -1;
    }
    if ((displacement & 3) != 0 || displacement < -(1ll << 27) ||
        displacement >= (1ll << 27)) {
        return -1;
    }
    {
        uint32_t insn = 0x14000000u |
                        (((uint32_t)(displacement >> 2)) & 0x03FFFFFFu);
        bytes[0] = (uint8_t)insn;
        bytes[1] = (uint8_t)(insn >> 8);
        bytes[2] = (uint8_t)(insn >> 16);
        bytes[3] = (uint8_t)(insn >> 24);
    }
    return 4;
}

#endif /* __aarch64__ */
