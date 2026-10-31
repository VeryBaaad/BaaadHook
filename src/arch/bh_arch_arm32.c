/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE 1

#include "bh_internal.h"

#if defined(__arm__)

#include <stdint.h>
#include <string.h>

#define BH_ARM_NOP 0xE1A00000u
#define BH_THUMB_NOP 0xBF00u
#define BH_ARM_BX_R12 0xE12FFF1Cu
#define BH_ARM_BLX_R12 0xE12FFF3Cu
#define BH_THUMB_BX_R12 0x4760u
#define BH_THUMB_BLX_R12 0x47E0u
#define BH_ARM_MATERIALIZE_SIZE 16u

static uint16_t bh_arm_rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t bh_arm_rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int64_t bh_arm_sign_extend(uint64_t value, unsigned bits) {
    uint64_t sign = 1ull << (bits - 1u);
    return (int64_t)((value ^ sign) - sign);
}

static int bh_arm_emit_u16(uint8_t *dst, size_t capacity, size_t *offset,
                           uint16_t value) {
    if (*offset + 2 > capacity) return -1;
    dst[*offset + 0] = (uint8_t)value;
    dst[*offset + 1] = (uint8_t)(value >> 8);
    *offset += 2;
    return 0;
}

static int bh_thumb_emit_u32(uint8_t *dst, size_t capacity, size_t *offset,
                             uint16_t hw1, uint16_t hw2) {
    if (bh_arm_emit_u16(dst, capacity, offset, hw1) != 0) return -1;
    return bh_arm_emit_u16(dst, capacity, offset, hw2);
}

static int bh_arm_emit_u32(uint8_t *dst, size_t capacity, size_t *offset,
                           uint32_t value) {
    if (*offset + 4 > capacity) return -1;
    dst[*offset + 0] = (uint8_t)value;
    dst[*offset + 1] = (uint8_t)(value >> 8);
    dst[*offset + 2] = (uint8_t)(value >> 16);
    dst[*offset + 3] = (uint8_t)(value >> 24);
    *offset += 4;
    return 0;
}

static uint32_t bh_arm_expand_imm(uint32_t imm12) {
    uint32_t value = imm12 & 0xFFu;
    uint32_t rotate = ((imm12 >> 8) & 0xFu) * 2u;
    if (rotate == 0) return value;
    return (value >> rotate) | (value << (32u - rotate));
}

static int bh_arm_align4(uint8_t *dst, size_t capacity, size_t *offset, int thumb) {
    if ((*offset & 3u) != 0) {
        if (thumb) {
            return bh_arm_emit_u16(dst, capacity, offset, BH_THUMB_NOP);
        }
        return bh_arm_emit_u32(dst, capacity, offset, BH_ARM_NOP);
    }
    return 0;
}

static int bh_arm_emit_b(uint8_t *dst, size_t capacity, size_t *offset,
                         uintptr_t from, uintptr_t target, unsigned condition) {
    int64_t displacement = (int64_t)target - (int64_t)(from + 8);
    if ((displacement & 3) != 0 || displacement < -(1ll << 25) ||
        displacement >= (1ll << 25)) {
        return -1;
    }
    return bh_arm_emit_u32(
        dst, capacity, offset,
        ((uint32_t)condition << 28) | 0x0A000000u |
            (((uint32_t)(displacement >> 2)) & 0x00FFFFFFu));
}

static int bh_arm_emit_abs_jump(uint8_t *dst, size_t capacity, size_t *offset,
                                uintptr_t target) {
    if (bh_arm_emit_u32(dst, capacity, offset, 0xE59FC000u) != 0) return -1;
    if (bh_arm_emit_u32(dst, capacity, offset, BH_ARM_BX_R12) != 0) return -1;
    return bh_arm_emit_u32(dst, capacity, offset, (uint32_t)target);
}

static int bh_arm_emit_abs_call(uint8_t *dst, size_t capacity, size_t *offset,
                                uintptr_t target) {
    if (bh_arm_emit_u32(dst, capacity, offset, 0xE59FC008u) != 0) return -1;
    if (bh_arm_emit_u32(dst, capacity, offset, BH_ARM_BLX_R12) != 0) return -1;
    if (bh_arm_emit_b(dst, capacity, offset, (uintptr_t)dst + *offset,
                      (uintptr_t)dst + *offset + 12, 0xE) != 0)
        return -1;
    if (bh_arm_emit_u32(dst, capacity, offset, BH_ARM_NOP) != 0) return -1;
    return bh_arm_emit_u32(dst, capacity, offset, (uint32_t)target);
}

static int bh_arm_emit_conditional_jump(uint8_t *dst, size_t capacity,
                                        size_t *offset, uintptr_t target,
                                        unsigned condition, int link) {
    size_t base = *offset;
    unsigned inverse = condition ^ 1u;
    if (link) {
        if (bh_arm_emit_b(dst, capacity, offset, (uintptr_t)dst + base,
                          (uintptr_t)dst + base + 24, inverse) != 0)
            return -1;
        if (bh_arm_emit_u32(dst, capacity, offset, 0xE59FC008u) != 0) return -1;
        if (bh_arm_emit_u32(dst, capacity, offset, BH_ARM_BLX_R12) != 0) return -1;
        if (bh_arm_emit_b(dst, capacity, offset, (uintptr_t)dst + *offset,
                          (uintptr_t)dst + base + 24, 0xE) != 0)
            return -1;
        if (bh_arm_emit_u32(dst, capacity, offset, BH_ARM_NOP) != 0) return -1;
        return bh_arm_emit_u32(dst, capacity, offset, (uint32_t)target);
    }

    if (bh_arm_emit_b(dst, capacity, offset, (uintptr_t)dst + base,
                      (uintptr_t)dst + base + 16, inverse) != 0)
        return -1;
    if (bh_arm_emit_u32(dst, capacity, offset, 0xE59FC000u) != 0) return -1;
    if (bh_arm_emit_u32(dst, capacity, offset, BH_ARM_BX_R12) != 0) return -1;
    return bh_arm_emit_u32(dst, capacity, offset, (uint32_t)target);
}

static int bh_arm_emit_materialize(uint8_t *dst, size_t capacity, size_t *offset,
                                   unsigned rd, uint32_t value) {
    if (rd > 14) return -1;
    if (bh_arm_emit_u32(dst, capacity, offset,
                        0xE59F0004u | (rd << 12)) != 0) /* ldr rd, [pc, #4] */
        return -1;
    if (bh_arm_emit_b(dst, capacity, offset, (uintptr_t)dst + *offset,
                      (uintptr_t)dst + *offset + 12, 0xE) != 0)
        return -1;
    if (bh_arm_emit_u32(dst, capacity, offset, BH_ARM_NOP) != 0) return -1;
    return bh_arm_emit_u32(dst, capacity, offset, value);
}

static int bh_arm_emit_conditional_materialize(uint8_t *dst, size_t capacity,
                                               size_t *offset, unsigned rd,
                                               uint32_t value,
                                               unsigned condition) {
    if (condition != 0xEu) {
        size_t base = *offset;
        if (bh_arm_emit_b(dst, capacity, offset, (uintptr_t)dst + base,
                          (uintptr_t)dst + base + 4u + BH_ARM_MATERIALIZE_SIZE,
                          condition ^ 1u) != 0)
            return -1;
    }
    return bh_arm_emit_materialize(dst, capacity, offset, rd, value);
}

static int bh_arm_emit_literal_load(uint8_t *dst, size_t capacity, size_t *offset,
                                    uint32_t insn, uintptr_t address) {
    uint32_t rewritten = (insn & ~0x000F0FFFu) | (12u << 16);
    if ((insn & 0x0F000000u) == 0x05000000u) {
        /* LDR/LDRB (immediate, literal) */
        if (bh_arm_emit_u32(dst, capacity, offset, 0xE59FC004u) != 0) return -1;
        if (bh_arm_emit_u32(dst, capacity, offset, rewritten) != 0) return -1;
        if (bh_arm_emit_u32(dst, capacity, offset, 0xEA000000u) != 0) return -1;
        return bh_arm_emit_u32(dst, capacity, offset, (uint32_t)address);
    }

    /* LDRH/LDRSB/LDRSH */
    rewritten = (insn & ~0x000F0F0Fu) | (12u << 16);
    if (bh_arm_emit_u32(dst, capacity, offset, 0xE59FC004u) != 0) return -1;
    if (bh_arm_emit_u32(dst, capacity, offset, rewritten) != 0) return -1;
    if (bh_arm_emit_u32(dst, capacity, offset, 0xEA000000u) != 0) return -1;
    return bh_arm_emit_u32(dst, capacity, offset, (uint32_t)address);
}

static int bh_thumb_emit_abs_jump(uint8_t *dst, size_t capacity, size_t *offset,
                                  uintptr_t target) {
    if (bh_thumb_emit_u32(dst, capacity, offset, 0xF8DFu, 0xC004u) != 0)
        return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, BH_THUMB_BX_R12) != 0) return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, BH_THUMB_NOP) != 0) return -1;
    return bh_arm_emit_u32(dst, capacity, offset, (uint32_t)target);
}

static int bh_thumb_emit_abs_call(uint8_t *dst, size_t capacity, size_t *offset,
                                  uintptr_t target) {
    if (bh_thumb_emit_u32(dst, capacity, offset, 0xF8DFu, 0xC008u) != 0)
        return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, BH_THUMB_BLX_R12) != 0) return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, 0xE003u) != 0) return -1;
    if (bh_thumb_emit_u32(dst, capacity, offset, 0xBF00u, 0xBF00u) != 0)
        return -1;
    return bh_arm_emit_u32(dst, capacity, offset, (uint32_t)target);
}

static int bh_thumb_emit_cond16(uint8_t *dst, size_t capacity, size_t *offset,
                                uint16_t branch, uintptr_t target) {
    if (bh_arm_align4(dst, capacity, offset, 1) != 0) return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, branch) != 0) return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, BH_THUMB_NOP) != 0) return -1;
    if (bh_thumb_emit_u32(dst, capacity, offset, 0xF8DFu, 0xC004u) != 0)
        return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, BH_THUMB_BX_R12) != 0) return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, BH_THUMB_NOP) != 0) return -1;
    return bh_arm_emit_u32(dst, capacity, offset, (uint32_t)target);
}

static int bh_thumb_emit_materialize16(uint8_t *dst, size_t capacity,
                                       size_t *offset, unsigned rd,
                                       uint32_t value) {
    if (rd > 7) return -1;
    if (bh_thumb_emit_u32(dst, capacity, offset, 0xF8DFu,
                          (uint16_t)(0x0004u | (rd << 12))) != 0)
        return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, 0xE002u) != 0) return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, BH_THUMB_NOP) != 0) return -1;
    return bh_arm_emit_u32(dst, capacity, offset, value);
}

static int bh_thumb_emit_materialize_any(uint8_t *dst, size_t capacity,
                                         size_t *offset, unsigned rd,
                                         uint32_t value) {
    if (rd >= 15) return -1;
    if (bh_thumb_emit_u32(dst, capacity, offset, 0xF8DFu,
                          (uint16_t)(0x0004u | (rd << 12))) != 0)
        return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, 0xE002u) != 0) return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, BH_THUMB_NOP) != 0) return -1;
    return bh_arm_emit_u32(dst, capacity, offset, value);
}

static uint32_t bh_thumb_bw(uintptr_t from, uintptr_t target) {
    int64_t displacement = (int64_t)target - (int64_t)(from + 4);
    uint32_t s, imm10, imm11, i1, i2, j1, j2;
    if ((displacement & 1) != 0 || displacement < -(1ll << 24) ||
        displacement >= (1ll << 24)) {
        return 0;
    }
    s = ((uint64_t)displacement >> 24) & 1u;
    i1 = ((uint64_t)displacement >> 23) & 1u;
    i2 = ((uint64_t)displacement >> 22) & 1u;
    imm10 = ((uint64_t)displacement >> 12) & 0x3FFu;
    imm11 = ((uint64_t)displacement >> 1) & 0x7FFu;
    j1 = ((~i1) & 1u) ^ s;
    j2 = ((~i2) & 1u) ^ s;
    return (0xF000u | (s << 10) | imm10) |
           ((0x8800u | (j1 << 13) | (j2 << 12) | imm11) << 16);
}

static int bh_thumb_emit_ldr16(uint8_t *dst, size_t capacity, size_t *offset,
                               unsigned rt, uintptr_t address) {
    if (bh_thumb_emit_u32(dst, capacity, offset, 0xF8DFu, 0xC008u) != 0)
        return -1;
    if (bh_thumb_emit_u32(dst, capacity, offset, 0xF8DCu,
                          (uint16_t)(rt << 12)) != 0)
        return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, 0xE002u) != 0) return -1;
    if (bh_arm_emit_u16(dst, capacity, offset, BH_THUMB_NOP) != 0) return -1;
    return bh_arm_emit_u32(dst, capacity, offset, (uint32_t)address);
}

int bh_arch_query(bh_arch_info_t *info) {
    if (info == NULL) return -1;
    info->patch_size = 4;
    info->relay_size = 16;
    info->max_distance = (size_t)0x00C00000u;
    return 0;
}

static int bh_arm_relocate_arm(const uint8_t *src_bytes, uintptr_t src_address,
                               void *dst, size_t dst_capacity, size_t *out_len,
                               size_t *copied) {
    uint32_t insn = bh_arm_rd32(src_bytes);
    size_t offset = 0;
    unsigned condition = (insn >> 28) & 0xFu;

    if ((insn & 0xFE000000u) == 0xFA000000u) {
        int64_t displacement = bh_arm_sign_extend(insn & 0x00FFFFFFu, 24) << 2;
        uintptr_t target = (uintptr_t)((int64_t)((src_address + 8u) & ~(uintptr_t)3u) +
                                       displacement + ((insn >> 24) & 1u) * 2u);
        if ((insn >> 24) & 1u) {
            target |= 1u;
        }
        if (bh_arm_emit_abs_call((uint8_t *)dst, dst_capacity, &offset, target) != 0)
            return -1;
    } else if ((insn & 0x0E000000u) == 0x0A000000u && condition != 0xFu) {
        int64_t displacement = bh_arm_sign_extend(insn & 0x00FFFFFFu, 24) << 2;
        uintptr_t target = (uintptr_t)((int64_t)(src_address + 8u) + displacement);
        int link = (insn & 0x01000000u) != 0;
        if (condition == 0xEu) {
            if (link) {
                if (bh_arm_emit_abs_call((uint8_t *)dst, dst_capacity, &offset,
                                         target) != 0)
                    return -1;
            } else {
                if (bh_arm_emit_abs_jump((uint8_t *)dst, dst_capacity, &offset,
                                         target) != 0)
                    return -1;
            }
        } else {
            if (bh_arm_emit_conditional_jump((uint8_t *)dst, dst_capacity, &offset,
                                             target, condition, link) != 0)
                return -1;
        }
    } else if ((insn & 0x0F000000u) == 0x05000000u &&
               (insn & 0x00200000u) == 0 && (insn & 0x00100000u) != 0 &&
               ((insn >> 16) & 0xFu) == 15u) {
        uint32_t imm12 = insn & 0xFFFu;
        uintptr_t target = (insn & 0x00800000u)
                               ? src_address + 8u + imm12
                               : src_address + 8u - imm12;
        if (bh_arm_emit_literal_load((uint8_t *)dst, dst_capacity, &offset, insn,
                                     target) != 0)
            return -1;
    } else if ((insn & 0x0E000000u) == 0 && (insn & 0x00400000u) != 0 &&
               (insn & 0x00200000u) == 0 && (insn & 0x00100000u) != 0 &&
               ((insn >> 16) & 0xFu) == 15u && (insn & 0x10u) == 0) {
        uint32_t imm12 = ((insn >> 4) & 0xF0u) | (insn & 0x0Fu);
        uintptr_t target = (insn & 0x00800000u)
                               ? src_address + 8u + imm12
                               : src_address + 8u - imm12;
        if (bh_arm_emit_literal_load((uint8_t *)dst, dst_capacity, &offset, insn,
                                     target) != 0)
            return -1;
    } else if ((insn & 0x0FEF0000u) == 0x028F0000u ||
               (insn & 0x0FEF0000u) == 0x024F0000u) {
        uint32_t imm12 = insn & 0xFFFu;
        uint32_t value = bh_arm_expand_imm(imm12);
        uint32_t target = (insn & 0x00400000u) ? src_address + 8u - value
                                               : src_address + 8u + value;
        unsigned rd = (insn >> 12) & 0xFu;
        if ((insn & 0x00100000u) != 0 || condition == 0xFu) return -1;
        if (bh_arm_emit_conditional_materialize((uint8_t *)dst, dst_capacity,
                                                &offset, rd, target,
                                                condition) != 0)
            return -1;
    } else if ((insn & 0x0FEF000Fu) == 0x01A0000Fu) {
        unsigned rd = (insn >> 12) & 0xFu;
        if ((insn & 0x00100000u) != 0 || (insn & 0xFF0u) != 0) return -1;
        if (bh_arm_emit_conditional_materialize((uint8_t *)dst, dst_capacity,
                                                &offset, rd,
                                                (uint32_t)(src_address + 8u),
                                                condition) != 0)
            return -1;
    } else if ((insn & 0x0F000000u) == 0x0D000000u &&
               (insn & 0x00200000u) == 0 && (insn & 0x00100000u) != 0 &&
               ((insn >> 16) & 0xFu) == 15u) {
        return -1;
    } else if (((insn & 0x0C000000u) == 0x04000000u) &&
               ((insn >> 16) & 0xFu) == 15u) {
        return -1;
    } else {
        if (bh_arm_emit_u32((uint8_t *)dst, dst_capacity, &offset, insn) != 0)
            return -1;
    }

    if (bh_arm_emit_b((uint8_t *)dst, dst_capacity, &offset,
                      (uintptr_t)dst + offset, src_address + 4u, 0xEu) != 0) {
        if (bh_arm_emit_abs_jump((uint8_t *)dst, dst_capacity, &offset,
                                 src_address + 4u) != 0)
            return -1;
    }

    *out_len = offset;
    *copied = 4;
    return 0;
}

static int bh_arm_relocate_thumb(const uint8_t *src_bytes, uintptr_t src_address,
                                 void *dst, size_t dst_capacity, size_t *out_len,
                                 size_t *copied, size_t min_bytes) {
    size_t source_offset = 0;
    size_t output_offset = 0;

    while (source_offset < 4) {
        uint16_t hw1;
        uintptr_t instruction_address;

        if (source_offset + 4 > 32) return -1;
        hw1 = bh_arm_rd16(src_bytes + source_offset);
        instruction_address = src_address + source_offset;

        if ((source_offset == 0 || source_offset == 2) &&
            (hw1 & 0xFF00u) == 0xBF00u && (hw1 & 0xFu) != 0) {
            return -1;
        }
        if (source_offset == 0 && min_bytes > 2 &&
            (hw1 == 0x4770u || (hw1 & 0xFF00u) == 0xBD00u)) {
            return -1;
        }

        if ((hw1 & 0xFF00u) == 0x4600u && ((hw1 >> 3) & 0xFu) == 0xFu) {
            /* MOV Rd */
            unsigned rd = (hw1 & 7u) | ((hw1 >> 4) & 8u);
            uintptr_t pc_value = instruction_address + 4u;
            if (bh_arm_align4((uint8_t *)dst, dst_capacity, &output_offset, 1) != 0)
                return -1;
            if (bh_thumb_emit_materialize_any((uint8_t *)dst, dst_capacity,
                                              &output_offset, rd,
                                              (uint32_t)pc_value) != 0)
                return -1;
            source_offset += 2;
        } else if ((hw1 & 0xFF00u) == 0x4400u &&
                   ((hw1 >> 3) & 0xFu) == 0xFu) {
            /* ADD/CMP with PC */
            return -1;
        } else if ((hw1 & 0xFF00u) == 0x4500u &&
                   ((hw1 >> 3) & 0xFu) == 0xFu) {
            return -1;
        } else if ((hw1 & 0xF800u) == 0xE000u) {
            int64_t displacement = bh_arm_sign_extend(hw1 & 0x7FFu, 11) << 1;
            uintptr_t target = (uintptr_t)((int64_t)(instruction_address + 4u) +
                                           displacement) | 1u;
            if (bh_arm_align4((uint8_t *)dst, dst_capacity, &output_offset, 1) != 0)
                return -1;
            if (bh_thumb_emit_abs_jump((uint8_t *)dst, dst_capacity, &output_offset,
                                       target) != 0)
                return -1;
            source_offset += 2;
        } else if ((hw1 & 0xF000u) == 0xD000u && ((hw1 >> 8) & 0xFu) < 0xEu) {
            unsigned condition = (hw1 >> 8) & 0xFu;
            int64_t displacement = bh_arm_sign_extend(hw1 & 0xFFu, 8) << 1;
            uintptr_t target = (uintptr_t)((int64_t)(instruction_address + 4u) +
                                           displacement) | 1u;
            uint16_t branch = (uint16_t)(0xD000u | (((condition ^ 1u) & 0xFu) << 8) |
                                         6u);
            if (bh_arm_align4((uint8_t *)dst, dst_capacity, &output_offset, 1) != 0)
                return -1;
            if (bh_thumb_emit_cond16((uint8_t *)dst, dst_capacity, &output_offset,
                                     branch, target) != 0)
                return -1;
            source_offset += 2;
        } else if ((hw1 & 0xF500u) == 0xB100u) {
            unsigned rn = hw1 & 7u;
            unsigned i = (hw1 >> 9) & 1u;
            unsigned imm5 = (hw1 >> 3) & 0x1Fu;
            uint32_t displacement = (i << 6) | (imm5 << 1);
            uintptr_t target =
                (uintptr_t)(instruction_address + 4u + displacement) | 1u;
            unsigned inverse = ((hw1 >> 11) & 1u) ^ 1u;
            uint16_t branch = (uint16_t)(0xB100u | (inverse << 11) | (6u << 3) | rn);
            if (bh_arm_align4((uint8_t *)dst, dst_capacity, &output_offset, 1) != 0)
                return -1;
            if (bh_thumb_emit_cond16((uint8_t *)dst, dst_capacity, &output_offset,
                                     branch, target) != 0)
                return -1;
            source_offset += 2;
        } else if ((hw1 & 0xF800u) == 0x4800u) {
            unsigned rt = (hw1 >> 8) & 7u;
            uint32_t imm8 = hw1 & 0xFFu;
            uintptr_t target = ((instruction_address + 4u) & ~(uintptr_t)3u) +
                               imm8 * 4u;
            if (bh_arm_align4((uint8_t *)dst, dst_capacity, &output_offset, 1) != 0)
                return -1;
            if (bh_thumb_emit_ldr16((uint8_t *)dst, dst_capacity, &output_offset, rt,
                                    target) != 0)
                return -1;
            source_offset += 2;
        } else if ((hw1 & 0xF800u) == 0xA000u) {
            unsigned rd = (hw1 >> 8) & 7u;
            uint32_t imm8 = hw1 & 0xFFu;
            uintptr_t target = ((instruction_address + 4u) & ~(uintptr_t)3u) +
                               imm8 * 4u;
            if (bh_arm_align4((uint8_t *)dst, dst_capacity, &output_offset, 1) != 0)
                return -1;
            if (bh_thumb_emit_materialize16((uint8_t *)dst, dst_capacity,
                                            &output_offset, rd,
                                            (uint32_t)target) != 0)
                return -1;
            source_offset += 2;
        } else if ((hw1 & 0xE000u) == 0xE000u && (hw1 & 0x1800u) != 0) {
            uint16_t hw2;
            uint32_t word;
            if (source_offset + 4 > 32) return -1;
            hw2 = bh_arm_rd16(src_bytes + source_offset + 2);
            word = (uint32_t)hw1 | ((uint32_t)hw2 << 16);

            if ((hw2 & 0xD000u) == 0x9000u) {
                uint32_t s = (hw1 >> 10) & 1u;
                uint32_t imm10 = hw1 & 0x3FFu;
                uint32_t j1 = (hw2 >> 13) & 1u;
                uint32_t j2 = (hw2 >> 11) & 1u;
                uint32_t i1 = ((~j1) & 1u) ^ s;
                uint32_t i2 = ((~j2) & 1u) ^ s;
                uint32_t raw = (s << 24) | (i1 << 23) | (i2 << 22) |
                               (imm10 << 12) | ((hw2 & 0x7FFu) << 1);
                int64_t displacement = bh_arm_sign_extend(raw, 25);
                uintptr_t target = (uintptr_t)((int64_t)(instruction_address + 4u) +
                                               displacement) | 1u;
                if (bh_arm_align4((uint8_t *)dst, dst_capacity, &output_offset,
                                  1) != 0)
                    return -1;
                if (bh_thumb_emit_abs_jump((uint8_t *)dst, dst_capacity,
                                           &output_offset, target) != 0)
                    return -1;
            } else if ((hw2 & 0xD000u) == 0xD000u) {
                uint32_t s = (hw1 >> 10) & 1u;
                uint32_t imm10 = hw1 & 0x3FFu;
                uint32_t j1 = (hw2 >> 13) & 1u;
                uint32_t j2 = (hw2 >> 11) & 1u;
                uint32_t i1 = ((~j1) & 1u) ^ s;
                uint32_t i2 = ((~j2) & 1u) ^ s;
                uint32_t raw = (s << 24) | (i1 << 23) | (i2 << 22) |
                               (imm10 << 12) | ((hw2 & 0x7FFu) << 1);
                int64_t displacement = bh_arm_sign_extend(raw, 25);
                uintptr_t target = (uintptr_t)((int64_t)(instruction_address + 4u) +
                                               displacement) | 1u;
                if (bh_arm_align4((uint8_t *)dst, dst_capacity, &output_offset,
                                  1) != 0)
                    return -1;
                if (bh_thumb_emit_abs_call((uint8_t *)dst, dst_capacity,
                                           &output_offset, target) != 0)
                    return -1;
            } else if ((hw2 & 0xD000u) == 0xC000u) {
                uint32_t s = (hw1 >> 10) & 1u;
                uint32_t imm10 = hw1 & 0x3FFu;
                uint32_t j1 = (hw2 >> 13) & 1u;
                uint32_t j2 = (hw2 >> 11) & 1u;
                uint32_t i1 = ((~j1) & 1u) ^ s;
                uint32_t i2 = ((~j2) & 1u) ^ s;
                uint32_t raw = (s << 24) | (i1 << 23) | (i2 << 22) |
                               (imm10 << 12) | ((hw2 & 0x7FFu) << 1);
                int64_t displacement = bh_arm_sign_extend(raw, 25);
                uintptr_t target = (uintptr_t)((int64_t)((instruction_address + 4u) &
                                                         ~(uintptr_t)3u) +
                                               displacement);
                if (bh_arm_align4((uint8_t *)dst, dst_capacity, &output_offset,
                                  1) != 0)
                    return -1;
                if (bh_thumb_emit_abs_call((uint8_t *)dst, dst_capacity,
                                           &output_offset, target) != 0)
                    return -1;
            } else if ((hw2 & 0xD000u) == 0x8000u) {
                unsigned condition = (hw1 >> 6) & 0xFu;
                uint32_t s = (hw1 >> 10) & 1u;
                uint32_t j1 = (hw2 >> 13) & 1u;
                uint32_t j2 = (hw2 >> 11) & 1u;
                uint32_t imm6 = hw1 & 0x3Fu;
                uint32_t imm11 = hw2 & 0x7FFu;
                uint32_t raw = (s << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) |
                               (imm11 << 1);
                int64_t displacement = bh_arm_sign_extend(raw, 21);
                uintptr_t target = (uintptr_t)((int64_t)(instruction_address + 4u) +
                                               displacement) | 1u;
                if (bh_arm_align4((uint8_t *)dst, dst_capacity, &output_offset,
                                  1) != 0)
                    return -1;
                if (bh_arm_emit_u16((uint8_t *)dst, dst_capacity, &output_offset,
                                    (uint16_t)(0xF000u |
                                               (((condition ^ 1u) & 0xFu) << 6))) != 0)
                    return -1;
                if (bh_arm_emit_u16((uint8_t *)dst, dst_capacity, &output_offset,
                                    (uint16_t)(0x8000u | 6u)) != 0)
                    return -1;
                if (bh_thumb_emit_u32((uint8_t *)dst, dst_capacity,
                                      &output_offset, 0xF8DFu, 0xC004u) != 0)
                    return -1;
                if (bh_arm_emit_u16((uint8_t *)dst, dst_capacity, &output_offset,
                                    BH_THUMB_BX_R12) != 0)
                    return -1;
                if (bh_arm_emit_u16((uint8_t *)dst, dst_capacity, &output_offset,
                                    BH_THUMB_NOP) != 0)
                    return -1;
                if (bh_arm_emit_u32((uint8_t *)dst, dst_capacity, &output_offset,
                                    (uint32_t)target) != 0)
                    return -1;
            } else if ((hw1 & 0xFF7Fu) == 0xF85Fu ||
                       (hw1 & 0xFF7Fu) == 0xF81Fu ||
                       (hw1 & 0xFF7Fu) == 0xF83Fu ||
                       (hw1 & 0xFF7Fu) == 0xF91Fu ||
                       (hw1 & 0xFF7Fu) == 0xF93Fu) {
                uint32_t imm12 = hw2 & 0xFFFu;
                unsigned rt = (hw2 >> 12) & 0xFu;
                uintptr_t target = ((instruction_address + 4u) & ~(uintptr_t)3u);
                if (hw1 & 0x80u) target += imm12;
                else target -= imm12;
                if (bh_arm_align4((uint8_t *)dst, dst_capacity, &output_offset,
                                  1) != 0)
                    return -1;
                if (bh_thumb_emit_u32((uint8_t *)dst, dst_capacity,
                                      &output_offset, 0xF8DFu, 0xC008u) != 0)
                    return -1;
                if (bh_arm_emit_u32((uint8_t *)dst, dst_capacity, &output_offset,
                                    (uint32_t)((hw1 & 0xFFF0u) | 0xCu) |
                                        ((uint32_t)rt << 12)) != 0)
                    return -1;
                if (bh_arm_emit_u16((uint8_t *)dst, dst_capacity, &output_offset,
                                    0xE002u) != 0)
                    return -1;
                if (bh_arm_emit_u16((uint8_t *)dst, dst_capacity, &output_offset,
                                    BH_THUMB_NOP) != 0)
                    return -1;
                if (bh_arm_emit_u32((uint8_t *)dst, dst_capacity, &output_offset,
                                    (uint32_t)target) != 0)
                    return -1;
            } else if ((hw1 & 0xFF0Fu) == 0xF20Fu) {
                uint32_t imm12 = (((hw2 >> 12) & 0xFu) << 8) | (hw2 & 0xFFu);
                unsigned rd = (hw2 >> 8) & 0xFu;
                uintptr_t base = (instruction_address + 4u) & ~(uintptr_t)3u;
                uintptr_t target = (hw1 & 0x0080u) ? base + imm12 : base - imm12;
                if (bh_arm_align4((uint8_t *)dst, dst_capacity, &output_offset,
                                  1) != 0)
                    return -1;
                if (bh_thumb_emit_materialize_any((uint8_t *)dst, dst_capacity,
                                                  &output_offset, rd,
                                                  (uint32_t)target) != 0)
                    return -1;
            } else {
                if (bh_arm_emit_u32((uint8_t *)dst, dst_capacity, &output_offset,
                                    word) != 0)
                    return -1;
            }
            source_offset += 4;
        } else {
            if (bh_arm_emit_u16((uint8_t *)dst, dst_capacity, &output_offset,
                                hw1) != 0)
                return -1;
            source_offset += 2;
        }
    }

    if (bh_arm_align4((uint8_t *)dst, dst_capacity, &output_offset, 1) != 0)
        return -1;
    {
        uint32_t branch = bh_thumb_bw((uintptr_t)dst + output_offset,
                                      src_address + source_offset);
        if (branch != 0) {
            if (bh_arm_emit_u32((uint8_t *)dst, dst_capacity, &output_offset,
                                branch) != 0)
                return -1;
        } else {
            if (bh_thumb_emit_abs_jump((uint8_t *)dst, dst_capacity,
                                       &output_offset,
                                       (src_address + source_offset) | 1u) != 0)
                return -1;
        }
    }

    *out_len = output_offset;
    *copied = source_offset;
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
    if (src_bytes == NULL || dst == NULL || out_len == NULL || copied == NULL ||
        min_bytes == 0) {
        return -1;
    }
    if (thumb) {
        return bh_arm_relocate_thumb(src_bytes, src_address, dst, dst_capacity,
                                     out_len, copied, min_bytes);
    }
    return bh_arm_relocate_arm(src_bytes, src_address, dst, dst_capacity, out_len,
                               copied);
}

int bh_arch_emit_relay(void *relay, size_t capacity, const void *dest, int thumb) {
    uint8_t *bytes = (uint8_t *)relay;
    size_t offset = 0;

    if (relay == NULL || dest == NULL || capacity < 16) {
        return -1;
    }
    if (thumb) {
        if (bh_thumb_emit_abs_jump(bytes, capacity, &offset, (uintptr_t)dest) != 0)
            return -1;
        while (offset < 16) {
            if (bh_arm_emit_u16(bytes, capacity, &offset, BH_THUMB_NOP) != 0)
                return -1;
        }
    } else {
        if (bh_arm_emit_abs_jump(bytes, capacity, &offset, (uintptr_t)dest) != 0)
            return -1;
        while (offset < 16) {
            if (bh_arm_emit_u32(bytes, capacity, &offset, BH_ARM_NOP) != 0)
                return -1;
        }
    }
    return 16;
}

int bh_arch_emit_patch(void *target, const void *dest, const void *relay,
                       int thumb, void *out, size_t capacity) {
    uintptr_t to = relay != NULL ? (uintptr_t)relay : (uintptr_t)dest;
    uintptr_t from = (uintptr_t)target;
    uint8_t *bytes = (uint8_t *)out;

    if (target == NULL || out == NULL || capacity < 4) {
        return -1;
    }
    if (thumb) {
        uint32_t encoded = bh_thumb_bw(from, to);
        if (encoded == 0) return -1;
        bytes[0] = (uint8_t)encoded;
        bytes[1] = (uint8_t)(encoded >> 8);
        bytes[2] = (uint8_t)(encoded >> 16);
        bytes[3] = (uint8_t)(encoded >> 24);
    } else {
        int64_t displacement = (int64_t)to - (int64_t)(from + 8);
        uint32_t encoded;
        if ((displacement & 3) != 0 || displacement < -(1ll << 25) ||
            displacement >= (1ll << 25)) {
            return -1;
        }
        encoded = 0xEA000000u |
                  (((uint32_t)(displacement >> 2)) & 0x00FFFFFFu);
        bytes[0] = (uint8_t)encoded;
        bytes[1] = (uint8_t)(encoded >> 8);
        bytes[2] = (uint8_t)(encoded >> 16);
        bytes[3] = (uint8_t)(encoded >> 24);
    }
    return 4;
}


size_t bh_arch_entry_prefix(const uint8_t *bytes, size_t size) {
    (void)bytes;
    (void)size;
    return 0;
}

#endif /* __arm__ */
