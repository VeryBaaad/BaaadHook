/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE 1

#include "bh_internal.h"

#if defined(__riscv) && (__riscv_xlen == 64)

#include <stdint.h>
#include <string.h>

#define BH_RV_NOP 0x00000013u
#define BH_RV_C_NOP 0x0001u
#define BH_RV_T0 5u
#define BH_RV_RA 1u

static uint32_t bh_rv_rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int64_t bh_rv_sign_extend(uint64_t value, unsigned bits) {
    uint64_t sign = 1ull << (bits - 1u);
    return (int64_t)((value ^ sign) - sign);
}

static int bh_rv_emit_u16(uint8_t *dst, size_t capacity, size_t *offset,
                          uint16_t value) {
    if (*offset + 2 > capacity) return -1;
    dst[*offset + 0] = (uint8_t)value;
    dst[*offset + 1] = (uint8_t)(value >> 8);
    *offset += 2;
    return 0;
}

static int bh_rv_emit_u32(uint8_t *dst, size_t capacity, size_t *offset,
                          uint32_t value) {
    if (*offset + 4 > capacity) return -1;
    dst[*offset + 0] = (uint8_t)value;
    dst[*offset + 1] = (uint8_t)(value >> 8);
    dst[*offset + 2] = (uint8_t)(value >> 16);
    dst[*offset + 3] = (uint8_t)(value >> 24);
    *offset += 4;
    return 0;
}

static int bh_rv_emit_u64(uint8_t *dst, size_t capacity, size_t *offset,
                          uint64_t value) {
    int i;
    if (*offset + 8 > capacity) return -1;
    for (i = 0; i < 8; i++) dst[*offset + i] = (uint8_t)(value >> (i * 8));
    *offset += 8;
    return 0;
}

static int bh_rv_align8(uint8_t *dst, size_t capacity, size_t *offset) {
    while ((*offset & 7u) != 0) {
        if (bh_rv_emit_u16(dst, capacity, offset, BH_RV_C_NOP) != 0) return -1;
    }
    return 0;
}

static uint32_t bh_rv_encode_auipc(unsigned rd, int32_t imm20) {
    return ((uint32_t)imm20 & 0xFFFFFu) << 12 | ((uint32_t)rd << 7) | 0x17u;
}

static uint32_t bh_rv_encode_jalr(unsigned rd, unsigned rs1, int32_t imm12) {
    return ((uint32_t)imm12 & 0xFFFu) << 20 | ((uint32_t)rs1 << 15) |
           ((uint32_t)rd << 7) | 0x67u;
}

static uint32_t bh_rv_encode_ld(unsigned rd, unsigned rs1, int32_t imm12) {
    return ((uint32_t)imm12 & 0xFFFu) << 20 | ((uint32_t)rs1 << 15) |
           (3u << 12) | ((uint32_t)rd << 7) | 0x03u;
}

static uint32_t bh_rv_encode_jal(unsigned rd, int32_t imm) {
    uint32_t value = (uint32_t)imm;
    return (((value >> 20) & 1u) << 31) | (((value >> 1) & 0x3FFu) << 21) |
           (((value >> 11) & 1u) << 20) | (((value >> 12) & 0xFFu) << 12) |
           ((uint32_t)rd << 7) | 0x6Fu;
}

static uint32_t bh_rv_encode_b(unsigned rs1, unsigned rs2, int32_t imm,
                               unsigned funct3) {
    uint32_t value = (uint32_t)imm;
    return (((value >> 12) & 1u) << 31) | (((value >> 5) & 0x3Fu) << 25) |
           ((uint32_t)rs2 << 20) | ((uint32_t)rs1 << 15) |
           ((uint32_t)funct3 << 12) | (((value >> 1) & 0xFu) << 8) |
           (((value >> 11) & 1u) << 7) | 0x63u;
}

static int bh_rv_emit_abs_jump(uint8_t *dst, size_t capacity, size_t *offset,
                               uintptr_t target, unsigned rd) {
    if (bh_rv_align8(dst, capacity, offset) != 0) return -1;
    if (bh_rv_emit_u32(dst, capacity, offset, bh_rv_encode_auipc(BH_RV_T0, 0)) != 0)
        return -1;
    if (bh_rv_emit_u32(dst, capacity, offset,
                       bh_rv_encode_ld(BH_RV_T0, BH_RV_T0, 16)) != 0)
        return -1;
    if (bh_rv_emit_u32(dst, capacity, offset,
                       bh_rv_encode_jalr(rd, BH_RV_T0, 0)) != 0)
        return -1;
    if (bh_rv_emit_u32(dst, capacity, offset, bh_rv_encode_b(0, 0, 12, 0)) != 0)
        return -1;
    if (bh_rv_emit_u64(dst, capacity, offset, (uint64_t)target) != 0) return -1;
    return 0;
}

static int bh_rv_emit_materialize(uint8_t *dst, size_t capacity, size_t *offset,
                                  unsigned rd, uint64_t value) {
    if (bh_rv_align8(dst, capacity, offset) != 0) return -1;
    if (bh_rv_emit_u32(dst, capacity, offset, bh_rv_encode_auipc(rd, 0)) != 0)
        return -1;
    if (bh_rv_emit_u32(dst, capacity, offset, bh_rv_encode_ld(rd, rd, 16)) != 0)
        return -1;
    if (bh_rv_emit_u32(dst, capacity, offset, bh_rv_encode_b(0, 0, 16, 0)) != 0)
        return -1;
    if (bh_rv_emit_u32(dst, capacity, offset, BH_RV_NOP) != 0) return -1;
    if (bh_rv_emit_u64(dst, capacity, offset, value) != 0) return -1;
    return 0;
}

static int bh_rv_emit_jal_direct(uint8_t *dst, size_t capacity, size_t *offset,
                                 uintptr_t from, uintptr_t target,
                                 unsigned rd) {
    int64_t delta = (int64_t)target - (int64_t)from;

    if ((delta & 1) != 0 || delta < -(1ll << 20) || delta >= (1ll << 20)) {
        return -1;
    }
    return bh_rv_emit_u32(dst, capacity, offset,
                          bh_rv_encode_jal(rd, (int32_t)delta));
}

static int bh_rv_emit_cond_jump(uint8_t *dst, size_t capacity, size_t *offset,
                                unsigned rs1, unsigned rs2, unsigned funct3,
                                uintptr_t target) {
    uintptr_t from = (uintptr_t)dst + *offset;
    int64_t delta = (int64_t)target - (int64_t)(from + 4);

    if ((delta & 1) == 0 && delta >= -(1ll << 20) && delta < (1ll << 20)) {
        if (bh_rv_emit_u32(dst, capacity, offset,
                           bh_rv_encode_b(rs1, rs2, 8, funct3)) != 0)
            return -1;
        return bh_rv_emit_jal_direct(dst, capacity, offset, from + 4, target, 0);
    }
    if (bh_rv_align8(dst, capacity, offset) != 0) return -1;
    if (bh_rv_emit_u32(dst, capacity, offset,
                       bh_rv_encode_b(rs1, rs2, 32, funct3)) != 0)
        return -1;
    if (bh_rv_emit_u32(dst, capacity, offset, BH_RV_NOP) != 0) return -1;
    return bh_rv_emit_abs_jump(dst, capacity, offset, target, 0);
}

static unsigned bh_rv_invert_branch(unsigned funct3) {
    switch (funct3) {
        case 0: return 1; /* beq  -> bne  */
        case 1: return 0; /* bne  -> beq  */
        case 4: return 5; /* blt  -> bge  */
        case 5: return 4; /* bge  -> blt  */
        case 6: return 7; /* bltu -> bgeu */
        case 7: return 6; /* bgeu -> bltu */
        default: return 0xFFFFFFFFu;
    }
}

int bh_arch_query(bh_arch_info_t *info) {
    if (info == NULL) return -1;
    info->patch_size = 6;
    info->relay_size = 24;
    info->max_distance = (size_t)0x000E0000u;
    return 0;
}

size_t bh_arch_patch_size(uintptr_t target, int thumb) {
    (void)thumb;
    if ((target & 3u) == 0) return 4;
    if ((target & 1u) == 0) return 6;
    return 0;
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

    {
        uint16_t hw1 = (uint16_t)((uint16_t)src_bytes[0] |
                                  ((uint16_t)src_bytes[1] << 8));
        if (hw1 == 0x8082u) {
            if (min_bytes > 2) return -1;
        } else if ((hw1 & 3u) == 3u) {
            if (bh_rv_rd32(src_bytes) == 0x00008067u && min_bytes > 4) return -1;
        }
    }

    while (source_offset < min_bytes) {
        uint32_t insn;
        unsigned size;
        uintptr_t address;

        if (source_offset + 4 > 32) return -1;
        insn = bh_rv_rd32(src_bytes + source_offset);
        address = src_address + source_offset;
        size = ((insn & 3u) == 3u) ? 4u : 2u;

        if (size == 2) {
            if ((insn & 0xE003u) == 0xA001u) { /* c.j */
                uint32_t imm = 0;
                int64_t displacement;
                imm |= ((insn >> 12) & 1u) << 11;
                imm |= ((insn >> 11) & 1u) << 4;
                imm |= ((insn >> 9) & 3u) << 8;
                imm |= ((insn >> 8) & 1u) << 10;
                imm |= ((insn >> 7) & 1u) << 6;
                imm |= ((insn >> 6) & 1u) << 7;
                imm |= ((insn >> 3) & 7u) << 1;
                imm |= ((insn >> 2) & 1u) << 5;
                displacement = bh_rv_sign_extend(imm, 12);
                if (bh_rv_emit_jal_direct((uint8_t *)dst, dst_capacity,
                                          &output_offset,
                                          (uintptr_t)dst + output_offset,
                                          (uintptr_t)((int64_t)address + displacement),
                                          0) != 0) {
                    if (bh_rv_emit_abs_jump((uint8_t *)dst, dst_capacity,
                                            &output_offset,
                                            (uintptr_t)((int64_t)address +
                                                        displacement),
                                            0) != 0)
                        return -1;
                }
            } else if ((insn & 0xE003u) == 0xC001u ||
                       (insn & 0xE003u) == 0xE001u) { /* c.beqz / c.bnez */
                uint32_t imm = 0;
                unsigned rs1 = 8u + ((insn >> 7) & 7u);
                unsigned funct3;
                int64_t displacement;
                imm |= ((insn >> 12) & 1u) << 8;
                imm |= ((insn >> 10) & 3u) << 3;
                imm |= ((insn >> 5) & 3u) << 6;
                imm |= ((insn >> 3) & 3u) << 1;
                imm |= ((insn >> 2) & 1u) << 5;
                displacement = bh_rv_sign_extend(imm, 9);
                funct3 = ((insn & 0xE003u) == 0xC001u) ? 1u : 0u;
                if (bh_rv_emit_cond_jump((uint8_t *)dst, dst_capacity,
                                         &output_offset, rs1, 0, funct3,
                                         (uintptr_t)((int64_t)address +
                                                     displacement)) != 0)
                    return -1;
            } else {
                if (bh_rv_emit_u16((uint8_t *)dst, dst_capacity, &output_offset,
                                   (uint16_t)insn) != 0)
                    return -1;
            }
        } else if ((insn & 0x7Fu) == 0x17u) { /* auipc */
            unsigned rd = (insn >> 7) & 0x1Fu;
            int64_t upper = bh_rv_sign_extend((insn >> 12) & 0xFFFFFu, 20) << 12;
            uint64_t value = (uint64_t)((int64_t)address + upper);
            if (rd == 0) {
                if (bh_rv_emit_u32((uint8_t *)dst, dst_capacity, &output_offset,
                                   BH_RV_NOP) != 0)
                    return -1;
            } else if (bh_rv_emit_materialize((uint8_t *)dst, dst_capacity,
                                              &output_offset, rd, value) != 0) {
                return -1;
            }
        } else if ((insn & 0x7Fu) == 0x6Fu) { /* jal */
            unsigned rd = (insn >> 7) & 0x1Fu;
            uint32_t raw = 0;
            int64_t displacement;
            raw |= ((insn >> 31) & 1u) << 20;
            raw |= ((insn >> 12) & 0xFFu) << 12;
            raw |= ((insn >> 20) & 1u) << 11;
            raw |= ((insn >> 21) & 0x3FFu) << 1;
            displacement = bh_rv_sign_extend(raw, 21);
            if (bh_rv_emit_jal_direct((uint8_t *)dst, dst_capacity,
                                      &output_offset,
                                      (uintptr_t)dst + output_offset,
                                      (uintptr_t)((int64_t)address + displacement),
                                      rd) != 0) {
                if (bh_rv_emit_abs_jump((uint8_t *)dst, dst_capacity,
                                        &output_offset,
                                        (uintptr_t)((int64_t)address +
                                                    displacement),
                                        rd) != 0)
                    return -1;
            }
        } else if ((insn & 0x7Fu) == 0x63u) { /* b<cond> */
            unsigned funct3 = (insn >> 12) & 7u;
            unsigned rs1 = (insn >> 15) & 0x1Fu;
            unsigned rs2 = (insn >> 20) & 0x1Fu;
            uint32_t raw = 0;
            int64_t displacement;
            unsigned inverted = bh_rv_invert_branch(funct3);
            if (inverted == 0xFFFFFFFFu) return -1;
            raw |= ((insn >> 31) & 1u) << 12;
            raw |= ((insn >> 7) & 1u) << 11;
            raw |= ((insn >> 25) & 0x3Fu) << 5;
            raw |= ((insn >> 8) & 0xFu) << 1;
            displacement = bh_rv_sign_extend(raw, 13);
            if (bh_rv_emit_cond_jump((uint8_t *)dst, dst_capacity, &output_offset,
                                     rs1, rs2, inverted,
                                     (uintptr_t)((int64_t)address +
                                                 displacement)) != 0)
                return -1;
        } else {
            if (bh_rv_emit_u32((uint8_t *)dst, dst_capacity, &output_offset,
                               insn) != 0)
                return -1;
        }

        source_offset += size;
    }

    if (bh_rv_emit_jal_direct((uint8_t *)dst, dst_capacity, &output_offset,
                              (uintptr_t)dst + output_offset,
                              src_address + source_offset, 0) != 0) {
        if (bh_rv_emit_abs_jump((uint8_t *)dst, dst_capacity, &output_offset,
                                src_address + source_offset, 0) != 0)
            return -1;
    }

    *out_len = output_offset;
    *copied = source_offset;
    return 0;
}

int bh_arch_emit_relay(void *relay, size_t capacity, const void *dest, int thumb) {
    size_t offset = 0;
    (void)thumb;
    if (relay == NULL || dest == NULL || capacity < 24) return -1;
    if (bh_rv_emit_abs_jump((uint8_t *)relay, capacity, &offset,
                            (uintptr_t)dest, 0) != 0)
        return -1;
    return 24;
}

int bh_arch_emit_patch(void *target, const void *dest, const void *relay,
                       int thumb, void *out, size_t capacity) {
    uintptr_t from = (uintptr_t)target;
    uintptr_t to = relay != NULL ? (uintptr_t)relay : (uintptr_t)dest;
    uintptr_t jal_address;
    int64_t delta;
    uint32_t encoded;
    uint8_t *bytes = (uint8_t *)out;
    size_t patch_size = bh_arch_patch_size(from, thumb);
    size_t prefix = patch_size - 4;
    (void)thumb;

    if (target == NULL || out == NULL || capacity < patch_size) return -1;
    if (patch_size != 4 && patch_size != 6) return -1;
    jal_address = from + prefix;
    delta = (int64_t)to - (int64_t)jal_address;
    if ((delta & 1) != 0 || delta < -(1ll << 20) || delta >= (1ll << 20)) return -1;
    encoded = bh_rv_encode_jal(0, (int32_t)delta);

    if (prefix == 2) {
        uint16_t c_nop = 0x0001;
        bytes[0] = (uint8_t)c_nop;
        bytes[1] = (uint8_t)(c_nop >> 8);
    }
    bytes[prefix + 0] = (uint8_t)encoded;
    bytes[prefix + 1] = (uint8_t)(encoded >> 8);
    bytes[prefix + 2] = (uint8_t)(encoded >> 16);
    bytes[prefix + 3] = (uint8_t)(encoded >> 24);
    return (int)patch_size;
}


size_t bh_arch_entry_prefix(const uint8_t *bytes, size_t size) {
    (void)bytes;
    (void)size;
    return 0;
}

#endif /* riscv64 */
