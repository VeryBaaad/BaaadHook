/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE 1

#include "bh_internal.h"

#if defined(__x86_64__) || defined(__i386__)

#include <limits.h>
#include <stdint.h>
#include <string.h>

#if defined(__x86_64__)
#  define BH_X86_64 1
#else
#  define BH_X86_64 0
#endif

#define BH_X86_MAX_INSN 15u
#define BH_X86_SOURCE_COPY 32u

enum {
    BH_X86_KIND_NORMAL = 0,
    BH_X86_KIND_CALL,
    BH_X86_KIND_JMP,
    BH_X86_KIND_JCC,
    BH_X86_KIND_LOOP,
    BH_X86_KIND_XBEGIN,
    BH_X86_KIND_RET
};

typedef struct bh_x86_insn {
    unsigned length;
    unsigned char modrm;
    unsigned char opcode;
    unsigned char opcode2;
    unsigned char kind;
    unsigned char condition;
    unsigned char rip_relative;
    unsigned char disp_offset;
    unsigned char disp_size;
    unsigned char imm_size;
} bh_x86_insn_t;

static uint32_t bh_x86_rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int64_t bh_x86_sign_extend(uint64_t value, unsigned bits) {
    uint64_t sign = 1ull << (bits - 1u);
    return (int64_t)((value ^ sign) - sign);
}

static int bh_x86_fits_i32(int64_t value) {
    return value >= (int64_t)INT32_MIN && value <= (int64_t)INT32_MAX;
}

static int bh_x86_is_legacy_prefix(uint8_t byte) {
    switch (byte) {
        case 0xF0:
        case 0xF2:
        case 0xF3:
        case 0x2E:
        case 0x36:
        case 0x3E:
        case 0x26:
        case 0x64:
        case 0x65:
        case 0x66:
        case 0x67:
            return 1;
        default:
            return 0;
    }
}

static int bh_x86_decode(const uint8_t *code, int is64, bh_x86_insn_t *insn) {
    unsigned pos = 0;
    unsigned i;
    int operand16 = 0;
    int address16 = 0;
    int address_bits = is64 ? 64 : 32;
    int rex_w = 0;
    int rex_present = 0;
    int has_modrm = 0;
    int imm_mode = 0;
    int map = 0;
    uint8_t opcode = 0;
    uint8_t opcode2 = 0;
    unsigned start;

    memset(insn, 0, sizeof(*insn));

    for (i = 0; i < BH_X86_MAX_INSN; i++) {
        uint8_t byte = code[pos];
        if (byte == 0x66) {
            operand16 = 1;
            pos++;
            continue;
        }
        if (byte == 0x67) {
            address16 = 1;
            if (is64) {
                address_bits = 32;
            } else {
                address_bits = 16;
            }
            pos++;
            continue;
        }
        if (bh_x86_is_legacy_prefix(byte)) {
            pos++;
            continue;
        }
        if (is64 && byte >= 0x40 && byte <= 0x4F) {
            rex_present = 1;
            rex_w = (byte & 8) != 0;
            pos++;
            continue;
        }
        break;
    }

    if (pos >= BH_X86_MAX_INSN) {
        return -1;
    }

    if (rex_w) {
        operand16 = 0;
    }

    opcode = code[pos++];

    if (is64 && (opcode == 0x62 || opcode == 0xD5)) {
        return -1;
    }

    if (opcode == 0x0F) {
        uint8_t next;
        if (pos >= BH_X86_MAX_INSN) {
            return -1;
        }
        next = code[pos++];
        if (next == 0x38) {
            if (pos >= BH_X86_MAX_INSN) return -1;
            opcode2 = code[pos++];
            map = 2;
            has_modrm = 1;
        } else if (next == 0x3A) {
            if (pos >= BH_X86_MAX_INSN) return -1;
            opcode2 = code[pos++];
            map = 3;
            has_modrm = 1;
            imm_mode = 1;
        } else {
            opcode2 = next;
            map = 1;
            if ((opcode2 >= 0x80 && opcode2 <= 0x8F)) {
                has_modrm = 0;
                imm_mode = 4;
                insn->kind = BH_X86_KIND_JCC;
                insn->condition = opcode2 & 0x0F;
            } else {
                switch (opcode2) {
                    case 0x05: case 0x06: case 0x07: case 0x08: case 0x09:
                    case 0x0B: case 0x0E: case 0x30: case 0x31: case 0x32:
                    case 0x33: case 0x34: case 0x35: case 0x37: case 0x77:
                    case 0xA2: case 0xAA:
                        has_modrm = 0;
                        break;
                    default:
                        has_modrm = 1;
                        break;
                }
                switch (opcode2) {
                    case 0x0F:
                        imm_mode = 1;
                        break;
                    case 0x70:
                    case 0x71:
                    case 0x72:
                    case 0x73:
                    case 0xA4:
                    case 0xAC:
                    case 0xBA:
                    case 0xC2:
                    case 0xC4:
                    case 0xC5:
                    case 0xC6:
                        imm_mode = 1;
                        break;
                    default:
                        break;
                }
            }
        }
    } else if (opcode == 0xC5 || opcode == 0xC4 || opcode == 0x62) {
        int is_vex = 0;
        int vex_map = 1;
        unsigned prefix_size = 0;

        if (opcode == 0xC5) {
            if (is64 || (pos < BH_X86_MAX_INSN && (code[pos] & 0xC0) == 0xC0)) {
                is_vex = 1;
                vex_map = 1;
                prefix_size = 1;
            }
        } else if (opcode == 0xC4) {
            if (is64 || (pos < BH_X86_MAX_INSN && (code[pos] & 0xC0) == 0xC0)) {
                is_vex = 1;
                if (pos >= BH_X86_MAX_INSN) return -1;
                vex_map = code[pos] & 0x1F;
                prefix_size = 2;
            }
        } else {
            if (is64 || (pos < BH_X86_MAX_INSN && (code[pos] & 0x0C) == 0)) {
                is_vex = 1;
                if (pos >= BH_X86_MAX_INSN) return -1;
                vex_map = code[pos] & 0x03;
                prefix_size = 3;
            }
        }

        if (is_vex) {
            if (pos + prefix_size >= BH_X86_MAX_INSN) {
                return -1;
            }
            pos += prefix_size;
            opcode2 = code[pos++];
            map = vex_map;
            if (map == 0 || map > 3) {
                return -1;
            }
            if (map == 1 && opcode2 == 0x77) {
                has_modrm = 0;
            } else {
                has_modrm = 1;
                if (map == 3) {
                    imm_mode = 1;
                } else if (map == 1) {
                    switch (opcode2) {
                        case 0x70:
                        case 0x71:
                        case 0x72:
                        case 0x73:
                        case 0xC2:
                        case 0xC4:
                        case 0xC5:
                        case 0xC6:
                            imm_mode = 1;
                            break;
                        default:
                            break;
                    }
                }
            }
        } else {
            has_modrm = 1;
            if (opcode == 0x62) {
                imm_mode = 0;
            }
        }
    } else {
        map = 0;
        switch (opcode) {
            case 0x00: case 0x01: case 0x02: case 0x03:
            case 0x08: case 0x09: case 0x0A: case 0x0B:
            case 0x10: case 0x11: case 0x12: case 0x13:
            case 0x18: case 0x19: case 0x1A: case 0x1B:
            case 0x20: case 0x21: case 0x22: case 0x23:
            case 0x28: case 0x29: case 0x2A: case 0x2B:
            case 0x30: case 0x31: case 0x32: case 0x33:
            case 0x38: case 0x39: case 0x3A: case 0x3B:
            case 0x62:
            case 0x63:
            case 0x84: case 0x85: case 0x86: case 0x87:
            case 0x88: case 0x89: case 0x8A: case 0x8B:
            case 0x8C: case 0x8D: case 0x8E: case 0x8F:
            case 0xC0: case 0xC1:
            case 0xD0: case 0xD1: case 0xD2: case 0xD3:
            case 0xD8: case 0xD9: case 0xDA: case 0xDB:
            case 0xDC: case 0xDD: case 0xDE: case 0xDF:
            case 0xF6: case 0xF7:
            case 0xFE: case 0xFF:
                has_modrm = 1;
                break;

            case 0x04: case 0x0C: case 0x14: case 0x1C:
            case 0x24: case 0x2C: case 0x34: case 0x3C:
            case 0x6A:
            case 0xA8:
            case 0xB0: case 0xB1: case 0xB2: case 0xB3:
            case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            case 0xC6:
            case 0xCD:
            case 0xD4: case 0xD5:
            case 0xE4: case 0xE5: case 0xE6: case 0xE7:
                has_modrm = (opcode == 0x6B || opcode == 0xC6);
                imm_mode = 1;
                break;

            case 0x05: case 0x0D: case 0x15: case 0x1D:
            case 0x25: case 0x2D: case 0x35: case 0x3D:
            case 0x68:
            case 0x69:
            case 0x81:
            case 0xA9:
            case 0xC7:
                has_modrm = (opcode == 0x69 || opcode == 0x81 || opcode == 0xC7);
                imm_mode = operand16 ? 2 : 4;
                break;

            case 0x6B:
                has_modrm = 1;
                imm_mode = 1;
                break;

            case 0x80:
            case 0x82:
            case 0x83:
                has_modrm = 1;
                imm_mode = 1;
                break;

            case 0x70: case 0x71: case 0x72: case 0x73:
            case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x78: case 0x79: case 0x7A: case 0x7B:
            case 0x7C: case 0x7D: case 0x7E: case 0x7F:
                imm_mode = 1;
                insn->kind = BH_X86_KIND_JCC;
                insn->condition = opcode & 0x0F;
                break;

            case 0xE0: case 0xE1: case 0xE2: case 0xE3:
                imm_mode = 1;
                insn->kind = BH_X86_KIND_LOOP;
                break;

            case 0xE8:
                imm_mode = 4;
                insn->kind = BH_X86_KIND_CALL;
                break;
            case 0xE9:
                imm_mode = 4;
                insn->kind = BH_X86_KIND_JMP;
                break;
            case 0xEB:
                imm_mode = 1;
                insn->kind = BH_X86_KIND_JMP;
                break;

            case 0x9A:
            case 0xEA:
                imm_mode = operand16 ? 5 : 6;
                break;

            case 0xA0: case 0xA1: case 0xA2: case 0xA3:
                if (address_bits == 16) imm_mode = 2;
                else if (address_bits == 32) imm_mode = 4;
                else imm_mode = 8;
                break;

            case 0xA4: case 0xA5: case 0xA6: case 0xA7:
            case 0xAA: case 0xAB: case 0xAC: case 0xAD:
            case 0xAE: case 0xAF:
            case 0x90: case 0x91: case 0x92: case 0x93:
            case 0x94: case 0x95: case 0x96: case 0x97:
            case 0x98: case 0x99:
            case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F:
            case 0x50: case 0x51: case 0x52: case 0x53:
            case 0x54: case 0x55: case 0x56: case 0x57:
            case 0x58: case 0x59: case 0x5A: case 0x5B:
            case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            case 0x60: case 0x61:
            case 0x6C: case 0x6D: case 0x6E: case 0x6F:
            case 0xC9:
            case 0xCC: case 0xCE: case 0xCF:
            case 0xD6: case 0xD7:
            case 0xEC: case 0xED: case 0xEE: case 0xEF:
            case 0xF1: case 0xF4: case 0xF5:
            case 0xF8: case 0xF9: case 0xFA: case 0xFB:
            case 0xFC: case 0xFD:
                break;

            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                imm_mode = operand16 ? 2 : (rex_w ? 8 : 4);
                break;

            case 0xC3:
            case 0xCB:
                insn->kind = BH_X86_KIND_RET;
                break;

            case 0xC2:
            case 0xCA:
                imm_mode = 2;
                insn->kind = BH_X86_KIND_RET;
                break;

            case 0xC8:
                imm_mode = 3;
                break;

            case 0x40: case 0x41: case 0x42: case 0x43:
            case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A: case 0x4B:
            case 0x4C: case 0x4D: case 0x4E: case 0x4F:
                break;

            case 0x06: case 0x07: case 0x0E:
            case 0x16: case 0x17: case 0x1E: case 0x1F:
            case 0x27: case 0x2F: case 0x37: case 0x3F:
                break;

            default:
                return -1;
        }
    }

    (void)rex_present;
    (void)address16;

    if (has_modrm) {
        unsigned mod;
        unsigned rm;
        unsigned disp_size = 0;
        unsigned disp_offset;
        uint8_t modrm;

        if (pos >= BH_X86_MAX_INSN) return -1;
        modrm = code[pos++];
        insn->modrm = modrm;
        mod = modrm >> 6;
        rm = modrm & 7;

        if (address_bits == 16) {
            if (mod == 0 && rm == 6) disp_size = 2;
            else if (mod == 1) disp_size = 1;
            else if (mod == 2) disp_size = 2;
        } else {
            if (mod != 3 && rm == 4) {
                uint8_t sib;
                if (pos >= BH_X86_MAX_INSN) return -1;
                sib = code[pos++];
                if (mod == 0 && (sib & 7) == 5) disp_size = 4;
            }
            if (mod == 0) {
                if (rm == 5) disp_size = 4;
            } else if (mod == 1) {
                disp_size = 1;
            } else if (mod == 2) {
                disp_size = 4;
            }
            if (is64 && address_bits == 64 && mod == 0 && rm == 5) {
                insn->rip_relative = 1;
            }
        }

        if (disp_size != 0) {
            disp_offset = pos;
            if (disp_offset + disp_size > BH_X86_MAX_INSN) return -1;
            insn->disp_offset = (unsigned char)disp_offset;
            insn->disp_size = (unsigned char)disp_size;
            pos += disp_size;
        }

        if (opcode == 0xF6 && (modrm >> 3) <= 1) {
            imm_mode = 1;
        } else if (opcode == 0xF7 && (modrm >> 3) <= 1) {
            imm_mode = operand16 ? 2 : 4;
        } else if (opcode == 0xC7 && modrm == 0xF8 && mod == 3) {
            imm_mode = 4;
            insn->kind = BH_X86_KIND_XBEGIN;
        }
    }

    if (imm_mode != 0) {
        if (pos + (unsigned)imm_mode > BH_X86_MAX_INSN) return -1;
        pos += (unsigned)imm_mode;
    }

    if (pos == 0 || pos > BH_X86_MAX_INSN) {
        return -1;
    }

    insn->length = pos;
    insn->imm_size = (unsigned char)imm_mode;
    insn->opcode = opcode;
    insn->opcode2 = opcode2;
    (void)map;
    (void)start;
    return 0;
}

#if !BH_X86_64
static int bh_x86_get_pc_thunk_register(uintptr_t target, unsigned *reg) {
    static const uint8_t kThunkPrefix[3] = {0x8Bu, 0x04u, 0x24u};
    static const unsigned kRegisters[6] = {0, 3, 1, 2, 6, 7};
    static const uint8_t kModRm[6] = {0x04u, 0x1Cu, 0x0Cu,
                                      0x14u, 0x34u, 0x3Cu};
    uint8_t code[8];
    size_t offset = 0;
    size_t i;

    if (bh__copy_code(code, (const void *)target, sizeof(code)) != 0) {
        return 0;
    }
    if (code[0] == 0xF3 && code[1] == 0x0F && code[2] == 0x1E &&
        code[3] == 0xFA) {
        offset = 4;
    }
    if (offset + 4 > sizeof(code)) return 0;
    for (i = 0; i < 6; i++) {
        if (code[offset + 0] == kThunkPrefix[0] &&
            code[offset + 1] == kModRm[i] &&
            code[offset + 2] == kThunkPrefix[2] &&
            code[offset + 3] == 0xC3) {
            *reg = kRegisters[i];
            return 1;
        }
    }
    (void)kThunkPrefix;
    return 0;
}
#endif

static int bh_x86_scan(const uint8_t *src, size_t minimum, size_t *copied) {
    size_t offset = 0;
    while (offset < minimum) {
        bh_x86_insn_t insn;
        if (offset + BH_X86_MAX_INSN > BH_X86_SOURCE_COPY) {
            return -1;
        }
        if (bh_x86_decode(src + offset, BH_X86_64, &insn) != 0) {
            return -1;
        }
        if ((insn.kind == BH_X86_KIND_RET || insn.kind == BH_X86_KIND_JMP) &&
            offset + insn.length < minimum) {
            return -1;
        }
        offset += insn.length;
    }
    *copied = offset;
    return 0;
}

static int bh_x86_emit_bytes(uint8_t *dst, size_t capacity, size_t *offset,
                             const void *bytes, size_t size) {
    if (*offset + size > capacity) {
        return -1;
    }
    memcpy(dst + *offset, bytes, size);
    *offset += size;
    return 0;
}

static int bh_x86_emit_u8(uint8_t *dst, size_t capacity, size_t *offset,
                          uint8_t value) {
    return bh_x86_emit_bytes(dst, capacity, offset, &value, 1);
}

static int bh_x86_emit_u32(uint8_t *dst, size_t capacity, size_t *offset,
                           uint32_t value) {
    uint8_t bytes[4];
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
    return bh_x86_emit_bytes(dst, capacity, offset, bytes, sizeof(bytes));
}

#if BH_X86_64
static int bh_x86_emit_u64(uint8_t *dst, size_t capacity, size_t *offset,
                           uint64_t value) {
    uint8_t bytes[8];
    int i;
    for (i = 0; i < 8; i++) {
        bytes[i] = (uint8_t)(value >> (i * 8));
    }
    return bh_x86_emit_bytes(dst, capacity, offset, bytes, sizeof(bytes));
}
#endif

static int bh_x86_emit_jmp_relative(uint8_t *dst, size_t capacity, size_t *offset,
                                    uintptr_t from, uintptr_t target) {
    int64_t displacement = (int64_t)target - (int64_t)(from + 5);
    if (!bh_x86_fits_i32(displacement)) {
        return -1;
    }
    if (bh_x86_emit_u8(dst, capacity, offset, 0xE9) != 0) return -1;
    return bh_x86_emit_u32(dst, capacity, offset, (uint32_t)(int32_t)displacement);
}

static int bh_x86_emit_abs_jmp(uint8_t *dst, size_t capacity, size_t *offset,
                               uintptr_t target) {
#if BH_X86_64
    uint8_t head[6] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    if (bh_x86_emit_bytes(dst, capacity, offset, head, sizeof(head)) != 0) return -1;
    return bh_x86_emit_u64(dst, capacity, offset, (uint64_t)target);
#else
    uint32_t literal = (uint32_t)((uintptr_t)dst + *offset + 6u);
    if (bh_x86_emit_u8(dst, capacity, offset, 0xFF) != 0) return -1;
    if (bh_x86_emit_u8(dst, capacity, offset, 0x25) != 0) return -1;
    if (bh_x86_emit_u32(dst, capacity, offset, literal) != 0) return -1;
    return bh_x86_emit_u32(dst, capacity, offset, (uint32_t)target);
#endif
}

static int bh_x86_emit_abs_call(uint8_t *dst, size_t capacity, size_t *offset,
                                uintptr_t target) {
#if BH_X86_64
    uint8_t head[6] = {0xFF, 0x15, 0x02, 0x00, 0x00, 0x00};
    if (bh_x86_emit_bytes(dst, capacity, offset, head, sizeof(head)) != 0) return -1;
    if (bh_x86_emit_u8(dst, capacity, offset, 0xEB) != 0) return -1;
    if (bh_x86_emit_u8(dst, capacity, offset, 0x08) != 0) return -1;
    return bh_x86_emit_u64(dst, capacity, offset, (uint64_t)target);
#else
    uint32_t literal = (uint32_t)((uintptr_t)dst + *offset + 8u);
    if (bh_x86_emit_u8(dst, capacity, offset, 0xFF) != 0) return -1;
    if (bh_x86_emit_u8(dst, capacity, offset, 0x15) != 0) return -1;
    if (bh_x86_emit_u32(dst, capacity, offset, literal) != 0) return -1;
    if (bh_x86_emit_u8(dst, capacity, offset, 0xEB) != 0) return -1;
    if (bh_x86_emit_u8(dst, capacity, offset, 0x04) != 0) return -1;
    return bh_x86_emit_u32(dst, capacity, offset, (uint32_t)target);
#endif
}

static size_t bh_x86_abs_jmp_size(void) {
#if BH_X86_64
    return 14;
#else
    return 10;
#endif
}

static int bh_x86_emit_jcc_relative(uint8_t *dst, size_t capacity, size_t *offset,
                                    uintptr_t from, uintptr_t target,
                                    unsigned condition) {
    int64_t displacement = (int64_t)target - (int64_t)(from + 6);
    if (!bh_x86_fits_i32(displacement)) {
        return -1;
    }
    if (bh_x86_emit_u8(dst, capacity, offset, 0x0F) != 0) return -1;
    if (bh_x86_emit_u8(dst, capacity, offset,
                       (uint8_t)(0x80 | (condition & 0x0F))) != 0)
        return -1;
    return bh_x86_emit_u32(dst, capacity, offset, (uint32_t)(int32_t)displacement);
}

static int bh_x86_emit_jcc_absolute(uint8_t *dst, size_t capacity, size_t *offset,
                                    uintptr_t target, unsigned condition) {
    size_t abs_size = bh_x86_abs_jmp_size();
    if (bh_x86_emit_u8(dst, capacity, offset,
                       (uint8_t)(0x70 | ((condition ^ 1u) & 0x0F))) != 0)
        return -1;
    if (bh_x86_emit_u8(dst, capacity, offset, (uint8_t)abs_size) != 0) return -1;
    return bh_x86_emit_abs_jmp(dst, capacity, offset, target);
}

int bh_arch_query(bh_arch_info_t *info) {
    if (info == NULL) return -1;
    info->patch_size = 5;
    info->relay_size = 16;
    info->max_distance = (size_t)0x40000000u;
    return 0;
}

size_t bh_arch_patch_size(uintptr_t target, int thumb) {
    (void)target;
    (void)thumb;
    return 5;
}

int bh_arch_relocate(const uint8_t *src_bytes, uintptr_t src_address,
                     size_t min_bytes, int thumb, void *dst, size_t dst_capacity,
                     size_t *out_len, size_t *copied) {
    size_t total = 0;
    size_t source_offset = 0;
    size_t output_offset = 0;
    (void)thumb;

    if (src_bytes == NULL || dst == NULL || out_len == NULL || copied == NULL ||
        min_bytes == 0) {
        return -1;
    }
    if (bh_x86_scan(src_bytes, min_bytes, &total) != 0) {
        return -1;
    }

    while (source_offset < total) {
        bh_x86_insn_t insn;
        uintptr_t instruction_address = src_address + source_offset;
        size_t next_source;
        uintptr_t next_address;

        if (bh_x86_decode(src_bytes + source_offset, BH_X86_64, &insn) != 0) {
            return -1;
        }
        next_source = source_offset + insn.length;
        next_address = instruction_address + insn.length;

        if (insn.kind != BH_X86_KIND_NORMAL) {
            int64_t relative = 0;
            uintptr_t target;
            if (insn.kind == BH_X86_KIND_LOOP) {
                return -1;
            }
            if (insn.imm_size == 1) {
                relative = bh_x86_sign_extend(src_bytes[source_offset + insn.length - 1], 8);
            } else {
                unsigned rel_offset = insn.length - 4u;
                relative = bh_x86_sign_extend(
                    bh_x86_rd32(src_bytes + source_offset + rel_offset), 32);
            }
            target = (uintptr_t)((int64_t)next_address + relative);

            if (target >= src_address && target < src_address + total) {
                return -1;
            }

            if (insn.kind == BH_X86_KIND_CALL) {
#if !BH_X86_64
                unsigned thunk_register = 0;
                if (bh_x86_get_pc_thunk_register(target, &thunk_register)) {
                    uint32_t return_address =
                        (uint32_t)(src_address + source_offset + insn.length);
                    if (bh_x86_emit_u8(dst, dst_capacity, &output_offset,
                                       (uint8_t)(0xB8u + thunk_register)) != 0)
                        return -1;
                    if (bh_x86_emit_u32(dst, dst_capacity, &output_offset,
                                        return_address) != 0)
                        return -1;
                } else
#endif
                {
                    int64_t displacement =
                        (int64_t)target -
                        (int64_t)((uintptr_t)dst + output_offset + 5);
                    if (bh_x86_fits_i32(displacement)) {
                        if (bh_x86_emit_u8(dst, dst_capacity, &output_offset,
                                           0xE8) != 0)
                            return -1;
                        if (bh_x86_emit_u32(dst, dst_capacity, &output_offset,
                                            (uint32_t)(int32_t)displacement) != 0)
                            return -1;
                    } else if (bh_x86_emit_abs_call(dst, dst_capacity,
                                                    &output_offset, target) != 0) {
                        return -1;
                    }
                }
            } else if (insn.kind == BH_X86_KIND_JMP) {
                if (bh_x86_emit_jmp_relative(dst, dst_capacity, &output_offset,
                                             (uintptr_t)dst + output_offset,
                                             target) != 0) {
                    if (bh_x86_emit_abs_jmp(dst, dst_capacity, &output_offset,
                                            target) != 0) {
                        return -1;
                    }
                }
            } else if (insn.kind == BH_X86_KIND_JCC) {
                if (bh_x86_emit_jcc_relative(dst, dst_capacity, &output_offset,
                                             (uintptr_t)dst + output_offset,
                                             target, insn.condition) != 0) {
                    if (bh_x86_emit_jcc_absolute(dst, dst_capacity, &output_offset,
                                                 target, insn.condition) != 0) {
                        return -1;
                    }
                }
            } else if (insn.kind == BH_X86_KIND_XBEGIN) {
                int64_t disp =
                    (int64_t)target - (int64_t)((uintptr_t)dst + output_offset + 6);
                if (!bh_x86_fits_i32(disp)) return -1;
                if (bh_x86_emit_bytes(dst, dst_capacity, &output_offset,
                                      src_bytes + source_offset, 2) != 0)
                    return -1;
                if (bh_x86_emit_u32(dst, dst_capacity, &output_offset,
                                    (uint32_t)(int32_t)disp) != 0)
                    return -1;
            } else {
                return -1;
            }
        } else {
            unsigned char local[BH_X86_MAX_INSN];
            int64_t new_disp = 0;
            if (insn.length > BH_X86_SOURCE_COPY - source_offset) {
                return -1;
            }
            memcpy(local, src_bytes + source_offset, insn.length);
            if (insn.rip_relative) {
                int64_t disp = (int64_t)(int32_t)bh_x86_rd32(
                    src_bytes + source_offset + insn.disp_offset);
                uintptr_t target = (uintptr_t)((int64_t)next_address + disp);
                new_disp = (int64_t)target -
                           (int64_t)((uintptr_t)dst + output_offset + insn.length);
                if (!bh_x86_fits_i32(new_disp)) {
                    return -1;
                }
                local[insn.disp_offset + 0] = (uint8_t)(new_disp);
                local[insn.disp_offset + 1] = (uint8_t)(new_disp >> 8);
                local[insn.disp_offset + 2] = (uint8_t)(new_disp >> 16);
                local[insn.disp_offset + 3] = (uint8_t)(new_disp >> 24);
            }
            if (bh_x86_emit_bytes(dst, dst_capacity, &output_offset, local,
                                  insn.length) != 0) {
                return -1;
            }
        }

        source_offset = next_source;
    }

    if (bh_x86_emit_jmp_relative(dst, dst_capacity, &output_offset,
                                 (uintptr_t)dst + output_offset,
                                 src_address + total) != 0) {
        if (bh_x86_emit_abs_jmp(dst, dst_capacity, &output_offset,
                                src_address + total) != 0) {
            return -1;
        }
    }

    *out_len = output_offset;
    *copied = total;
    return 0;
}

int bh_arch_emit_relay(void *relay, size_t capacity, const void *dest, int thumb) {
    uint8_t buffer[16];
    int64_t displacement;
    (void)thumb;

    if (relay == NULL || dest == NULL || capacity < 16) {
        return -1;
    }
    memset(buffer, 0x90, sizeof(buffer));
    displacement = (int64_t)(uintptr_t)dest - (int64_t)((uintptr_t)relay + 5);
    if (bh_x86_fits_i32(displacement)) {
        buffer[0] = 0xE9;
        buffer[1] = (uint8_t)displacement;
        buffer[2] = (uint8_t)(displacement >> 8);
        buffer[3] = (uint8_t)(displacement >> 16);
        buffer[4] = (uint8_t)(displacement >> 24);
    } else {
#if BH_X86_64
        buffer[0] = 0xFF;
        buffer[1] = 0x25;
        buffer[2] = buffer[3] = buffer[4] = buffer[5] = 0;
        {
            uint64_t value = (uint64_t)(uintptr_t)dest;
            int i;
            for (i = 0; i < 8; i++) buffer[6 + i] = (uint8_t)(value >> (i * 8));
        }
#else
        buffer[0] = 0xFF;
        buffer[1] = 0x25;
        {
            uint32_t literal =
                (uint32_t)(uintptr_t)relay + 6u;
            uint32_t value = (uint32_t)(uintptr_t)dest;
            buffer[2] = (uint8_t)literal;
            buffer[3] = (uint8_t)(literal >> 8);
            buffer[4] = (uint8_t)(literal >> 16);
            buffer[5] = (uint8_t)(literal >> 24);
            buffer[6] = (uint8_t)value;
            buffer[7] = (uint8_t)(value >> 8);
            buffer[8] = (uint8_t)(value >> 16);
            buffer[9] = (uint8_t)(value >> 24);
        }
#endif
    }
    memcpy(relay, buffer, sizeof(buffer));
    return 16;
}

int bh_arch_emit_patch(void *target, const void *dest, const void *relay,
                       int thumb, void *out, size_t capacity) {
    uint8_t *bytes = (uint8_t *)out;
    uintptr_t from = (uintptr_t)target;
    uintptr_t to = relay != NULL ? (uintptr_t)relay : (uintptr_t)dest;
    int64_t displacement = (int64_t)to - (int64_t)(from + 5);
    (void)thumb;

    if (target == NULL || out == NULL || capacity < 5) {
        return -1;
    }
    if (!bh_x86_fits_i32(displacement)) {
        return -1;
    }
    bytes[0] = 0xE9;
    bytes[1] = (uint8_t)displacement;
    bytes[2] = (uint8_t)(displacement >> 8);
    bytes[3] = (uint8_t)(displacement >> 16);
    bytes[4] = (uint8_t)(displacement >> 24);
    return 5;
}


size_t bh_arch_entry_prefix(const uint8_t *bytes, size_t size) {
    (void)bytes;
    (void)size;
    return 0;
}

#endif /* x86 */
