/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#ifndef BAAADHOOK_BHINLINE_H
#define BAAADHOOK_BHINLINE_H

#include <stddef.h>
#include <stdint.h>

#ifndef BH_API
#  if defined(_WIN32)
#    if defined(BH_BUILDING_LIBRARY)
#      define BH_API __declspec(dllexport)
#    else
#      define BH_API __declspec(dllimport)
#    endif
#  elif defined(__GNUC__) || defined(__clang__)
#    define BH_API __attribute__((visibility("default")))
#  else
#    define BH_API
#  endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define BH_INLINE_VERSION_MAJOR 1
#define BH_INLINE_VERSION_MINOR 0
#define BH_INLINE_VERSION_PATCH 0

typedef enum bh_inline_status {
    BH_INLINE_OK = 0,
    BH_INLINE_ERROR_INVALID_ARGUMENT = -1,
    BH_INLINE_ERROR_NOT_HOOKED = -2,
    BH_INLINE_ERROR_ALREADY_HOOKED = -3,
    BH_INLINE_ERROR_NOT_EXECUTABLE = -4,
    BH_INLINE_ERROR_OUT_OF_RANGE = -5,
    BH_INLINE_ERROR_OUT_OF_MEMORY = -6,
    BH_INLINE_ERROR_UNSUPPORTED = -7,
    BH_INLINE_ERROR_MEMORY_PROTECTION = -8,
    BH_INLINE_ERROR_ARCHITECTURE = -9
} bh_inline_status_t;

BH_API int bh_inline_hook(void *target, void *replacement, void **original);

BH_API int bh_inline_unhook(void *target);

BH_API int bh_inline_unhook_all(void);

BH_API int bh_inline_is_hooked(const void *target);

BH_API void *bh_inline_get_original(const void *target);

BH_API const char *bh_inline_strerror(int status);

BH_API const char *bh_inline_arch_name(void);

#ifdef __cplusplus
}
#endif

#endif /* BAAADHOOK_BHINLINE_H */
