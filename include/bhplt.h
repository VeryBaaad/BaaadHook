/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#ifndef BAAADHOOK_BHPLT_H
#define BAAADHOOK_BHPLT_H

#include <stddef.h>

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

#define BH_PLT_VERSION_MAJOR 1
#define BH_PLT_VERSION_MINOR 0
#define BH_PLT_VERSION_PATCH 0

typedef enum bh_plt_status {
    BH_PLT_OK = 0,
    BH_PLT_ERROR_INVALID_ARGUMENT = -1,
    BH_PLT_ERROR_NOT_FOUND = -2,
    BH_PLT_ERROR_ALREADY_HOOKED = -3,
    BH_PLT_ERROR_OUT_OF_MEMORY = -4,
    BH_PLT_ERROR_MEMORY_PROTECTION = -5
} bh_plt_status_t;

BH_API int bh_plt_hook(const char *image_name, const char *symbol,
                       void *replacement, void **original);

BH_API int bh_plt_unhook(const char *image_name, const char *symbol,
                         void *replacement);

BH_API int bh_plt_unhook_all(void);

BH_API int bh_plt_is_hooked(const char *image_name, const char *symbol,
                            void *replacement);

BH_API const char *bh_plt_strerror(int status);

#ifdef __cplusplus
}
#endif

#endif /* BAAADHOOK_BHPLT_H */
