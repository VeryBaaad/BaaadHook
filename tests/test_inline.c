/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdint.h>

#include "bhinline.h"

extern volatile int bh_test_global;

extern int bh_test_add(int a, int b);
extern int bh_test_sub(int a, int b);
extern int bh_test_read_global(void);
extern int bh_test_many_args(int a, int b, int c, int d, int e, int f, int g,
                             int h);

static int (*bh_orig_add)(int, int);
static int (*bh_orig_sub)(int, int);
static int (*bh_orig_global)(void);
static int (*bh_orig_many)(int, int, int, int, int, int, int, int);

__attribute__((noinline)) static int bh_hook_add(int a, int b) {
    return bh_orig_add(a, b) + 100;
}

__attribute__((noinline)) static int bh_hook_sub(int a, int b) {
    return bh_orig_sub(a, b) * 2;
}

__attribute__((noinline)) static int bh_hook_global(void) {
    return bh_orig_global() + 1000;
}

__attribute__((noinline)) static int bh_hook_many(int a, int b, int c, int d,
                                                  int e, int f, int g, int h) {
    return bh_orig_many(a, b, c, d, e, f, g, h) + 1;
}

#define CHECK(condition)                                                                 \
    do {                                                                                 \
        if (!(condition)) {                                                              \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,          \
                    #condition);                                                         \
            return 1;                                                                    \
        }                                                                                \
    } while (0)

int main(void) {
    void *original = NULL;
    int result;

    printf("arch=%s\n", bh_inline_arch_name());
    CHECK(bh_test_add(2, 3) == 5);
    CHECK(bh_test_sub(9, 4) == 5);
    CHECK(bh_test_read_global() == 7);
    CHECK(bh_test_many_args(1, 2, 3, 4, 5, 6, 7, 8) ==
          1 + 4 + 9 + 16 + 25 + 36 + 49 + 64);

    result = bh_inline_hook((void *)bh_test_add, (void *)bh_hook_add, &original);
    CHECK(result == BH_INLINE_OK);
    CHECK(original != NULL);
    bh_orig_add = (int (*)(int, int))original;
    CHECK(bh_inline_is_hooked((void *)bh_test_add) == 1);
    CHECK(bh_inline_get_original((void *)bh_test_add) == original);
    CHECK(bh_test_add(2, 3) == 105);
    CHECK(bh_inline_hook((void *)bh_test_add, (void *)bh_hook_add, NULL) ==
          BH_INLINE_ERROR_ALREADY_HOOKED);
    CHECK(bh_inline_unhook((void *)bh_test_add) == BH_INLINE_OK);
    CHECK(bh_test_add(2, 3) == 5);
    CHECK(bh_inline_hook((void *)bh_test_add, (void *)bh_hook_add, &original) ==
          BH_INLINE_OK);
    bh_orig_add = (int (*)(int, int))original;
    CHECK(bh_test_add(4, 5) == 109);
    CHECK(bh_inline_unhook_all() >= 1);
    CHECK(bh_test_add(1, 1) == 2);

    original = NULL;
    result = bh_inline_hook((void *)bh_test_read_global, (void *)bh_hook_global,
                            &original);
    CHECK(result == BH_INLINE_OK);
    bh_orig_global = (int (*)(void))original;
    CHECK(bh_test_read_global() == 1007);

    original = NULL;
    result = bh_inline_hook((void *)bh_test_sub, (void *)bh_hook_sub, &original);
    CHECK(result == BH_INLINE_OK);
    bh_orig_sub = (int (*)(int, int))original;
    CHECK(bh_test_sub(9, 4) == 10);

    original = NULL;
    result = bh_inline_hook((void *)bh_test_many_args, (void *)bh_hook_many,
                            &original);
    CHECK(result == BH_INLINE_OK);
    bh_orig_many = (int (*)(int, int, int, int, int, int, int, int))original;
    CHECK(bh_test_many_args(1, 2, 3, 4, 5, 6, 7, 8) ==
          1 + 4 + 9 + 16 + 25 + 36 + 49 + 64 + 1);

    CHECK(bh_inline_unhook_all() == 3);
    CHECK(bh_test_read_global() == 7);
    CHECK(bh_test_sub(9, 4) == 5);

    puts("inline tests passed");
    return 0;
}
