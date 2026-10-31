/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

volatile int bh_test_global = 7;

__attribute__((noinline)) int bh_test_add(int a, int b) {
    return a + b;
}

__attribute__((noinline)) int bh_test_sub(int a, int b) {
    return a - b;
}

__attribute__((noinline)) int bh_test_read_global(void) {
    return bh_test_global;
}

__attribute__((noinline)) int bh_test_many_args(int a, int b, int c, int d,
                                                int e, int f, int g, int h) {
    return a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6 + g * 7 + h * 8;
}
