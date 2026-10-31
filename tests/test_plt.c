/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE 1
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bhplt.h"

static int (*bh_real_puts)(const char *);
static int bh_puts_calls = 0;

static int bh_fake_puts(const char *text) {
    bh_puts_calls++;
    if (bh_real_puts == NULL) {
        return 0;
    }
    return bh_real_puts(text);
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
    int count;

    bh_real_puts = puts;
    puts("before plt hook");

    count = bh_plt_hook(NULL, "puts", (void *)bh_fake_puts, &original);
    if (count < 0) {
        fprintf(stderr, "bh_plt_hook failed: %s (%d)\n", bh_plt_strerror(count),
                count);
        return 1;
    }
    bh_real_puts = (int (*)(const char *))(original != NULL ? original : (void *)puts);
    CHECK(count >= 1);
    CHECK(bh_plt_is_hooked(NULL, "puts", (void *)bh_fake_puts) == 1);
    CHECK(puts("through plt hook") >= 0);
    CHECK(bh_puts_calls == 1);

    count = bh_plt_unhook(NULL, "puts", (void *)bh_fake_puts);
    CHECK(count >= 1);
    CHECK(bh_puts_calls == 1);
    CHECK(puts("after plt unhook") >= 0);
    CHECK(bh_puts_calls == 1);
    CHECK(bh_plt_is_hooked(NULL, "puts", (void *)bh_fake_puts) == 0);

    {
        char executable[4096];
        ssize_t length = readlink("/proc/self/exe", executable,
                                  sizeof(executable) - 1);
        if (length > 0) {
            executable[length] = '\0';
            original = NULL;
            count = bh_plt_hook(executable, "puts", (void *)bh_fake_puts,
                                &original);
            CHECK(count >= 1);
            if (original != NULL) {
                bh_real_puts = (int (*)(const char *))original;
            }
            CHECK(puts("image filtered hook") >= 0);
            CHECK(bh_puts_calls == 2);
            CHECK(bh_plt_unhook(executable, "puts", (void *)bh_fake_puts) >= 1);
        }
    }

    puts("plt tests passed");
    return 0;
}
