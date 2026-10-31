/**
 * Copyright (c) 2026 VeryBaaad <verybaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE 1

#include <pthread.h>
#include <stdio.h>

#include "bhinline.h"
#include "bhplt.h"

#define BH_INLINE_CYCLES 1000
#define BH_PLT_CYCLES 300

static int (*bh_real_puts)(const char *);

__attribute__((noinline)) static int bh_concurrent_target(int a, int b) {
    return a + b;
}

__attribute__((noinline)) static int bh_concurrent_replacement(int a, int b) {
    return a + b + 1;
}

static int bh_concurrent_fake_puts(const char *text) {
    return bh_real_puts != NULL ? bh_real_puts(text) : 0;
}

static void *bh_inline_worker(void *argument) {
    int i;
    (void)argument;
    for (i = 0; i < BH_INLINE_CYCLES; i++) {
        void *original = NULL;
        int status = bh_inline_hook((void *)bh_concurrent_target,
                                    (void *)bh_concurrent_replacement,
                                    &original);
        if (status != BH_INLINE_OK &&
            status != BH_INLINE_ERROR_ALREADY_HOOKED) {
            fprintf(stderr, "concurrent inline hook failed: %s (%d)\n",
                    bh_inline_strerror(status), status);
            return (void *)1;
        }
        (void)bh_inline_unhook((void *)bh_concurrent_target);
    }
    return NULL;
}

static void *bh_plt_worker(void *argument) {
    int i;
    (void)argument;
    for (i = 0; i < BH_PLT_CYCLES; i++) {
        void *original = NULL;
        int status = bh_plt_hook(NULL, "puts", (void *)bh_concurrent_fake_puts,
                                 &original);
        if (status < 0) {
            fprintf(stderr, "concurrent PLT hook failed: %s (%d)\n",
                    bh_plt_strerror(status), status);
            return (void *)1;
        }
        (void)bh_plt_unhook(NULL, "puts", (void *)bh_concurrent_fake_puts);
    }
    return NULL;
}

int main(void) {
    pthread_t threads[4];
    void *result;
    int i;

    bh_real_puts = puts;
    puts("before concurrent tests");

    if (pthread_create(&threads[0], NULL, bh_inline_worker, NULL) != 0 ||
        pthread_create(&threads[1], NULL, bh_inline_worker, NULL) != 0 ||
        pthread_create(&threads[2], NULL, bh_plt_worker, NULL) != 0 ||
        pthread_create(&threads[3], NULL, bh_plt_worker, NULL) != 0) {
        fprintf(stderr, "unable to create worker threads\n");
        return 1;
    }

    for (i = 0; i < 4; i++) {
        if (pthread_join(threads[i], &result) != 0 || result != NULL) {
            return 1;
        }
    }

    (void)bh_inline_unhook_all();
    (void)bh_plt_unhook_all();

    if (bh_concurrent_target(2, 3) != 5) {
        fprintf(stderr, "inline target was not restored\n");
        return 1;
    }
    if (bh_inline_is_hooked((const void *)bh_concurrent_target)) {
        fprintf(stderr, "inline target is still hooked\n");
        return 1;
    }
    if (bh_plt_is_hooked(NULL, "puts", (void *)bh_concurrent_fake_puts)) {
        fprintf(stderr, "puts is still hooked\n");
        return 1;
    }

    puts("concurrent tests passed");
    return 0;
}
