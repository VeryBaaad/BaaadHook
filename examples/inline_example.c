#include <stdio.h>

#include "bhinline.h"

static int (*original_add)(int, int);

__attribute__((noinline)) static int add(int a, int b) {
    return a + b;
}

__attribute__((noinline)) static int hooked_add(int a, int b) {
    return original_add(a, b) * 10;
}

int main(void) {
    int status = bh_inline_hook((void *)add, (void *)hooked_add,
                                (void **)&original_add);
    if (status != BH_INLINE_OK) {
        fprintf(stderr, "hook failed: %s\n", bh_inline_strerror(status));
        return 1;
    }
    printf("add(1, 2) = %d\n", add(1, 2));
    bh_inline_unhook((void *)add);
    return 0;
}
