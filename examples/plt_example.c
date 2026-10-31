#include <stdio.h>

#include "bhplt.h"

static int (*original_puts)(const char *);

static int hooked_puts(const char *text) {
    return original_puts(text);
}

int main(void) {
    int count = bh_plt_hook(NULL, "puts", (void *)hooked_puts,
                            (void **)&original_puts);
    if (count < 0) {
        fprintf(stderr, "plt hook failed: %s\n", bh_plt_strerror(count));
        return 1;
    }
    puts("hello through the PLT hook");
    bh_plt_unhook(NULL, "puts", (void *)hooked_puts);
    return 0;
}
