/**
 * Copyright (c) 2026 VeryBaaad <verybaaad@outlook.com>
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include "bhinline.h"
#include "bhplt.h"

int main(void) {
    printf("embedded %s\n", bh_inline_arch_name());
    return 0;
}
