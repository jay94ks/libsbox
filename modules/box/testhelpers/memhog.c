/* Test helper: allocates and touches memory in 1 MiB steps up to 2 GiB. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    for (int i = 0; i < 2048; ++i) {
        char* block = malloc(1 << 20);
        if (!block) {
            printf("malloc failed after %d MiB\n", i);
            return 3;
        }

        memset(block, 0x5a, 1 << 20);
    }

    printf("done\n");
    return 0;
}
