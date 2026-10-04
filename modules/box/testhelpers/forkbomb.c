/* Test helper: forks sleeping children until fork fails (or 200), prints how many it got. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int made = 0;
    for (int i = 0; i < 200; ++i) {
        pid_t pid = fork();
        if (pid == 0) {
            for (;;) {
                pause();
            }
        }

        if (pid < 0) {
            break;
        }

        ++made;
    }

    printf("%d\n", made);
    fflush(stdout);
    return 0;
}
