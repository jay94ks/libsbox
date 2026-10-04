/* Test helper: spins on the CPU forever. */
int main(void) {
    volatile unsigned long n = 0;
    for (;;) {
        ++n;
    }
}
