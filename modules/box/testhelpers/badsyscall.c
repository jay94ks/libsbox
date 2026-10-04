/* Test helper: calls ptrace (denied by the sandbox profile) and reports the errno. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>

int main(void) {
    long rc = ptrace(PTRACE_TRACEME, 0, 0, 0);
    printf("%ld %s\n", rc, rc < 0 ? strerror(errno) : "ok");
    return rc < 0 && errno == EPERM ? 0 : 1;
}
