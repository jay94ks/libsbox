/*
 * e2ehelper: the one program the end-to-end tests put into images and sandboxes.
 *
 *   serve PORT MESSAGE COUNT   listen on 0.0.0.0:PORT, send MESSAGE to COUNT clients, exit 0
 *   fetch HOST PORT [SECONDS]  connect (retrying up to SECONDS, default 10), print what is received
 *   connect HOST PORT          one connect attempt; prints "connected" or "error <errno name>"
 *   read PATH                  prints the file or "error <errno name>" (exit 1)
 *   write PATH TEXT            creates PATH with TEXT
 *   pids                       prints the number of processes visible in /proc and their pids
 *   forkbomb                   forks children (that sleep) until fork fails; prints the count
 *   memhog MIB                 allocates and touches MIB MiB
 *   spin                       burns CPU forever
 *   syscall NAME               ptrace / mount / unshare / setns / bpf / keyctl; prints the result
 *
 * The hostile subcommands report "error <name>" for a refused call so the tests can tell an
 * errno-based denial from a kill.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char* errname(int e) {
    switch (e) {
    case EPERM: return "EPERM";
    case ENOENT: return "ENOENT";
    case EACCES: return "EACCES";
    case EAGAIN: return "EAGAIN";
    case ENOSYS: return "ENOSYS";
    case ENETUNREACH: return "ENETUNREACH";
    case ECONNREFUSED: return "ECONNREFUSED";
    case ETIMEDOUT: return "ETIMEDOUT";
    case EHOSTUNREACH: return "EHOSTUNREACH";
    case EROFS: return "EROFS";
    case ENOMEM: return "ENOMEM";
    case EINVAL: return "EINVAL";
    default: return "EOTHER";
    }
}

static int fail(const char* what) {
    printf("error %s\n", errname(errno));
    fflush(stdout);
    (void)what;
    return 1;
}

static int resolve(const char* host, int port, struct sockaddr_in* out) {
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((unsigned short)port);
    return inet_pton(AF_INET, host, &out->sin_addr) == 1 ? 0 : -1;
}

static int cmdServe(int port, const char* message, int count) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return fail("socket");
    }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0 || listen(fd, 16) != 0) {
        return fail("bind");
    }

    printf("listening\n");
    fflush(stdout);
    for (int i = 0; i < count; ++i) {
        int c = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) {
            if (errno == EINTR) {
                --i;
                continue;
            }

            return fail("accept");
        }

        ssize_t n = send(c, message, strlen(message), MSG_NOSIGNAL);
        (void)n;
        close(c);
    }

    return 0;
}

static int cmdFetch(const char* host, int port, int seconds) {
    struct sockaddr_in sa;
    if (resolve(host, port, &sa) != 0) {
        errno = EINVAL;
        return fail("address");
    }

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            return fail("socket");
        }

        struct timeval tv = { 3, 0 };
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
            char buf[4096];
            ssize_t n;
            while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) {
                fwrite(buf, 1, (size_t)n, stdout);
            }

            close(fd);
            fflush(stdout);
            return 0;
        }

        int err = errno;
        close(fd);
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= seconds) {
            errno = err;
            return fail("connect");
        }

        usleep(50000);
    }
}

static int cmdConnect(const char* host, int port) {
    struct sockaddr_in sa;
    if (resolve(host, port, &sa) != 0) {
        errno = EINVAL;
        return fail("address");
    }

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return fail("socket");
    }

    struct timeval tv = { 2, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        return fail("connect");
    }

    printf("connected\n");
    close(fd);
    return 0;
}

static int cmdRead(const char* path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return fail("open");
    }

    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, (size_t)n, stdout);
    }

    close(fd);
    return n < 0 ? fail("read") : 0;
}

static int cmdWrite(const char* path, const char* text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        return fail("open");
    }

    ssize_t n = write(fd, text, strlen(text));
    close(fd);
    return n == (ssize_t)strlen(text) ? 0 : fail("write");
}

static int cmdPids(void) {
    DIR* d = opendir("/proc");
    if (!d) {
        return fail("opendir");
    }

    int count = 0;
    char list[4096] = "";
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') {
            continue;
        }

        ++count;
        if (strlen(list) + strlen(e->d_name) + 2 < sizeof(list)) {
            strcat(list, " ");
            strcat(list, e->d_name);
        }
    }

    closedir(d);
    printf("%d%s\n", count, list);
    return 0;
}

static int cmdForkbomb(void) {
    int count = 0;
    for (;;) {
        pid_t pid = fork();
        if (pid == 0) {
            pause();
            _exit(0);
        }

        if (pid < 0) {
            printf("forked %d error %s\n", count, errname(errno));
            fflush(stdout);
            // --> The children are killed with the sandbox; exit with a distinct code.
            return 3;
        }

        if (++count > 100000) {
            printf("forked %d\n", count);
            return 0;
        }
    }
}

static int cmdMemhog(int mib) {
    for (int i = 0; i < mib; ++i) {
        char* block = malloc(1 << 20);
        if (!block) {
            printf("malloc failed after %d MiB\n", i);
            return 3;
        }

        memset(block, 0x5a, 1 << 20);
    }

    printf("allocated %d MiB\n", mib);
    return 0;
}

static int cmdSpin(void) {
    volatile unsigned long x = 0;
    for (;;) {
        ++x;
    }
}

static int cmdSyscall(const char* name) {
    long r;
    if (strcmp(name, "ptrace") == 0) {
        r = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    } else if (strcmp(name, "mount") == 0) {
        r = mount("none", "/tmp", "tmpfs", 0, NULL);
    } else if (strcmp(name, "unshare") == 0) {
        r = unshare(CLONE_NEWUSER);
    } else if (strcmp(name, "setns") == 0) {
        int fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
        r = setns(fd, CLONE_NEWNET);
    } else if (strcmp(name, "bpf") == 0) {
        r = syscall(SYS_bpf, 0, NULL, 0);
    } else if (strcmp(name, "keyctl") == 0) {
        r = syscall(SYS_keyctl, 0, 0, 0, 0, 0);
    } else {
        fprintf(stderr, "unknown syscall %s\n", name);
        return 2;
    }

    if (r < 0) {
        return fail(name);
    }

    printf("allowed\n");
    return 0;
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2) {
        fprintf(stderr, "usage: e2ehelper COMMAND ...\n");
        return 2;
    }

    const char* cmd = argv[1];
    if (strcmp(cmd, "serve") == 0 && argc >= 5) {
        return cmdServe(atoi(argv[2]), argv[3], atoi(argv[4]));
    }

    if (strcmp(cmd, "fetch") == 0 && argc >= 4) {
        return cmdFetch(argv[2], atoi(argv[3]), argc >= 5 ? atoi(argv[4]) : 10);
    }

    if (strcmp(cmd, "connect") == 0 && argc >= 4) {
        return cmdConnect(argv[2], atoi(argv[3]));
    }

    if (strcmp(cmd, "read") == 0 && argc >= 3) {
        return cmdRead(argv[2]);
    }

    if (strcmp(cmd, "write") == 0 && argc >= 4) {
        return cmdWrite(argv[2], argv[3]);
    }

    if (strcmp(cmd, "pids") == 0) {
        return cmdPids();
    }

    if (strcmp(cmd, "forkbomb") == 0) {
        return cmdForkbomb();
    }

    if (strcmp(cmd, "memhog") == 0 && argc >= 3) {
        return cmdMemhog(atoi(argv[2]));
    }

    if (strcmp(cmd, "spin") == 0) {
        return cmdSpin();
    }

    if (strcmp(cmd, "syscall") == 0 && argc >= 3) {
        return cmdSyscall(argv[2]);
    }

    fprintf(stderr, "e2ehelper: bad arguments\n");
    return 2;
}
