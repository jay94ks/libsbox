#ifndef __TESTS_BOX_TESTUTIL_HPP__
#define __TESTS_BOX_TESTUTIL_HPP__

#include <sbox/box/launch.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/stream.hpp>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sched.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string>

namespace testutil {

    using namespace sbox;

    /**
     * Returns true when a path exists.
     */
    inline bool exists(const char* path) {
        struct stat st;
        return ::stat(path, &st) == 0;
    }

    /**
     * Returns true when this process may create user namespaces (probed in a child).
     */
    inline bool userNamespacesWork() {
        pid_t pid = ::fork();
        if (pid == 0) {
            ::_exit(::unshare(CLONE_NEWUSER) == 0 ? 0 : 1);
        }

        int st = 0;
        ::waitpid(pid, &st, 0);
        return WIFEXITED(st) && WEXITSTATUS(st) == 0;
    }

    /**
     * A container spec with every namespace new, a tmpfs root, the host's system directories
     * bound read-only, a fresh /proc and a minimal /dev.
     */
    inline SLaunchSpec baseSpec(std::vector<std::string> args) {
        SLaunchSpec s;
        s.args = std::move(args);
        s.env = { "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/", "LANG=C" };
        s.namespaces = {
            { ENS_USER, "" }, { ENS_PID, "" }, { ENS_MOUNT, "" }, { ENS_IPC, "" },
            { ENS_UTS, "" }, { ENS_NET, "" }, { ENS_CGROUP, "" },
        };
        s.rootfsMode = ERFS_TMPFS;
        s.hostname = "testbox";
        s.loopbackUp = true;

        for (const char* dir : { "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc" }) {
            if (exists(dir)) {
                SMountSpec m;
                m.source = dir;
                m.destination = dir;
                m.flags = MS_BIND | MS_REC | MS_RDONLY | MS_NOSUID | MS_NODEV;
                s.mounts.push_back(m);
            }
        }

        SMountSpec proc;
        proc.source = "proc";
        proc.destination = "/proc";
        proc.type = "proc";
        proc.flags = MS_NOSUID | MS_NODEV | MS_NOEXEC;
        s.mounts.push_back(proc);

        SMountSpec dev;
        dev.source = "tmpfs";
        dev.destination = "/dev";
        dev.type = "tmpfs";
        dev.flags = MS_NOSUID | MS_NOEXEC;
        dev.data = "mode=755,size=64k";
        s.mounts.push_back(dev);

        SMountSpec pts;
        pts.source = "devpts";
        pts.destination = "/dev/pts";
        pts.type = "devpts";
        pts.flags = MS_NOSUID | MS_NOEXEC;
        pts.data = "newinstance,ptmxmode=0666,mode=0620";
        s.mounts.push_back(pts);

        SMountSpec tmp;
        tmp.source = "tmpfs";
        tmp.destination = "/tmp";
        tmp.type = "tmpfs";
        tmp.flags = MS_NOSUID | MS_NODEV;
        tmp.data = "mode=1777,size=16m";
        s.mounts.push_back(tmp);

        s.devices = DefaultDevices();
        s.devSymlinks = true;
        s.parentDeathSignal = SIGKILL;
        return s;
    }

    /**
     * Result of running a spec with captured output.
     */
    struct SRun {
        int32_t spawn = 0;
        std::string step;
        SExitStatus status;
        std::string out;
        std::string err;
    };

    /**
     * Spawns `spec` with stdout/stderr captured (stdin is /dev/null) and waits for it.
     */
    inline TTask<SRun> run(SLaunchSpec spec, std::string input = std::string()) {
        SRun r;
        CStream outRead, errRead, inWrite;
        CFd outChild, errChild, inChild;

        CPipe::createForChild(outRead, outChild, true);
        CPipe::createForChild(errRead, errChild, true);
        CPipe::createForChild(inWrite, inChild, false);

        spec.fds.push_back({ inChild.get(), 0 });
        spec.fds.push_back({ outChild.get(), 1 });
        spec.fds.push_back({ errChild.get(), 2 });

        CProcess proc;
        r.spawn = co_await CProcess::spawn(spec, proc);
        r.step = proc.failedStep();
        outChild.reset();
        errChild.reset();
        inChild.reset();

        if (r.spawn != SBOX_OK) {
            co_return r;
        }

        if (!input.empty()) {
            co_await inWrite.send(BytesOf(input));
        }

        inWrite.close();

        std::vector<uint8_t> out, err;
        co_await outRead.recvAll(out);
        co_await errRead.recvAll(err);
        co_await proc.wait(r.status);

        r.out.assign(out.begin(), out.end());
        r.err.assign(err.begin(), err.end());
        co_return r;
    }

}

#endif
