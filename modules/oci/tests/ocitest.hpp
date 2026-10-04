#ifndef __TESTS_OCI_OCITEST_HPP__
#define __TESTS_OCI_OCITEST_HPP__

// Shared helpers of the oci tests: temporary directories, a minimal rootfs assembled from the
// host's binaries (and the shared libraries ldd names), bundles and command execution.

#include <sbox/core/file.hpp>
#include <sbox/core/json.hpp>
#include <sbox/oci/spec.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <random>
#include <sched.h>
#include <signal.h>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace ocitest {

    using namespace sbox;

    /**
     * Returns true when the test runs as root.
     */
    inline bool isRoot() {
        return ::geteuid() == 0;
    }

    /**
     * Returns true when an unprivileged process may create user namespaces (probed in a child
     * that drops to uid 65534).
     */
    inline bool unprivilegedUserNamespaces() {
        pid_t pid = ::fork();
        if (pid == 0) {
            if (::setresgid(65534, 65534, 65534) != 0 || ::setresuid(65534, 65534, 65534) != 0) {
                ::_exit(2);
            }

            ::_exit(::unshare(CLONE_NEWUSER) == 0 ? 0 : 1);
        }

        int st = 0;
        ::waitpid(pid, &st, 0);
        return WIFEXITED(st) && WEXITSTATUS(st) == 0;
    }

    /**
     * Returns a short random suffix for unique ids.
     */
    inline std::string randomSuffix() {
        std::random_device rd;
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%08x", unsigned(rd()));
        return buf;
    }

    /**
     * Temporary directory under /var/tmp (traversable by every uid), removed on destruction.
     */
    struct TempDir {
        std::string path;

        TempDir() {
            char tmpl[] = "/var/tmp/sbox-oci-XXXXXX";
            if (::mkdtemp(tmpl)) {
                path = tmpl;
                ::chmod(path.c_str(), 0755);
            }
        }

        ~TempDir() {
            if (!path.empty()) {
                CFile::removeTree(path);
            }
        }

        std::string operator/(const std::string& leaf) const {
            return CFile::join(path, leaf);
        }
    };

    /**
     * Runs a shell command and returns its standard output (test helper; blocking).
     */
    inline std::string capture(const std::string& cmd, int* status = nullptr) {
        std::string out;
        FILE* p = ::popen(cmd.c_str(), "r");
        if (!p) {
            return out;
        }

        char buf[4096];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof(buf), p)) > 0) {
            out.append(buf, n);
        }

        int st = ::pclose(p);
        if (status) {
            *status = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
        }

        return out;
    }

    /**
     * Copies a file preserving its mode.
     */
    inline bool copyFile(const std::string& from, const std::string& to) {
        std::string data;
        if (CFile::readAll(from, data, size_t(256) << 20) != SBOX_OK) {
            return false;
        }

        struct stat st;
        if (::stat(from.c_str(), &st) != 0) {
            return false;
        }

        size_t slash = to.find_last_of('/');
        CFile::makeDirs(to.substr(0, slash), 0755);
        int fd = ::open(to.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, st.st_mode & 07777);
        if (fd < 0) {
            return false;
        }

        bool ok = ::write(fd, data.data(), data.size()) == ssize_t(data.size());
        ::close(fd);
        ::chmod(to.c_str(), st.st_mode & 0777);
        return ok;
    }

    /**
     * Builds a minimal rootfs: the listed programs copied into /bin together with every shared
     * library `ldd` reports, plus empty /proc, /dev, /sys, /tmp and /etc/passwd.
     */
    inline bool makeRootfs(const std::string& root) {
        static const char* const PROGRAMS[] = {
            "sh", "cat", "sleep", "echo", "ls", "id", "readlink", "hostname", "true", "false", "touch", "mkdir", "head", "ps",
        };

        CFile::makeDirs(root + "/bin", 0755);
        for (const char* dir : { "proc", "dev", "sys", "tmp", "etc", "run" }) {
            CFile::makeDirs(root + "/" + dir, 0755);
        }

        ::chmod((root + "/tmp").c_str(), 01777);

        std::vector<std::string> libs;
        for (const char* prog : PROGRAMS) {
            std::string src = std::string("/bin/") + prog;
            if (::access(src.c_str(), X_OK) != 0) {
                src = std::string("/usr/bin/") + prog;
                if (::access(src.c_str(), X_OK) != 0) {
                    continue;
                }
            }

            if (!copyFile(src, root + "/bin/" + prog)) {
                return false;
            }

            // --> "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...)" and "/lib64/ld-linux... (0x...)".
            std::string out = capture("ldd " + src + " 2>/dev/null");
            for (std::string_view line : CFile::splitLines(out)) {
                size_t slash = line.find('/');
                if (slash == std::string_view::npos) {
                    continue;
                }

                std::string_view rest = line.substr(slash);
                size_t end = rest.find_first_of(" \t");
                libs.emplace_back(rest.substr(0, end));
            }
        }

        for (const std::string& lib : libs) {
            if (!CFile::exists(root + lib) && !copyFile(lib, root + lib)) {
                return false;
            }
        }

        CFile::writeAtomic(root + "/etc/passwd", "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/sh\n", 0644);
        CFile::writeAtomic(root + "/etc/group", "root:x:0:\ntty:x:5:\nnogroup:x:65534:\n", 0644);
        return true;
    }

    /**
     * Returns runc's default configuration adapted for tests: no terminal, a read-write root,
     * the given program.
     */
    inline oci::SSpec testSpec(std::vector<std::string> args, bool rootless = false, uint32_t uid = 0, uint32_t gid = 0) {
        oci::SSpec spec = oci::DefaultSpec(rootless, uid, gid, "ocitest");
        spec.process->terminal = false;
        spec.process->args = std::move(args);
        spec.root->readonly = false;
        return spec;
    }

    /**
     * Writes config.json into a bundle directory.
     */
    inline bool writeSpec(const std::string& bundle, const oci::SSpec& spec) {
        return CFile::writeAtomic(bundle + "/config.json", oci::SpecToJson(spec).dump(true), 0644) == SBOX_OK;
    }

    /**
     * Returns the path of a fixture.
     */
    inline std::string dataFile(const std::string& name) {
        return std::string(SBOX_OCI_TEST_DATA) + "/" + name;
    }

    /**
     * Compares two JSON values structurally (object member order does not matter).
     */
    inline bool jsonEqual(const CJson& a, const CJson& b) {
        if (a.isNumber() && b.isNumber()) {
            return a.asDouble() == b.asDouble() && a.asInt() == b.asInt();
        }

        if (a.type() != b.type()) {
            return false;
        }

        switch (a.type()) {
        case EJSON_NULL:
            return true;
        case EJSON_BOOL:
            return a.asBool() == b.asBool();
        case EJSON_STRING:
            return a.asString() == b.asString();
        case EJSON_ARRAY:
            if (a.size() != b.size()) {
                return false;
            }

            for (size_t i = 0; i < a.size(); ++i) {
                if (!jsonEqual(a.at(i), b.at(i))) {
                    return false;
                }
            }

            return true;
        case EJSON_OBJECT:
            if (a.size() != b.size()) {
                return false;
            }

            for (size_t i = 0; i < a.size(); ++i) {
                const CJson* other = b.find(a.keyAt(i));
                if (!other || !jsonEqual(a.at(i), *other)) {
                    return false;
                }
            }

            return true;
        default:
            return false;
        }
    }

}

#endif
