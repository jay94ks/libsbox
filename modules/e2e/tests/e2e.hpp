#ifndef __TESTS_E2E_E2E_HPP__
#define __TESTS_E2E_E2E_HPP__

// Shared helpers of the end-to-end tests.
//
// Every test executable moves itself into a private mount namespace before doctest starts (when
// it runs as root): overlay roots, volume mounts and netns pins made by the test or by the tools
// it starts never reach the host's mount table, and they vanish with the process even when a
// test aborts. Network work happens in throwaway network namespaces; the real host network is
// never touched.

#include <sbox/archive/codec.hpp>
#include <sbox/archive/stream.hpp>
#include <sbox/archive/tar.hpp>
#include <sbox/archive/tree.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/json.hpp>
#include <sbox/image/digest.hpp>
#include <sbox/image/spec.hpp>
#include <sbox/net/nftables.hpp>
#include <sbox/core/stream.hpp>
#include <sbox/oci/runtime.hpp>
#include <sbox/oci/spec.hpp>
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <grp.h>
#include <random>
#include <sched.h>
#include <string>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#ifndef P_PIDFD
#define P_PIDFD 3
#endif

extern char** environ;

namespace e2e {

    using namespace sbox;

    /**
     * Process-wide setup: a private mount namespace (root only) and SIGPIPE ignored.
     */
    struct SProcessSetup {
        bool privateMounts = false;

        SProcessSetup() {
            ::signal(SIGPIPE, SIG_IGN);
            if (::geteuid() == 0 && ::unshare(CLONE_NEWNS) == 0 &&
                ::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == 0) {
                privateMounts = true;
            }
        }
    };

    inline SProcessSetup processSetup;

    /**
     * Returns true when the test runs as root in its private mount namespace.
     */
    inline bool isRoot() {
        return ::geteuid() == 0 && processSetup.privateMounts;
    }

    /**
     * Returns a short random suffix for unique names.
     */
    inline std::string randomSuffix() {
        std::random_device rd;
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%08x", unsigned(rd()));
        return buf;
    }

    /**
     * Returns the path of a built CLI tool.
     */
    inline std::string tool(const std::string& name) {
        return std::string(SBOX_TEST_BIN_DIR) + "/" + name;
    }

    /**
     * Returns true when the CLI tools were built.
     */
    inline bool haveTools() {
        for (const char* name : { "sbox", "sbox-image", "sbox-cni", "sboxvol" }) {
            if (::access(tool(name).c_str(), X_OK) != 0) {
                return false;
            }
        }

        return true;
    }

    /**
     * Detaches every mount at or below `path` (deepest first).
     */
    inline void unmountBelow(const std::string& path) {
        std::string info;
        if (CFile::readAll("/proc/self/mountinfo", info) != SBOX_OK) {
            return;
        }

        std::vector<std::string> targets;
        for (std::string_view line : CFile::splitLines(info)) {
            // --> "id parent major:minor root mountpoint options ..." (mountpoint is field 5).
            size_t pos = 0;
            for (int field = 0; field < 4 && pos != std::string_view::npos; ++field) {
                pos = line.find(' ', pos);
                if (pos != std::string_view::npos) {
                    ++pos;
                }
            }

            if (pos == std::string_view::npos) {
                continue;
            }

            std::string_view mp = line.substr(pos, line.find(' ', pos) - pos);
            if (mp == path || (mp.size() > path.size() && mp.substr(0, path.size()) == path && mp[path.size()] == '/')) {
                targets.emplace_back(mp);
            }
        }

        std::sort(targets.begin(), targets.end(), [](const std::string& a, const std::string& b) { return a.size() > b.size(); });
        for (const std::string& t : targets) {
            ::umount2(t.c_str(), MNT_DETACH);
        }
    }

    /**
     * Temporary directory under /var/tmp (traversable by every uid), unmounted and removed on
     * destruction.
     */
    struct TempDir {
        std::string path;

        TempDir() {
            char tmpl[] = "/var/tmp/sbox-e2e-XXXXXX";
            if (::mkdtemp(tmpl)) {
                path = tmpl;
                ::chmod(path.c_str(), 0755);
            }
        }

        TempDir(const TempDir&) = delete;

        TempDir& operator=(const TempDir&) = delete;

        ~TempDir() {
            if (!path.empty()) {
                unmountBelow(path);
                CFile::removeTree(path);
            }
        }

        std::string operator/(const std::string& leaf) const {
            return CFile::join(path, leaf);
        }
    };

    /**
     * Builds an argument vector (avoids braced string lists inside co_await expressions, which
     * crash GCC 13).
     */
    template<typename... A>
    inline std::vector<std::string> Args(A&&... args) {
        std::vector<std::string> out;
        out.reserve(sizeof...(args));
        (out.emplace_back(std::forward<A>(args)), ...);
        return out;
    }

    /**
     * Result of one tool invocation.
     */
    struct ToolResult {
        int code = -1;
        std::string out;
        std::string err;
    };

    /**
     * Options of runTool.
     */
    struct RunOptions {
        std::string input;                  // --> Standard input.
        std::string netns;                  // --> Network namespace to run in (empty: ours).
        std::vector<std::string> env;       // --> Added to (or replacing in) our environment.
        int64_t timeoutMs = 120000;
        int64_t uid = -1;                   // --> Run as this uid/gid (no supplementary groups).
        int64_t gid = -1;
    };

    /**
     * Runs a program the way a user's shell does: fork + exec, standard streams redirected to
     * files (a created container inherits them, so pipes would see EOF only when it exits).
     * Waits on a pidfd in the event loop, so servers running in the same loop keep serving.
     */
    inline TTask<ToolResult> runTool(std::string scratch, std::string binary, std::vector<std::string> args,
                                     RunOptions options = RunOptions()) {
        static int counter = 0;
        std::string base = scratch + "/io-" + std::to_string(::getpid()) + "-" + std::to_string(counter++);
        std::string inPath = base + ".in", outPath = base + ".out", errPath = base + ".err";
        CFile::writeAtomic(inPath, options.input, 0644);

        std::vector<std::string> envStore;
        for (char** e = environ; *e; ++e) {
            std::string kv = *e;
            bool replaced = false;
            for (const std::string& add : options.env) {
                if (kv.substr(0, kv.find('=') + 1) == add.substr(0, add.find('=') + 1)) {
                    replaced = true;
                }
            }

            if (!replaced) {
                envStore.push_back(kv);
            }
        }

        for (const std::string& add : options.env) {
            envStore.push_back(add);
        }

        std::vector<char*> argv;
        argv.push_back(binary.data());
        for (std::string& a : args) {
            argv.push_back(a.data());
        }

        argv.push_back(nullptr);
        std::vector<char*> envp;
        for (std::string& e : envStore) {
            envp.push_back(e.data());
        }

        envp.push_back(nullptr);

        // --> Opened here, before any uid change, so the files need not be writable by the child.
        ToolResult r;
        CFd in(::open(inPath.c_str(), O_RDONLY | O_CLOEXEC));
        CFd out(::open(outPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
        CFd err(::open(errPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
        if (!in.isValid() || !out.isValid() || !err.isValid()) {
            co_return r;
        }

        pid_t pid = ::fork();
        if (pid < 0) {
            co_return r;
        }

        if (pid == 0) {
            sigset_t all;
            sigemptyset(&all);
            ::sigprocmask(SIG_SETMASK, &all, nullptr);
            if (!options.netns.empty()) {
                int ns = ::open(options.netns.c_str(), O_RDONLY | O_CLOEXEC);
                if (ns < 0 || ::setns(ns, CLONE_NEWNET) != 0) {
                    ::_exit(126);
                }
            }

            if (options.uid >= 0) {
                if (::setgroups(0, nullptr) != 0 || ::setresgid(gid_t(options.gid), gid_t(options.gid), gid_t(options.gid)) != 0 ||
                    ::setresuid(uid_t(options.uid), uid_t(options.uid), uid_t(options.uid)) != 0) {
                    ::_exit(126);
                }
            }

            if (::dup2(in.get(), 0) < 0 || ::dup2(out.get(), 1) < 0 || ::dup2(err.get(), 2) < 0) {
                ::_exit(126);
            }

            ::execve(binary.c_str(), argv.data(), envp.data());
            ::_exit(127);
        }

        CFd pidfd(int(::syscall(SYS_pidfd_open, pid, 0)));
        int32_t ready = co_await CEventLoop::current()->waitFd(pidfd.get(), EFDE_READ, options.timeoutMs);
        if (ready < 0) {
            ::kill(pid, SIGKILL);
        }

        siginfo_t info;
        std::memset(&info, 0, sizeof(info));
        ::waitid(idtype_t(P_PIDFD), id_t(pidfd.get()), &info, WEXITED);
        r.code = info.si_code == CLD_EXITED ? info.si_status : 128 + info.si_status;
        CFile::readAll(outPath, r.out);
        CFile::readAll(errPath, r.err);
        ::unlink(inPath.c_str());
        ::unlink(outPath.c_str());
        ::unlink(errPath.c_str());
        co_return r;
    }

    /**
     * Strips trailing newlines and spaces.
     */
    inline std::string trim(std::string s) {
        while (!s.empty() && (s.back() == '\n' || s.back() == ' ' || s.back() == '\r')) {
            s.pop_back();
        }

        return s;
    }

    /**
     * Parses JSON text (null on error).
     */
    inline CJson parseJson(const std::string& text) {
        CJson doc;
        CJson::parse(text, doc);
        return doc;
    }

    /**
     * Returns true when nf_tables can be programmed in `netns` (port mappings need it). Applies
     * an empty `sbox` table there; the network manager replaces it later anyway.
     */
    inline TTask<bool> haveNftables(std::string netns) {
        net::CFirewall fw;
        if (fw.open(netns) != SBOX_OK) {
            co_return false;
        }

        co_return co_await fw.apply(net::SFirewallState()) == SBOX_OK;
    }

    /**
     * Outcome of runContainer.
     */
    struct ContainerRun {
        int32_t error = SBOX_OK;            // --> First failing runtime call.
        std::string message;                // --> CRuntime::lastError() of that call.
        int code = -1;                      // --> Exit code, or 128 + signal.
        std::string out;                    // --> stdout and stderr together.
    };

    /**
     * Reads a stream to EOF (bounded).
     */
    inline TTask<std::string> readStream(CStream& s, int64_t timeoutMs = 30000) {
        std::vector<uint8_t> out;
        co_await s.recvAll(out, size_t(1) << 20, timeoutMs);
        co_return std::string(out.begin(), out.end());
    }

    /**
     * Runs a bundle with the library the way `sbox run` does: create (stdout and stderr on a
     * pipe, the init kept), check the created state, start, collect output, wait, delete.
     */
    inline TTask<ContainerRun> runContainer(std::string stateRoot, std::string bundle, std::string id, int64_t timeoutMs = 30000) {
        ContainerRun run;
        oci::SRuntimeOptions ro;
        ro.root = stateRoot;
        oci::CRuntime rt(ro);
        CStream out;
        CFd outChild;
        if ((run.error = CPipe::createForChild(out, outChild, true)) != SBOX_OK) {
            co_return run;
        }

        oci::SCreateOptions o;
        o.bundle = bundle;
        o.stdio = { { outChild.get(), 1 }, { outChild.get(), 2 } };
        oci::CContainerProcess proc;
        if ((run.error = co_await rt.create(id, o, &proc)) != SBOX_OK) {
            run.message = "create: " + rt.lastError();
            co_return run;
        }

        outChild.reset();
        oci::SState st;
        if ((run.error = co_await rt.state(id, st)) != SBOX_OK || st.status != oci::ECST_CREATED) {
            run.message = "state after create: " + rt.lastError();
            run.error = run.error ? run.error : -EPROTO;
            co_await rt.remove(id, true);
            co_return run;
        }

        if ((run.error = co_await rt.start(id)) != SBOX_OK) {
            run.message = "start: " + rt.lastError();
            co_await rt.remove(id, true);
            co_return run;
        }

        run.out = co_await readStream(out, timeoutMs);
        SExitStatus es;
        if ((run.error = co_await proc.wait(es, timeoutMs)) != SBOX_OK) {
            run.message = "wait";
            proc.kill(SIGKILL);
        } else {
            run.code = es.exited ? es.exitCode : 128 + es.signal;
        }

        int32_t r = co_await rt.remove(id, true);
        if (run.error == SBOX_OK && r != SBOX_OK) {
            run.error = r;
            run.message = "delete: " + rt.lastError();
        }

        co_return run;
    }

    /**
     * Writes a config.json document into a bundle.
     */
    inline bool writeConfig(const std::string& bundle, const CJson& config) {
        return CFile::writeAtomic(bundle + "/config.json", config.dump(true), 0644) == SBOX_OK;
    }

    /**
     * runc's default config (no terminal, writable root) running `args`, as JSON.
     */
    inline CJson defaultConfig(std::vector<std::string> args, std::string hostname = "e2e") {
        oci::SSpec spec = oci::DefaultSpec(false, 0, 0, hostname);
        spec.process->terminal = false;
        spec.process->args = std::move(args);
        spec.root->readonly = false;
        return oci::SpecToJson(spec);
    }

    /**
     * Sets the path of a namespace in a config.json document (adds the entry when missing).
     */
    inline void setNamespacePath(CJson& config, const std::string& type, const std::string& path) {
        CJson& namespaces = config["linux"]["namespaces"];
        for (size_t i = 0; i < namespaces.size(); ++i) {
            if (namespaces.at(i).get("type").asString() == type) {
                namespaces.at(i).set("path", path);
                return;
            }
        }

        CJson entry = CJson::object();
        entry.set("type", type);
        entry.set("path", path);
        namespaces.push(std::move(entry));
    }

    /**
     * Reads a bundle's config.json (null on error).
     */
    inline CJson readConfig(const std::string& bundle) {
        std::string text;
        CFile::readAll(bundle + "/config.json", text);
        CJson doc;
        CJson::parse(text, doc);
        return doc;
    }

    /**
     * Copies a file preserving its permission bits.
     */
    inline bool copyFile(const std::string& from, const std::string& to) {
        std::string data;
        struct stat st;
        if (::stat(from.c_str(), &st) != 0 || CFile::readAll(from, data, size_t(256) << 20) != SBOX_OK) {
            return false;
        }

        CFile::makeDirs(to.substr(0, to.find_last_of('/')), 0755);
        int fd = ::open(to.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, st.st_mode & 0777);
        if (fd < 0) {
            return false;
        }

        bool ok = ::write(fd, data.data(), data.size()) == ssize_t(data.size());
        ::close(fd);
        ::chmod(to.c_str(), st.st_mode & 0777);
        return ok;
    }

    /**
     * Runs a shell command and returns its standard output (blocking; only for ldd at setup).
     */
    inline std::string capture(const std::string& cmd) {
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

        ::pclose(p);
        return out;
    }

    /**
     * Copies a program and every shared library ldd reports into a root directory.
     */
    inline bool installProgram(const std::string& root, const std::string& source, const std::string& target) {
        if (!copyFile(source, root + target)) {
            return false;
        }

        // --> "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...)" and "/lib64/ld-linux... (0x...)".
        std::string out = capture("ldd " + source + " 2>/dev/null");
        for (std::string_view line : CFile::splitLines(out)) {
            size_t slash = line.find('/');
            if (slash == std::string_view::npos) {
                continue;
            }

            std::string_view rest = line.substr(slash);
            std::string lib(rest.substr(0, rest.find_first_of(" \t")));
            if (!CFile::exists(root + lib) && !copyFile(lib, root + lib)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Builds a small root filesystem from the host's programs (or busybox when present) and the
     * e2e helper: /bin/{sh, cat, ...}, their libraries, /etc/passwd and /etc/group, empty /proc,
     * /dev, /sys, /tmp, /run.
     */
    inline bool makeRootfs(const std::string& root) {
        static const char* const PROGRAMS[] = {
            "sh", "cat", "sleep", "echo", "ls", "id", "hostname", "true", "false", "touch", "mkdir", "head", "rm", "wc",
        };

        for (const char* dir : { "bin", "proc", "dev", "sys", "tmp", "etc", "run", "root" }) {
            CFile::makeDirs(root + "/" + dir, 0755);
        }

        ::chmod((root + "/tmp").c_str(), 01777);
        for (const char* prog : PROGRAMS) {
            std::string src;
            for (const char* dir : { "/bin/", "/usr/bin/" }) {
                if (::access((std::string(dir) + prog).c_str(), X_OK) == 0) {
                    src = std::string(dir) + prog;
                    break;
                }
            }

            if (src.empty()) {
                if (::access("/bin/busybox", X_OK) != 0) {
                    continue;
                }

                // --> No such host program: a busybox applet link does the job.
                if (!CFile::exists(root + "/bin/busybox") && !installProgram(root, "/bin/busybox", "/bin/busybox")) {
                    return false;
                }

                ::symlink("busybox", (root + "/bin/" + prog).c_str());
                continue;
            }

            if (!installProgram(root, src, std::string("/bin/") + prog)) {
                return false;
            }
        }

        if (!installProgram(root, SBOX_E2E_HELPER, "/bin/e2ehelper")) {
            return false;
        }

        CFile::writeAtomic(root + "/etc/passwd", "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/sh\n", 0644);
        CFile::writeAtomic(root + "/etc/group", "root:x:0:\ntty:x:5:\nnogroup:x:65534:\n", 0644);
        return true;
    }

    /**
     * An image built inside the test: two layers (the rootfs, then a layer that whites out
     * /etc/removed and adds /etc/motd and /data/seed.txt), its config, a docker-save archive
     * and the registry form (gzip layers + schema2 manifest).
     */
    struct ImageFixture {
        std::string config;                     // --> Config JSON bytes.
        std::string configDigest;               // --> = image ID.
        std::vector<std::string> layers;        // --> Uncompressed tar bytes.
        std::vector<std::string> diffIds;
        std::vector<std::string> gzLayers;      // --> gzip-compressed layer blobs.
        std::vector<std::string> gzDigests;
        std::string manifest;                   // --> Docker schema2 manifest for the gzip blobs.
        std::string manifestDigest;
    };

    /**
     * Writes a tree as an uncompressed tar.
     */
    inline bool tarTree(const std::string& dir, std::string& out) {
        std::vector<uint8_t> bytes;
        archive::CVectorSink sink(bytes);
        if (archive::WriteTreeArchive(dir, sink, archive::ECOMP_NONE) != SBOX_OK) {
            return false;
        }

        out.assign(bytes.begin(), bytes.end());
        return true;
    }

    /**
     * gzip-compresses bytes.
     */
    inline bool gzip(const std::string& in, std::string& out) {
        std::vector<uint8_t> bytes;
        archive::CVectorSink sink(bytes);
        archive::CCodecSink codec(archive::CreateEncoder(archive::ECOMP_GZIP, 1), sink);
        if (codec.write(SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(in.data()), in.size())) != SBOX_OK ||
            codec.finish() != SBOX_OK) {
            return false;
        }

        out.assign(bytes.begin(), bytes.end());
        return true;
    }

    /**
     * Builds the image fixture under `scratch` (the rootfs is assembled there first).
     * @param cmd The image's Cmd.
     */
    inline bool buildImage(const std::string& scratch, ImageFixture& out,
                           std::vector<std::string> cmd = { "/bin/sh", "-c", "echo hello from $(cat /etc/motd)" }) {
        std::string base = scratch + "/image-base";
        std::string top = scratch + "/image-top";
        if (!makeRootfs(base)) {
            return false;
        }

        CFile::writeAtomic(base + "/etc/removed", "this file is whited out by the second layer\n", 0644);
        CFile::makeDirs(top + "/etc", 0755);
        CFile::makeDirs(top + "/data", 0755);
        CFile::writeAtomic(top + "/etc/.wh.removed", "", 0644);
        CFile::writeAtomic(top + "/etc/motd", "layer-two\n", 0644);
        CFile::writeAtomic(top + "/data/seed.txt", "seeded by the image\n", 0644);

        out.layers.resize(2);
        if (!tarTree(base, out.layers[0]) || !tarTree(top, out.layers[1])) {
            return false;
        }

        CFile::removeTree(base);
        CFile::removeTree(top);

        CJson diffIds = CJson::array();
        for (const std::string& layer : out.layers) {
            out.diffIds.push_back(image::DigestOf(BytesOf(layer)));
            diffIds.push(out.diffIds.back());
            std::string gz;
            if (!gzip(layer, gz)) {
                return false;
            }

            out.gzDigests.push_back(image::DigestOf(BytesOf(gz)));
            out.gzLayers.push_back(std::move(gz));
        }

        image::SPlatform host = image::HostPlatform();
        CJson config = CJson::object();
        config.set("architecture", host.architecture);
        if (!host.variant.empty()) {
            config.set("variant", host.variant);
        }

        config.set("os", "linux");
        config.set("created", "2026-10-04T00:00:00Z");
        CJson c = CJson::object();
        c.set("Env", CJson::fromStrings({ "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "E2E=1" }));
        c.set("Cmd", CJson::fromStrings(cmd));
        c.set("WorkingDir", "/");
        CJson volumes = CJson::object();
        volumes.set("/data", CJson::object());
        c.set("Volumes", std::move(volumes));
        config.set("config", std::move(c));
        CJson rootfs = CJson::object();
        rootfs.set("type", "layers");
        rootfs.set("diff_ids", std::move(diffIds));
        config.set("rootfs", std::move(rootfs));
        CJson history = CJson::array();
        for (const char* step : { "e2e base", "e2e top" }) {
            CJson h = CJson::object();
            h.set("created", "2026-10-04T00:00:00Z");
            h.set("created_by", step);
            history.push(std::move(h));
        }

        config.set("history", std::move(history));
        out.config = config.dump();
        out.configDigest = image::DigestOf(BytesOf(out.config));

        CJson manifest = CJson::object();
        manifest.set("schemaVersion", 2);
        manifest.set("mediaType", "application/vnd.docker.distribution.manifest.v2+json");
        CJson cd = CJson::object();
        cd.set("mediaType", "application/vnd.docker.container.image.v1+json");
        cd.set("size", uint64_t(out.config.size()));
        cd.set("digest", out.configDigest);
        manifest.set("config", std::move(cd));
        CJson layers = CJson::array();
        for (size_t i = 0; i < out.gzLayers.size(); ++i) {
            CJson l = CJson::object();
            l.set("mediaType", "application/vnd.docker.image.rootfs.diff.tar.gzip");
            l.set("size", uint64_t(out.gzLayers[i].size()));
            l.set("digest", out.gzDigests[i]);
            layers.push(std::move(l));
        }

        manifest.set("layers", std::move(layers));
        out.manifest = manifest.dump();
        out.manifestDigest = image::DigestOf(BytesOf(out.manifest));
        return true;
    }

    /**
     * Writes the fixture as a classic `docker save` archive (manifest.json, <id>.json,
     * <diffID>/layer.tar) tagged `tag`.
     */
    inline bool writeDockerSave(const ImageFixture& img, const std::string& tag, const std::string& path) {
        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd < 0) {
            return false;
        }

        archive::CFdSink sink(fd);
        archive::CTarWriter tar(sink);
        bool ok = true;
        auto file = [&](const std::string& name, const std::string& data) {
            archive::STarEntry e;
            e.type = archive::ETAR_FILE;
            e.path = name;
            e.mode = 0644;
            e.size = data.size();
            e.mtime.sec = 1790000000;
            ok = ok && tar.writeEntry(e, BytesOf(data)) == SBOX_OK;
        };

        auto dir = [&](const std::string& name) {
            archive::STarEntry e;
            e.type = archive::ETAR_DIR;
            e.path = name + "/";
            e.mode = 0755;
            e.mtime.sec = 1790000000;
            ok = ok && tar.writeEntry(e) == SBOX_OK;
        };

        std::string configName = std::string(image::DigestHex(img.configDigest)) + ".json";
        file(configName, img.config);
        CJson layerNames = CJson::array();
        for (size_t i = 0; i < img.layers.size(); ++i) {
            std::string hex(image::DigestHex(img.diffIds[i]));
            dir(hex);
            file(hex + "/layer.tar", img.layers[i]);
            layerNames.push(hex + "/layer.tar");
        }

        CJson entry = CJson::object();
        entry.set("Config", configName);
        entry.set("RepoTags", CJson::fromStrings({ tag }));
        entry.set("Layers", std::move(layerNames));
        CJson manifest = CJson::array();
        manifest.push(std::move(entry));
        file("manifest.json", manifest.dump());
        ok = ok && tar.finish() == SBOX_OK;
        ::close(fd);
        return ok;
    }

}

#endif
