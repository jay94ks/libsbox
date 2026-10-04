#ifndef __TESTS_TLS_SUPPORT_HPP__
#define __TESTS_TLS_SUPPORT_HPP__

// --> Test helpers shared by the tls tests: temporary directories, running the openssl CLI
// as a child process (pidfd + CEventLoop, no blocking waitpid) and an `openssl s_server`
// harness.

#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/core/stream.hpp>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace tlstest {

    using namespace sbox;

    /* Returns the path of the openssl binary, or "" when absent. */
    inline std::string OpensslPath() {
        static const char* const CANDIDATES[] = { "/usr/bin/openssl", "/usr/local/bin/openssl", "/bin/openssl" };
        for (const char* p : CANDIDATES) {
            if (::access(p, X_OK) == 0) {
                return p;
            }
        }

        return "";
    }

    /* Temporary directory removed on destruction. */
    struct TempDir {
        std::string path;

        TempDir() {
            char tmpl[] = "/tmp/sbox-tls-XXXXXX";
            char* p = ::mkdtemp(tmpl);
            path = p ? p : "";
        }

        ~TempDir() {
            if (!path.empty()) {
                CFile::removeTree(path);
            }
        }

        std::string operator/(const std::string& leaf) const { return CFile::join(path, leaf); }
    };

    /* A spawned child with optional stdin/stdout pipes. */
    struct Child {
        pid_t pid = -1;
        CFd pidfd;
        CStream in;     // --> Our end of the child's stdin.
        CStream out;    // --> Our end of the child's stdout+stderr.
    };

    /* Spawns argv with stdin/stdout/stderr piped (stdout and stderr merged). */
    inline int32_t Spawn(const std::vector<std::string>& argv, Child& child, const std::string& cwd = "") {
        CStream inParent, outParent;
        CFd inChild, outChild;
        if (CPipe::createForChild(inParent, inChild, false) != SBOX_OK
            || CPipe::createForChild(outParent, outChild, true) != SBOX_OK) {
            return -EIO;
        }

        std::vector<char*> args;
        for (const std::string& a : argv) {
            args.push_back(const_cast<char*>(a.c_str()));
        }
        args.push_back(nullptr);

        pid_t pid = ::fork();
        if (pid < 0) {
            return -errno;
        }

        if (pid == 0) {
            ::dup2(inChild.get(), 0);
            ::dup2(outChild.get(), 1);
            ::dup2(outChild.get(), 2);
            if (!cwd.empty() && ::chdir(cwd.c_str()) != 0) {
                ::_exit(126);
            }

            ::execv(args[0], args.data());
            ::_exit(127);
        }

        int fd = int(::syscall(SYS_pidfd_open, pid, 0));
        if (fd < 0) {
            ::kill(pid, SIGKILL);
            return -errno;
        }

        child.pid = pid;
        child.pidfd.reset(fd);
        child.in = std::move(inParent);
        child.out = std::move(outParent);
        return SBOX_OK;
    }

    /* Waits for a child to exit (pidfd readiness) and reaps it. */
    inline TTask<int32_t> Wait(Child& child, int64_t timeoutMs = 30000) {
        if (child.pid < 0) {
            co_return -ECHILD;
        }

        int32_t w = co_await CEventLoop::current()->waitFd(child.pidfd.get(), EFDE_READ, timeoutMs);
        if (w < 0) {
            co_return w;
        }

        int status = 0;
        pid_t r = ::waitpid(child.pid, &status, WNOHANG);
        child.pid = -1;
        child.pidfd.reset();
        if (r <= 0) {
            co_return -ECHILD;
        }

        co_return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    }

    /* Runs a command to completion, collecting its output. */
    inline TTask<int32_t> Run(const std::vector<std::string>& argv, std::string* output = nullptr, const std::string& cwd = "") {
        Child child;
        int32_t rc = Spawn(argv, child, cwd);
        if (rc != SBOX_OK) {
            co_return rc;
        }

        child.in.close();
        std::vector<uint8_t> all;
        co_await child.out.recvAll(all, size_t(16) << 20, 60000);
        if (output) {
            output->assign(all.begin(), all.end());
        }

        co_return co_await Wait(child);
    }

    /* Runs `openssl <args...>`; returns its exit status. */
    inline TTask<int32_t> Openssl(std::vector<std::string> args, std::string* output = nullptr, const std::string& cwd = "") {
        args.insert(args.begin(), OpensslPath());
        co_return co_await Run(args, output, cwd);
    }

    /**
     * Test PKI generated with the openssl CLI: a root CA, an intermediate CA, and leaf
     * certificates for "localhost" / 127.0.0.1 with different key types.
     */
    struct Pki {
        TempDir dir;
        bool ok = false;

        std::string file(const std::string& name) const { return dir / name; }

        /* Writes a small file into the PKI directory. */
        bool write(const std::string& name, const std::string& text) const {
            return CFile::writeAtomic(dir / name, text) == SBOX_OK;
        }

        /* Generates a private key of `type` ("ec256", "ec384", "rsa2048", "rsa1024", "ed25519"). */
        TTask<bool> key(const std::string& name, const std::string& type) {
            std::vector<std::string> args = { "genpkey", "-out", file(name) };
            // --> Built as a named vector: GCC 13 crashes on braced lists inside co_await.
            if (type == "ec256" || type == "ec384") {
                args.insert(args.end(), { "-algorithm", "EC", "-pkeyopt", type == "ec256" ? "ec_paramgen_curve:P-256" : "ec_paramgen_curve:P-384" });
            }
            else if (type == "rsa2048" || type == "rsa1024") {
                args.insert(args.end(), { "-algorithm", "RSA", "-pkeyopt", type == "rsa2048" ? "rsa_keygen_bits:2048" : "rsa_keygen_bits:1024" });
            }
            else {
                args.insert(args.end(), { "-algorithm", "ED25519" });
            }

            co_return co_await Openssl(args) == 0;
        }

        /* Writes an openssl config whose [v3] section holds `ext`. */
        bool config(const std::string& name, const std::string& ext) const {
            return write(name + ".cnf", "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\n[v3]\n" + ext);
        }

        /* Creates a self-signed root from key `name`.key with extensions `ext` (config text). */
        TTask<bool> selfSigned(const std::string& name, const std::string& subject, const std::string& ext, int32_t days = 30) {
            if (!config(name, ext)) {
                co_return false;
            }

            std::vector<std::string> args = { "req", "-x509", "-new", "-key", file(name + ".key"), "-out", file(name + ".pem"),
                                              "-subj", subject, "-days", std::to_string(days), "-sha256",
                                              "-config", file(name + ".cnf"), "-extensions", "v3" };
            co_return co_await Openssl(args) == 0;
        }

        /* Issues certificate `name` (key `name`.key) signed by `issuer` with extension text `ext`. */
        TTask<bool> issue(const std::string& name, const std::string& subject, const std::string& issuer,
                          const std::string& ext, const std::string& validity = "-days 30", const std::string& digest = "-sha256") {
            if (!config(name, ext)) {
                co_return false;
            }

            std::vector<std::string> csr = { "req", "-new", "-key", file(name + ".key"), "-out", file(name + ".csr"),
                                             "-subj", subject, "-config", file(name + ".cnf") };
            if (co_await Openssl(csr) != 0) {
                co_return false;
            }

            std::vector<std::string> args = { "x509", "-req", "-in", file(name + ".csr"), "-CA", file(issuer + ".pem"),
                                              "-CAkey", file(issuer + ".key"), "-set_serial", std::to_string(::rand() % 1000000 + 1000),
                                              "-out", file(name + ".pem"), "-extfile", file(name + ".cnf"), "-extensions", "v3" };

            auto split = [&](const std::string& s) {
                size_t start = 0;
                while (start < s.size()) {
                    size_t sp = s.find(' ', start);
                    if (sp == std::string::npos) {
                        sp = s.size();
                    }

                    if (sp > start) {
                        args.push_back(s.substr(start, sp - start));
                    }

                    start = sp + 1;
                }
            };

            split(validity);
            split(digest);
            co_return co_await Openssl(args) == 0;
        }

        /* Reads a generated file. */
        std::string read(const std::string& name) const {
            std::string out;
            CFile::readAll(file(name), out);
            return out;
        }

        /* Builds the default hierarchy: root -> inter -> leaf certificates. */
        TTask<bool> standard() {
            const std::string caExt = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                                      "subjectKeyIdentifier=hash\n";
            const std::string leafExt = "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                                        "extendedKeyUsage=serverAuth,clientAuth\n"
                                        "subjectAltName=DNS:localhost,DNS:*.test.example,IP:127.0.0.1\n";

            ok = co_await key("root.key", "ec384")
                && co_await selfSigned("root", "/CN=sbox test root", caExt)
                && co_await key("inter.key", "ec256")
                && co_await issue("inter", "/CN=sbox test intermediate", "root", caExt + "basicConstraints=critical,CA:TRUE,pathlen:0\n")
                && co_await key("ec.key", "ec256")
                && co_await issue("ec", "/CN=localhost", "inter", leafExt)
                && co_await key("ec384.key", "ec384")
                && co_await issue("ec384", "/CN=localhost", "inter", leafExt)
                && co_await key("rsa.key", "rsa2048")
                && co_await issue("rsa", "/CN=localhost", "inter", leafExt)
                && co_await key("ed.key", "ed25519")
                && co_await issue("ed", "/CN=localhost", "inter", leafExt)
                && co_await key("client.key", "ec256")
                && co_await issue("client", "/CN=sbox client", "inter",
                                  "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")
                && co_await key("clientrsa.key", "rsa2048")
                && co_await issue("clientrsa", "/CN=sbox rsa client", "inter",
                                  "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n");

            if (ok) {
                // --> Chain files as a server presents them: leaf then intermediate.
                for (const char* leaf : { "ec", "ec384", "rsa", "ed", "client", "clientrsa" }) {
                    ok = ok && write(std::string(leaf) + "-chain.pem", read(std::string(leaf) + ".pem") + read("inter.pem"));
                }
            }

            co_return ok;
        }
    };

    /**
     * An `openssl s_server` child listening on 127.0.0.1 (port chosen by the kernel).
     */
    struct Server {
        Child child;
        uint16_t port = 0;
        std::string output;     // --> Everything the server printed so far.
        bool reading = false;

        /* Starts s_server with extra arguments and waits for its ACCEPT line. */
        TTask<bool> start(std::vector<std::string> args) {
            std::vector<std::string> argv = { OpensslPath(), "s_server", "-accept", "127.0.0.1:0" };
            argv.insert(argv.end(), args.begin(), args.end());

            if (Spawn(argv, child) != SBOX_OK) {
                co_return false;
            }

            int64_t until = CEventLoop::nowMs() + 15000;
            while (CEventLoop::nowMs() < until) {
                size_t at = output.find("ACCEPT");
                size_t nl = at == std::string::npos ? std::string::npos : output.find('\n', at);
                if (nl != std::string::npos) {
                    size_t colon = output.rfind(':', nl);
                    port = uint16_t(std::atoi(output.c_str() + colon + 1));
                    output.erase(0, nl + 1);
                    break;
                }

                uint8_t buf[4096];
                SIoResult r = co_await child.out.recv(SByteSpan(buf, sizeof(buf)), until - CEventLoop::nowMs());
                if (!r.ok() || r.bytes == 0) {
                    break;
                }

                output.append(reinterpret_cast<char*>(buf), r.bytes);
            }

            if (port == 0) {
                co_return false;
            }

            // --> Keep draining the server's output so it never blocks on a full pipe.
            reading = true;
            CEventLoop::current()->spawn([](Server* self) -> TTask<void> {
                uint8_t buf[16384];
                while (true) {
                    SIoResult r = co_await self->child.out.recv(SByteSpan(buf, sizeof(buf)));
                    if (!r.ok() || r.bytes == 0) {
                        break;
                    }

                    self->output.append(reinterpret_cast<char*>(buf), r.bytes);
                }

                self->reading = false;
            }(this));

            co_return true;
        }

        /* Waits until the server output contains `text`. */
        TTask<bool> waitOutput(const std::string& text, int64_t timeoutMs = 10000) {
            int64_t until = CEventLoop::nowMs() + timeoutMs;
            while (output.find(text) == std::string::npos) {
                if (CEventLoop::nowMs() > until || !reading) {
                    co_return output.find(text) != std::string::npos;
                }

                co_await CEventLoop::current()->sleepFor(10);
            }

            co_return true;
        }

        /* Types a line on the server's stdin (s_server commands such as "K"). */
        TTask<bool> type(const std::string& line) {
            SIoResult r = co_await child.in.send(BytesOf(line));
            co_return r.ok();
        }

        /* Connects a TCP socket to the server. */
        TTask<int32_t> connect(IStreamPtr& out) {
            SEndpoint ep;
            SEndpoint::fromIp("127.0.0.1", port, ep);
            auto sock = std::make_shared<CSocket>();
            int32_t rc = co_await sock->connect(ep, 5000);
            if (rc == SBOX_OK) {
                out = sock;
            }

            co_return rc;
        }

        /* Kills the server and reaps it. */
        TTask<void> stop() {
            if (child.pid > 0) {
                ::kill(child.pid, SIGKILL);
                co_await Wait(child, 10000);
            }

            // --> Let the drain task observe EOF before the frame goes away.
            for (int32_t i = 0; i < 100 && reading; ++i) {
                co_await CEventLoop::current()->sleepFor(5);
            }

            child.out.close();
            child.in.close();
        }
    };

}

#endif
