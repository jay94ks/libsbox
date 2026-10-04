// sbox-cni: CNI 1.0 plugin (ADD/DEL/CHECK/VERSION) backed by libsbox's network drivers and IPAM.
// The protocol logic lives in sbox::net::RunCni; this file only adapts stdin/stdout/env.
#include <sbox/core/eventloop.hpp>
#include <sbox/net/cni.hpp>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

using namespace sbox;

namespace {

    /* Reads stdin until EOF (the runtime closes it after writing the configuration). */
    bool readStdin(std::string& out) {
        char buffer[8192];
        while (true) {
            ssize_t n = ::read(STDIN_FILENO, buffer, sizeof(buffer));
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }

                return false;
            }

            if (n == 0) {
                return true;
            }

            out.append(buffer, size_t(n));
            if (out.size() > (size_t(16) << 20)) {
                return false;
            }
        }
    }

}

int main() {
    net::SCniRequest request = net::CniRequestFromEnvironment();

    // --> VERSION may come without a configuration on stdin.
    if (request.command != "VERSION" && !readStdin(request.config)) {
        std::fputs("{\"cniVersion\":\"1.0.0\",\"code\":5,\"msg\":\"cannot read stdin\"}\n", stdout);
        return 1;
    }

    if (request.command == "VERSION" && !::isatty(STDIN_FILENO)) {
        readStdin(request.config);
    }

    std::string output;
    CEventLoop loop;
    int32_t code = loop.run(net::RunCni(std::move(request), output));

    if (!output.empty()) {
        std::fwrite(output.data(), 1, output.size(), stdout);
        std::fputc('\n', stdout);
    }

    std::fflush(stdout);
    return code;
}
