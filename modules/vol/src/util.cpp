#include "util.hpp"

#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/random.h>
#include <unistd.h>

namespace sbox {
namespace vol {

    /* Waits for the lock on `path`. */
    TTask<int32_t> StoreLock::lock(std::string path, int64_t timeoutMs) {
        int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) {
            co_return -errno;
        }

        CFd held(fd);
        int64_t deadline = timeoutMs < 0 ? -1 : CEventLoop::nowMs() + timeoutMs;
        int64_t delay = 1;

        for (;;) {
            if (::flock(held.get(), LOCK_EX | LOCK_NB) == 0) {
                _fd = std::move(held);
                co_return SBOX_OK;
            }

            if (errno == EINTR) {
                continue;
            }

            if (errno != EWOULDBLOCK) {
                co_return -errno;
            }

            if (deadline >= 0 && CEventLoop::nowMs() >= deadline) {
                co_return -ETIMEDOUT;
            }

            // --> Exponential back-off up to 25 ms keeps contention cheap without blocking the loop.
            CEventLoop* loop = CEventLoop::current();
            if (loop == nullptr) {
                co_return -EWOULDBLOCK;
            }

            co_await loop->sleepFor(delay);
            delay = delay < 25 ? delay * 2 : 25;
        }
    }

    /* Returns the current UTC time in RFC 3339 form. */
    std::string NowRfc3339() {
        std::time_t now = std::time(nullptr);
        std::tm tm{};
        ::gmtime_r(&now, &tm);

        char buffer[32];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return buffer;
    }

    /* Returns the kernel boot id. */
    std::string BootId() {
        std::string text;
        if (CFile::readAll("/proc/sys/kernel/random/boot_id", text, 4096) != SBOX_OK) {
            return std::string();
        }

        while (!text.empty() && (text.back() == '\n' || text.back() == ' ')) {
            text.pop_back();
        }

        return text;
    }

    /* Fills `out` with random bytes. */
    int32_t RandomBytes(uint8_t* out, size_t size) noexcept {
        size_t done = 0;
        while (done < size) {
            ssize_t n = ::getrandom(out + done, size - done, 0);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }

                return -errno;
            }

            done += size_t(n);
        }

        return SBOX_OK;
    }

    /* Returns random bytes as lowercase hex. */
    std::string RandomHex(size_t size) {
        static const char DIGITS[] = "0123456789abcdef";
        std::vector<uint8_t> bytes(size);
        if (RandomBytes(bytes.data(), size) != SBOX_OK) {
            // --> getrandom cannot really fail for small requests; keep names unique anyway.
            uint64_t seed = uint64_t(CEventLoop::nowMs()) ^ (uint64_t(::getpid()) << 32);
            for (size_t i = 0; i < size; ++i) {
                seed = seed * 6364136223846793005ull + 1442695040888963407ull;
                bytes[i] = uint8_t(seed >> 56);
            }
        }

        std::string out;
        out.reserve(size * 2);
        for (uint8_t b : bytes) {
            out.push_back(DIGITS[b >> 4]);
            out.push_back(DIGITS[b & 15]);
        }

        return out;
    }

    /* Converts a JSON object into a string map. */
    TStringMap MapFromJson(const CJson& json) {
        TStringMap out;
        if (!json.isObject()) {
            return out;
        }

        for (size_t i = 0; i < json.size(); ++i) {
            const CJson& v = json.at(i);
            out[json.keyAt(i)] = v.isString() ? v.asString() : (v.isNull() ? std::string() : v.dump());
        }

        return out;
    }

    /* Converts a string map into a JSON object. */
    CJson MapToJson(const TStringMap& map) {
        CJson out = CJson::object();
        for (const auto& kv : map) {
            out.set(kv.first, CJson(kv.second));
        }

        return out;
    }

    /* Reads and parses a JSON file. */
    int32_t ReadJsonFile(const std::string& path, CJson& out) {
        std::string text;
        int32_t rc = CFile::readAll(path, text, size_t(4) << 20);
        if (rc != SBOX_OK) {
            return rc;
        }

        return CJson::parse(text, out);
    }

    /* Returns strerror text for a negated errno. */
    std::string ErrorText(int32_t code) {
        char buffer[128];
        int e = code < 0 ? -code : code;
        const char* text = ::strerror_r(e, buffer, sizeof(buffer));
        return text ? std::string(text) : std::string("error ") + std::to_string(e);
    }

}
}
