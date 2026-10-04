#include <sbox/vol/local.hpp>

#include <sbox/archive/extract.hpp>
#include <sbox/archive/tree.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/socket.hpp>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <netinet/in.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef STATX_ATTR_MOUNT_ROOT
#define STATX_ATTR_MOUNT_ROOT 0x00002000
#endif

namespace sbox {
namespace vol {

    namespace {

        /**
         * One word of a mount option string and what it does to the flags.
         */
        struct MountFlagWord {
            const char* name;
            bool clear;             // --> Clears `flag` instead of setting it.
            uint64_t flag;
        };

        // --> Same table as Docker's pkg/mount (mount.ParseOptions), including propagation words.
        const MountFlagWord MOUNT_WORDS[] = {
            { "defaults", false, 0 },
            { "ro", false, MS_RDONLY },
            { "rw", true, MS_RDONLY },
            { "suid", true, MS_NOSUID },
            { "nosuid", false, MS_NOSUID },
            { "dev", true, MS_NODEV },
            { "nodev", false, MS_NODEV },
            { "exec", true, MS_NOEXEC },
            { "noexec", false, MS_NOEXEC },
            { "sync", false, MS_SYNCHRONOUS },
            { "async", true, MS_SYNCHRONOUS },
            { "dirsync", false, MS_DIRSYNC },
            { "remount", false, MS_REMOUNT },
            { "mand", false, MS_MANDLOCK },
            { "nomand", true, MS_MANDLOCK },
            { "atime", true, MS_NOATIME },
            { "noatime", false, MS_NOATIME },
            { "diratime", true, MS_NODIRATIME },
            { "nodiratime", false, MS_NODIRATIME },
            { "bind", false, MS_BIND },
            { "rbind", false, MS_BIND | MS_REC },
            { "unbindable", false, MS_UNBINDABLE },
            { "runbindable", false, MS_UNBINDABLE | MS_REC },
            { "private", false, MS_PRIVATE },
            { "rprivate", false, MS_PRIVATE | MS_REC },
            { "shared", false, MS_SHARED },
            { "rshared", false, MS_SHARED | MS_REC },
            { "slave", false, MS_SLAVE },
            { "rslave", false, MS_SLAVE | MS_REC },
            { "relatime", false, MS_RELATIME },
            { "norelatime", true, MS_RELATIME },
            { "strictatime", false, MS_STRICTATIME },
            { "nostrictatime", true, MS_STRICTATIME },
        };

        constexpr uint64_t PROPAGATION_FLAGS = MS_UNBINDABLE | MS_PRIVATE | MS_SHARED | MS_SLAVE;

        /* Returns true for a numeric IPv4 or IPv6 address. */
        bool isNumericIp(const std::string& text) {
            in6_addr a6{};
            in_addr a4{};
            return ::inet_pton(AF_INET, text.c_str(), &a4) == 1 || ::inet_pton(AF_INET6, text.c_str(), &a6) == 1;
        }

        /* Splits on commas. */
        std::vector<std::string> splitComma(std::string_view text) {
            std::vector<std::string> out;
            size_t start = 0;
            while (start <= text.size()) {
                size_t comma = text.find(',', start);
                if (comma == std::string_view::npos) {
                    comma = text.size();
                }

                out.emplace_back(text.substr(start, comma - start));
                start = comma + 1;
            }

            return out;
        }

        /* Resolves a host name to a numeric address string (first result). */
        TTask<int32_t> resolveHost(std::string host, std::string& out) {
            std::vector<SEndpoint> eps;
            int32_t rc = co_await ResolveEndpoints(host, 0, eps);
            if (rc < 0) {
                co_return rc;
            }

            // --> Prefer IPv4 like the NFS mount helpers do; fall back to the first IPv6 address.
            for (int pass = 0; pass < 2; ++pass) {
                for (const SEndpoint& ep : eps) {
                    char text[INET6_ADDRSTRLEN] = {};
                    if (pass == 0 && ep.family() == AF_INET) {
                        const sockaddr_in* sin = reinterpret_cast<const sockaddr_in*>(&ep.storage);
                        ::inet_ntop(AF_INET, &sin->sin_addr, text, sizeof(text));
                        out = text;
                        co_return SBOX_OK;
                    }

                    if (pass == 1 && ep.family() == AF_INET6) {
                        const sockaddr_in6* sin6 = reinterpret_cast<const sockaddr_in6*>(&ep.storage);
                        ::inet_ntop(AF_INET6, &sin6->sin6_addr, text, sizeof(text));
                        out = text;
                        co_return SBOX_OK;
                    }
                }
            }

            co_return -EHOSTUNREACH;
        }

        /* Calls mount(2) with optional strings. */
        int32_t doMount(const std::string& source, const std::string& target, const std::string& type,
                        uint64_t flags, const std::string& data) noexcept {
            int rc = ::mount(source.empty() ? nullptr : source.c_str(), target.c_str(),
                             type.empty() ? nullptr : type.c_str(), (unsigned long)flags,
                             data.empty() ? nullptr : data.c_str());
            return rc == 0 ? SBOX_OK : -errno;
        }

    }

    /* Parses a size the way go-units RAMInBytes does. */
    int32_t ParseSize(std::string_view text, uint64_t& out) {
        size_t i = 0;
        while (i < text.size() && (text[i] == ' ')) {
            ++i;
        }

        size_t numStart = i;
        bool dot = false;
        while (i < text.size() && ((text[i] >= '0' && text[i] <= '9') || (text[i] == '.' && !dot))) {
            dot = dot || text[i] == '.';
            ++i;
        }

        if (i == numStart || (i == numStart + 1 && text[numStart] == '.')) {
            return -EINVAL;
        }

        std::string number(text.substr(numStart, i - numStart));
        std::string unit;
        for (; i < text.size(); ++i) {
            char c = text[i];
            if (c == ' ') {
                continue;
            }

            unit.push_back(char(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
        }

        // --> go-units: ^(\d+(\.\d+)*) ?([kKmMgGtTpP])?[iI]?[bB]?$
        uint64_t mul = 1;
        std::string rest = unit;
        static const char UNITS[] = "kmgtp";
        const char* p = unit.empty() ? nullptr : std::strchr(UNITS, unit[0]);
        if (p != nullptr && *p != '\0') {
            rest = unit.substr(1);
            for (const char* q = UNITS; q <= p; ++q) {
                mul <<= 10;
            }
        }

        if (!rest.empty() && rest != "b" && rest != "i" && rest != "ib") {
            return -EINVAL;
        }

        // --> Integer path keeps exact values for whole numbers; fractions go through long double.
        if (!dot) {
            uint64_t value = 0;
            for (char c : number) {
                uint64_t d = uint64_t(c - '0');
                if (value > (UINT64_MAX - d) / 10) {
                    return -ERANGE;
                }

                value = value * 10 + d;
            }

            if (mul != 0 && value > UINT64_MAX / mul) {
                return -ERANGE;
            }

            out = value * mul;
            return SBOX_OK;
        }

        long double v = std::strtold(number.c_str(), nullptr) * (long double)mul;
        if (v >= 18446744073709551615.0L) {
            return -ERANGE;
        }

        out = uint64_t(v);
        return SBOX_OK;
    }

    /* Formats a byte count with the largest exact binary unit. */
    std::string FormatSize(uint64_t bytes) {
        static const char UNITS[] = { 'p', 't', 'g', 'm', 'k' };
        static const int SHIFTS[] = { 50, 40, 30, 20, 10 };
        if (bytes != 0) {
            for (size_t i = 0; i < sizeof(SHIFTS) / sizeof(SHIFTS[0]); ++i) {
                uint64_t unit = uint64_t(1) << SHIFTS[i];
                if (bytes % unit == 0) {
                    return std::to_string(bytes / unit) + UNITS[i];
                }
            }
        }

        return std::to_string(bytes);
    }

    /* Splits mount options into MS_* flags and filesystem data. */
    int32_t ParseMountOptions(std::string_view options, uint64_t& flags, std::string& data) {
        flags = 0;
        data.clear();
        if (options.empty()) {
            return SBOX_OK;
        }

        for (const std::string& word : splitComma(options)) {
            if (word.empty()) {
                return -EINVAL;
            }

            bool known = false;
            for (const MountFlagWord& w : MOUNT_WORDS) {
                if (word == w.name) {
                    flags = w.clear ? (flags & ~w.flag) : (flags | w.flag);
                    known = true;
                    break;
                }
            }

            if (!known) {
                if (!data.empty()) {
                    data.push_back(',');
                }

                data += word;
            }
        }

        return SBOX_OK;
    }

    /* Validates and parses local driver options. */
    int32_t ParseLocalOptions(const TStringMap& options, SLocalOptions& out, std::string* error) {
        auto bad = [&](std::string message) -> int32_t {
            if (error != nullptr) {
                *error = std::move(message);
            }

            return -EINVAL;
        };

        out = SLocalOptions();
        for (const auto& kv : options) {
            if (kv.first != "type" && kv.first != "device" && kv.first != "o" && kv.first != "size") {
                return bad("invalid option: \"" + kv.first + "\"");
            }
        }

        // --> Docker's mandatoryOpts: device needs type, type needs device, o needs both.
        auto has = [&](const char* key) { return options.find(key) != options.end(); };
        if (has("device") && !has("type")) {
            return bad("missing required option: \"type\"");
        }

        if (has("type") && !has("device")) {
            return bad("missing required option: \"device\"");
        }

        if (has("o") && (!has("type") || !has("device"))) {
            return bad(std::string("missing required option: \"") + (has("type") ? "device" : "type") + "\"");
        }

        if (has("size")) {
            int32_t rc = ParseSize(options.at("size"), out.quotaBytes);
            if (rc < 0) {
                return bad("invalid size: \"" + options.at("size") + "\"");
            }

            if (has("type")) {
                return bad("size option only applies to volumes without type (use o=size= for tmpfs)");
            }
        }

        if (!has("type")) {
            out.kind = ELK_DIRECTORY;
            return SBOX_OK;
        }

        out.type = options.at("type");
        out.device = options.at("device");
        out.o = has("o") ? options.at("o") : std::string();
        if (out.type.empty()) {
            return bad("type must not be empty");
        }

        if (out.device.empty()) {
            return bad("device must not be empty");
        }

        if (ParseMountOptions(out.o, out.flags, out.data) < 0) {
            return bad("invalid mount options: \"" + out.o + "\"");
        }

        if (out.flags & MS_REMOUNT) {
            return bad("remount is not a valid volume mount option");
        }

        if (out.flags & MS_BIND) {
            out.kind = ELK_BIND;
            if (out.device[0] != '/') {
                return bad("bind device must be an absolute host path: \"" + out.device + "\"");
            }
        } else if (out.type == "tmpfs") {
            out.kind = ELK_TMPFS;
        } else if (out.type == "nfs" || out.type == "nfs4") {
            out.kind = ELK_NFS;
            if (out.device.find(':') == std::string::npos) {
                return bad("nfs device must be \"host:/export\" or \":/export\" with o=addr=: \"" + out.device + "\"");
            }
        } else if (out.type == "none") {
            return bad("type none needs o=bind (or rbind)");
        } else {
            out.kind = ELK_DEVICE;
        }

        return SBOX_OK;
    }

    /* Mounts a volume's backing filesystem onto `target`. */
    TTask<int32_t> MountLocalVolume(SLocalOptions options, std::string target) {
        uint64_t prop = options.flags & (PROPAGATION_FLAGS | MS_REC);
        uint64_t flags = options.flags & ~(PROPAGATION_FLAGS | MS_REC);
        if (!(prop & PROPAGATION_FLAGS)) {
            prop = 0;
        }

        int32_t rc = SBOX_OK;
        switch (options.kind) {
            case ELK_TMPFS:
            case ELK_DEVICE:
                rc = doMount(options.device, target, options.type, flags, options.data);
                break;

            case ELK_NFS: {
                // --> The kernel NFS client takes only numeric addresses: resolve addr= (or the host of
                // "host:/export") here, the way mount.nfs and Docker's local driver do.
                std::vector<std::string> words = splitComma(options.data);
                if (options.data.empty()) {
                    words.clear();
                }

                bool haveAddr = false;
                for (std::string& w : words) {
                    if (w.compare(0, 5, "addr=") == 0) {
                        haveAddr = true;
                        std::string host = w.substr(5);
                        if (!isNumericIp(host)) {
                            std::string numeric;
                            rc = co_await resolveHost(host, numeric);
                            if (rc < 0) {
                                co_return rc;
                            }

                            w = "addr=" + numeric;
                        }
                    }
                }

                if (!haveAddr) {
                    std::string host = options.device.substr(0, options.device.find(':'));
                    if (!host.empty() && host.front() == '[' && host.back() == ']') {
                        host = host.substr(1, host.size() - 2);
                    }

                    if (host.empty()) {
                        co_return -EDESTADDRREQ;
                    }

                    std::string numeric = host;
                    if (!isNumericIp(host)) {
                        rc = co_await resolveHost(host, numeric);
                        if (rc < 0) {
                            co_return rc;
                        }
                    }

                    words.push_back("addr=" + numeric);
                }

                std::string data;
                for (const std::string& w : words) {
                    if (!data.empty()) {
                        data.push_back(',');
                    }

                    data += w;
                }

                rc = doMount(options.device, target, options.type, flags, data);
                break;
            }

            case ELK_BIND: {
                rc = doMount(options.device, target, std::string(), MS_BIND | (flags & MS_REC), std::string());
                if (rc < 0) {
                    break;
                }

                // --> MS_BIND ignores the other flags: apply them with a bind remount.
                uint64_t extra = flags & ~(MS_BIND | MS_REC);
                if (extra != 0) {
                    rc = doMount(std::string(), target, std::string(), MS_REMOUNT | MS_BIND | extra, std::string());
                    if (rc < 0) {
                        ::umount2(target.c_str(), MNT_DETACH);
                    }
                }

                break;
            }

            default:
                co_return -EINVAL;
        }

        if (rc == SBOX_OK && prop != 0) {
            rc = doMount(std::string(), target, std::string(), prop, std::string());
            if (rc < 0) {
                ::umount2(target.c_str(), MNT_DETACH);
            }
        }

        co_return rc;
    }

    /* Unmounts a volume mount. */
    int32_t UnmountLocalVolume(const std::string& target, bool lazy) noexcept {
        if (::umount2(target.c_str(), UMOUNT_NOFOLLOW) == 0) {
            return SBOX_OK;
        }

        int e = errno;
        if (e == EINVAL || e == ENOENT) {
            return SBOX_OK;
        }

        if (e == EBUSY && lazy) {
            if (::umount2(target.c_str(), MNT_DETACH | UMOUNT_NOFOLLOW) == 0) {
                return SBOX_OK;
            }

            return -errno;
        }

        return -e;
    }

    /* Returns true when `path` is the root of a mount. */
    bool IsMountPoint(const std::string& path) noexcept {
        struct statx sx{};
        if (::statx(AT_FDCWD, path.c_str(), AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &sx) == 0 &&
            (sx.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT)) {
            return (sx.stx_attributes & STATX_ATTR_MOUNT_ROOT) != 0;
        }

        // --> Older kernels: a different device than the parent means a mount root (misses
        // same-filesystem binds, which the statx path catches on 5.8+).
        struct stat self{}, parent{};
        if (::lstat(path.c_str(), &self) != 0 || ::lstat((path + "/..").c_str(), &parent) != 0) {
            return false;
        }

        return self.st_dev != parent.st_dev || self.st_ino == parent.st_ino;
    }

    /* Returns true when the directory has no entries. */
    bool IsDirectoryEmpty(const std::string& path) noexcept {
        DIR* dir = ::opendir(path.c_str());
        if (dir == nullptr) {
            return errno == ENOENT;
        }

        bool empty = true;
        while (dirent* de = ::readdir(dir)) {
            if (std::strcmp(de->d_name, ".") != 0 && std::strcmp(de->d_name, "..") != 0) {
                empty = false;
                break;
            }
        }

        ::closedir(dir);
        return empty;
    }

    /* Resolves `path` inside `rootfs` and opens it O_PATH. */
    int32_t OpenInRoot(const std::string& rootfs, const std::string& path) noexcept {
        int root = ::open(rootfs.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (root < 0) {
            return -errno;
        }

        CFd rootFd(root);
        std::string rel = path;
        while (!rel.empty() && rel.front() == '/') {
            rel.erase(rel.begin());
        }

        if (rel.empty()) {
            rel = ".";
        }

        open_how how{};
        how.flags = O_PATH | O_CLOEXEC;
        how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;
        long fd = ::syscall(SYS_openat2, rootFd.get(), rel.c_str(), &how, sizeof(how));
        if (fd < 0) {
            return -errno;
        }

        return int32_t(fd);
    }

    /* Copies `source` into an empty `target`. */
    int32_t CopyUpIfEmpty(const std::string& source, const std::string& target) {
        struct stat st{};
        if (::stat(source.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
            return 0;
        }

        if (!IsDirectoryEmpty(target)) {
            return 0;
        }

        if (IsDirectoryEmpty(source)) {
            // --> Docker still copies the directory's ownership and mode for an empty source.
            if (::chown(target.c_str(), st.st_uid, st.st_gid) != 0 && ::geteuid() == 0) {
                return -errno;
            }

            if (::chmod(target.c_str(), st.st_mode & 07777) != 0) {
                return -errno;
            }

            return 1;
        }

        archive::STreeOptions tree;
        tree.includeRoot = true;
        tree.xattrs = true;
        tree.preciseTimes = true;

        archive::SExtractOptions extract;
        extract.ownership = archive::EOWN_AUTO;
        extract.xattrs = true;

        archive::CTreeTarSource producer(source, tree);
        archive::CExtractor extractor(extract);
        int32_t rc = extractor.open(target);
        if (rc < 0) {
            return rc;
        }

        archive::CTarSink sink(extractor);
        rc = archive::Pump(producer, sink);
        return rc < 0 ? rc : 1;
    }

}
}
