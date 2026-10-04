#include <sbox/vol/mount.hpp>

#include "util.hpp"

#include <sbox/core/fd.hpp>
#include <sbox/core/file.hpp>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

namespace sbox {
namespace vol {

    namespace {

        const char* const PROPAGATIONS[] = { "shared", "rshared", "slave", "rslave", "private", "rprivate" };
        const char* const CONSISTENCIES[] = { "consistent", "cached", "delegated" };

        /* Returns true when `word` is in the list. */
        template<size_t N>
        bool oneOf(std::string_view word, const char* const (&list)[N]) {
            for (const char* w : list) {
                if (word == w) {
                    return true;
                }
            }

            return false;
        }

        /* Records an error message and returns -EINVAL. */
        int32_t invalid(std::string* error, std::string message) {
            if (error != nullptr) {
                *error = std::move(message);
            }

            return -EINVAL;
        }

        /* Splits on a separator. */
        std::vector<std::string> split(std::string_view text, char sep) {
            std::vector<std::string> out;
            size_t start = 0;
            for (;;) {
                size_t pos = text.find(sep, start);
                if (pos == std::string_view::npos) {
                    out.emplace_back(text.substr(start));
                    return out;
                }

                out.emplace_back(text.substr(start, pos - start));
                start = pos + 1;
            }
        }

        /* Splits a CSV record (RFC 4180 quoting, like Go's encoding/csv used by the docker CLI). */
        int32_t splitCsv(std::string_view text, std::vector<std::string>& out) {
            out.clear();
            size_t i = 0;
            for (;;) {
                std::string field;
                if (i < text.size() && text[i] == '"') {
                    ++i;
                    for (;;) {
                        if (i >= text.size()) {
                            return -EINVAL;
                        }

                        if (text[i] == '"') {
                            if (i + 1 < text.size() && text[i + 1] == '"') {
                                field.push_back('"');
                                i += 2;
                                continue;
                            }

                            ++i;
                            break;
                        }

                        field.push_back(text[i++]);
                    }

                    if (i < text.size() && text[i] != ',') {
                        return -EINVAL;
                    }
                } else {
                    while (i < text.size() && text[i] != ',') {
                        field.push_back(text[i++]);
                    }
                }

                out.push_back(std::move(field));
                if (i >= text.size()) {
                    return SBOX_OK;
                }

                ++i;
            }
        }

        /* Parses a boolean like Go's strconv.ParseBool. */
        bool parseBool(std::string_view text, bool& out) {
            static const char* const TRUE_WORDS[] = { "1", "t", "T", "true", "TRUE", "True" };
            static const char* const FALSE_WORDS[] = { "0", "f", "F", "false", "FALSE", "False" };
            if (oneOf(text, TRUE_WORDS)) {
                out = true;
                return true;
            }

            if (oneOf(text, FALSE_WORDS)) {
                out = false;
                return true;
            }

            return false;
        }

        /* Cleans and checks a container target path. */
        int32_t cleanTarget(std::string_view target, std::string& out, std::string* error) {
            if (target.empty() || target[0] != '/') {
                return invalid(error, "invalid mount config: mount path must be absolute: \"" + std::string(target) + "\"");
            }

            if (CleanAbsolutePath(target, out) < 0) {
                return invalid(error, "invalid mount path: \"" + std::string(target) + "\"");
            }

            if (out == "/") {
                return invalid(error, "invalid mount config: destination can't be '/'");
            }

            return SBOX_OK;
        }

        /* Cleans a relative path inside a volume ("a/./b" -> "a/b"); rejects ".." and absolute paths. */
        int32_t cleanSubpath(std::string_view path, std::string& out) {
            out.clear();
            if (path.empty() || path[0] == '/') {
                return -EINVAL;
            }

            for (const std::string& part : split(path, '/')) {
                if (part.empty() || part == ".") {
                    continue;
                }

                if (part == ".." || part.find('\0') != std::string::npos) {
                    return -EINVAL;
                }

                out += (out.empty() ? "" : "/") + part;
            }

            return out.empty() ? -EINVAL : SBOX_OK;
        }

    }

    /* Cleans an absolute path lexically. */
    int32_t CleanAbsolutePath(std::string_view path, std::string& out) {
        if (path.empty() || path[0] != '/' || path.find('\0') != std::string_view::npos) {
            return -EINVAL;
        }

        std::vector<std::string> parts;
        for (const std::string& part : split(path, '/')) {
            if (part.empty() || part == ".") {
                continue;
            }

            if (part == "..") {
                if (parts.empty()) {
                    return -EINVAL;
                }

                parts.pop_back();
                continue;
            }

            parts.push_back(part);
        }

        out = "/";
        for (size_t i = 0; i < parts.size(); ++i) {
            out += (i == 0 ? "" : "/") + parts[i];
        }

        return SBOX_OK;
    }

    /* Parses -v / --volume. */
    int32_t ParseVolumeFlag(std::string_view spec, SMountRequest& out, std::string* error) {
        out = SMountRequest();
        std::string where = "invalid volume specification: '" + std::string(spec) + "'";
        if (spec.empty()) {
            return invalid(error, where);
        }

        std::vector<std::string> parts = split(spec, ':');
        std::string source, target, mode;
        auto isModeText = [](const std::string& text) {
            for (const std::string& w : split(text, ',')) {
                if (!(w == "ro" || w == "rw" || w == "z" || w == "Z" || w == "nocopy" || oneOf(w, PROPAGATIONS) ||
                      oneOf(w, CONSISTENCIES))) {
                    return false;
                }
            }

            return true;
        };

        switch (parts.size()) {
            case 1:
                target = parts[0];
                break;

            case 2:
                // --> "/foo:rw" is a destination with a mode, which volumes cannot have.
                if (isModeText(parts[1])) {
                    return invalid(error, where);
                }

                source = parts[0];
                target = parts[1];
                break;

            case 3:
                source = parts[0];
                target = parts[1];
                mode = parts[2];
                break;

            default:
                return invalid(error, where);
        }

        if (parts.size() > 1 && source.empty()) {
            return invalid(error, where);
        }

        int32_t rc = cleanTarget(target, out.target, error);
        if (rc < 0) {
            return rc;
        }

        if (source.empty()) {
            out.type = EMT_VOLUME;
        } else if (source[0] == '/') {
            out.type = EMT_BIND;
            out.createHostPath = true;
            if (CleanAbsolutePath(source, out.source) < 0) {
                return invalid(error, where + ": invalid host path");
            }
        } else if (source[0] == '.' || source.find('/') != std::string::npos) {
            return invalid(error, where + ": bind source must be an absolute path");
        } else if (!IsValidVolumeName(source)) {
            return invalid(error, where + ": \"" + source + "\" includes invalid characters for a local volume name");
        } else {
            out.type = EMT_VOLUME;
            out.source = source;
        }

        if (mode.empty()) {
            return SBOX_OK;
        }

        bool rwSeen = false, labelSeen = false, propSeen = false, copySeen = false, consSeen = false;
        for (const std::string& w : split(mode, ',')) {
            bool dup = false;
            if (w == "ro" || w == "rw") {
                dup = rwSeen;
                rwSeen = true;
                out.readOnly = w == "ro";
            } else if (w == "z" || w == "Z") {
                dup = labelSeen;
                labelSeen = true;
                out.selinuxLabel = w;
            } else if (oneOf(w, PROPAGATIONS)) {
                dup = propSeen;
                propSeen = true;
                out.propagation = w;
            } else if (w == "nocopy") {
                dup = copySeen;
                copySeen = true;
                out.noCopy = true;
            } else if (oneOf(w, CONSISTENCIES)) {
                dup = consSeen;
                consSeen = true;
                out.consistency = w;
            } else {
                return invalid(error, "invalid mode: " + w);
            }

            if (dup) {
                return invalid(error, "invalid mode: " + mode);
            }
        }

        if (out.noCopy && out.type != EMT_VOLUME) {
            return invalid(error, "invalid mode: nocopy is only valid for volumes");
        }

        if (propSeen && out.type != EMT_BIND) {
            return invalid(error, "invalid mode: propagation is only valid for bind mounts");
        }

        return SBOX_OK;
    }

    /* Parses --mount. */
    int32_t ParseMountFlag(std::string_view spec, SMountRequest& out, std::string* error) {
        out = SMountRequest();
        std::vector<std::string> fields;
        if (splitCsv(spec, fields) < 0) {
            return invalid(error, "invalid mount specification (bad quoting): " + std::string(spec));
        }

        std::string typeText = "volume";
        std::string source, target;
        bool sawBind = false, sawVolume = false, sawTmpfs = false;
        for (const std::string& field : fields) {
            size_t eq = field.find('=');
            std::string key = field.substr(0, eq);
            for (char& c : key) {
                c = char(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
            }

            if (eq == std::string::npos) {
                // --> Bare words are booleans set to true.
                if (key == "readonly" || key == "ro") {
                    out.readOnly = true;
                } else if (key == "volume-nocopy") {
                    out.noCopy = true;
                    sawVolume = true;
                } else if (key == "bind-nonrecursive") {
                    out.nonRecursive = true;
                    sawBind = true;
                } else {
                    return invalid(error, "invalid field '" + field + "' must be a key=value pair");
                }

                continue;
            }

            std::string value = field.substr(eq + 1);
            bool flag = false;
            if (key == "type") {
                typeText = value;
            } else if (key == "source" || key == "src") {
                source = value;
            } else if (key == "target" || key == "dst" || key == "destination") {
                target = value;
            } else if (key == "readonly" || key == "ro") {
                if (!parseBool(value, flag)) {
                    return invalid(error, "invalid value for " + key + ": " + value);
                }

                out.readOnly = flag;
            } else if (key == "consistency") {
                if (!oneOf(value, CONSISTENCIES) && value != "default") {
                    return invalid(error, "invalid consistency: " + value);
                }

                out.consistency = value;
            } else if (key == "bind-propagation") {
                if (!oneOf(value, PROPAGATIONS)) {
                    return invalid(error, "invalid bind propagation: " + value);
                }

                out.propagation = value;
                sawBind = true;
            } else if (key == "bind-nonrecursive") {
                if (!parseBool(value, flag)) {
                    return invalid(error, "invalid value for " + key + ": " + value);
                }

                out.nonRecursive = flag;
                sawBind = true;
            } else if (key == "volume-driver") {
                out.volumeDriver = value;
                sawVolume = true;
            } else if (key == "volume-label" || key == "volume-opt") {
                size_t veq = value.find('=');
                std::string k = value.substr(0, veq);
                std::string v = veq == std::string::npos ? std::string() : value.substr(veq + 1);
                if (k.empty()) {
                    return invalid(error, "invalid " + key + ": " + value);
                }

                (key == "volume-label" ? out.volumeLabels : out.volumeOptions)[k] = v;
                sawVolume = true;
            } else if (key == "volume-nocopy") {
                if (!parseBool(value, flag)) {
                    return invalid(error, "invalid value for " + key + ": " + value);
                }

                out.noCopy = flag;
                sawVolume = true;
            } else if (key == "volume-subpath") {
                out.volumeSubpath = value;
                sawVolume = true;
            } else if (key == "tmpfs-size") {
                if (ParseSize(value, out.tmpfsSize) < 0) {
                    return invalid(error, "invalid tmpfs-size: " + value);
                }

                sawTmpfs = true;
            } else if (key == "tmpfs-mode") {
                char* end = nullptr;
                unsigned long m = std::strtoul(value.c_str(), &end, 8);
                if (value.empty() || *end != '\0' || m > 07777) {
                    return invalid(error, "invalid tmpfs-mode: " + value);
                }

                out.tmpfsMode = uint32_t(m);
                sawTmpfs = true;
            } else {
                return invalid(error, "unexpected key '" + key + "' in '" + field + "'");
            }
        }

        if (typeText == "volume") {
            out.type = EMT_VOLUME;
        } else if (typeText == "bind") {
            out.type = EMT_BIND;
        } else if (typeText == "tmpfs") {
            out.type = EMT_TMPFS;
        } else {
            return invalid(error, "unsupported mount type: \"" + typeText + "\"");
        }

        if (sawBind && out.type != EMT_BIND) {
            return invalid(error, "cannot mix 'bind-*' options with mount type '" + typeText + "'");
        }

        if (sawVolume && out.type != EMT_VOLUME) {
            return invalid(error, "cannot mix 'volume-*' options with mount type '" + typeText + "'");
        }

        if (sawTmpfs && out.type != EMT_TMPFS) {
            return invalid(error, "cannot mix 'tmpfs-*' options with mount type '" + typeText + "'");
        }

        if (target.empty()) {
            return invalid(error, "target is required");
        }

        int32_t rc = cleanTarget(target, out.target, error);
        if (rc < 0) {
            return rc;
        }

        switch (out.type) {
            case EMT_BIND:
                if (source.empty()) {
                    return invalid(error, "invalid mount config for type \"bind\": field Source must not be empty");
                }

                if (CleanAbsolutePath(source, out.source) < 0) {
                    return invalid(error, "invalid mount config for type \"bind\": source must be an absolute path: " + source);
                }

                break;

            case EMT_VOLUME:
                if (!source.empty() && !IsValidVolumeName(source)) {
                    return invalid(error, "\"" + source + "\" includes invalid characters for a local volume name");
                }

                out.source = source;
                if (!out.volumeSubpath.empty()) {
                    std::string sub;
                    if (cleanSubpath(out.volumeSubpath, sub) < 0) {
                        return invalid(error, "invalid volume-subpath: " + out.volumeSubpath);
                    }

                    out.volumeSubpath = sub;
                }

                break;

            default:
                if (!source.empty()) {
                    return invalid(error, "invalid mount config for type \"tmpfs\": source is not supported");
                }

                break;
        }

        return SBOX_OK;
    }

    /* Parses --tmpfs. */
    int32_t ParseTmpfsFlag(std::string_view spec, SMountRequest& out, std::string* error) {
        out = SMountRequest();
        out.type = EMT_TMPFS;
        size_t colon = spec.find(':');
        std::string_view target = spec.substr(0, colon);
        int32_t rc = cleanTarget(target, out.target, error);
        if (rc < 0) {
            return rc;
        }

        if (colon == std::string_view::npos) {
            return SBOX_OK;
        }

        for (const std::string& w : split(spec.substr(colon + 1), ',')) {
            if (w.empty()) {
                return invalid(error, "invalid tmpfs options: " + std::string(spec));
            }

            if (w == "ro") {
                out.readOnly = true;
            } else if (w == "rw") {
                out.readOnly = false;
            } else {
                out.tmpfsOptions.push_back(w);
            }
        }

        return SBOX_OK;
    }

    /* Validates a bind source. */
    int32_t ValidateHostPath(const std::string& path, bool create, std::string& cleaned, const std::string& storeRoot) {
        if (CleanAbsolutePath(path, cleaned) < 0) {
            return -EINVAL;
        }

        if (!storeRoot.empty()) {
            std::string root;
            if (CleanAbsolutePath(storeRoot, root) == SBOX_OK && root != "/" &&
                (cleaned == root || cleaned.compare(0, root.size() + 1, root + "/") == 0)) {
                // --> Only a volume's _data (or below) may be bound directly; metadata stays private.
                std::string rest = cleaned.size() > root.size() ? cleaned.substr(root.size() + 1) : std::string();
                size_t slash = rest.find('/');
                std::string second = slash == std::string::npos ? std::string() : rest.substr(slash + 1);
                if (slash == std::string::npos || !(second == "_data" || second.compare(0, 6, "_data/") == 0)) {
                    return -EACCES;
                }
            }
        }

        struct stat st{};
        if (::stat(cleaned.c_str(), &st) == 0) {
            return SBOX_OK;
        }

        if (errno != ENOENT || !create) {
            return -errno;
        }

        return CFile::makeDirs(cleaned, 0755);
    }

    /* Builds an OCI mount object. */
    int32_t BuildOciMount(const SMountRequest& request, const std::string& hostSource, CJson& out) {
        if (request.target.empty() || request.target[0] != '/') {
            return -EINVAL;
        }

        out = CJson::object();
        out.set("destination", CJson(request.target));
        std::vector<std::string> options;
        switch (request.type) {
            case EMT_VOLUME:
            case EMT_BIND:
                if (hostSource.empty() || hostSource[0] != '/') {
                    return -EINVAL;
                }

                out.set("type", CJson("bind"));
                out.set("source", CJson(hostSource));
                options.push_back(request.nonRecursive ? "bind" : "rbind");
                options.push_back(request.readOnly ? "ro" : "rw");
                options.push_back(request.propagation.empty() ? std::string("rprivate") : request.propagation);
                break;

            case EMT_TMPFS: {
                out.set("type", CJson("tmpfs"));
                out.set("source", CJson("tmpfs"));
                options = { "nosuid", "nodev", "noexec" };
                // --> --tmpfs words may turn the defaults off (exec, suid, dev), like Docker.
                for (const std::string& w : request.tmpfsOptions) {
                    const char* off = w == "exec" ? "noexec" : w == "suid" ? "nosuid" : w == "dev" ? "nodev" : nullptr;
                    if (off != nullptr) {
                        options.erase(std::remove(options.begin(), options.end(), std::string(off)), options.end());
                    }

                    if (std::find(options.begin(), options.end(), w) == options.end()) {
                        options.push_back(w);
                    }
                }

                if (request.readOnly) {
                    options.push_back("ro");
                }

                if (request.tmpfsSize != 0) {
                    options.push_back("size=" + FormatSize(request.tmpfsSize));
                }

                if (request.tmpfsMode != 0) {
                    char text[16];
                    std::snprintf(text, sizeof(text), "mode=%o", request.tmpfsMode);
                    options.push_back(text);
                }

                break;
            }

            default:
                return -EINVAL;
        }

        out.set("options", CJson::fromStrings(options));
        return SBOX_OK;
    }

    /* Turns mount requests into OCI mounts for a container. */
    TTask<int32_t> PrepareContainerMounts(CVolumeStore& store, std::vector<SMountRequest> requests, std::string containerId,
                                          std::string rootfs, std::vector<CJson>& out, std::string* error) {
        out.clear();
        std::vector<std::string> acquired;      // --> Volumes this call registered the container on.
        std::vector<std::string> created;       // --> Anonymous volumes this call created.
        std::set<std::string> targets;
        int32_t rc = SBOX_OK;

        auto report = [&](int32_t code, std::string message) {
            if (error != nullptr) {
                *error = std::move(message);
            }

            return code;
        };

        for (SMountRequest& req : requests) {
            if (!targets.insert(req.target).second) {
                rc = report(-EINVAL, "duplicate mount point: " + req.target);
                break;
            }

            std::string hostSource;
            if (req.type == EMT_VOLUME) {
                if (!req.volumeDriver.empty() && req.volumeDriver != "local") {
                    rc = report(-ENOTSUP, "volume driver \"" + req.volumeDriver + "\" is not supported");
                    break;
                }

                SVolume v;
                std::string name = req.source;
                int32_t found = name.empty() ? -ENOENT : store.inspect(name, v);
                if (found == -ENOENT) {
                    SVolumeCreate create;
                    create.name = name;
                    create.labels = req.volumeLabels;
                    create.options = req.volumeOptions;
                    rc = co_await store.create(create, v);
                    if (rc < 0) {
                        rc = report(rc, store.lastError());
                        break;
                    }

                    if (name.empty()) {
                        created.push_back(v.name);
                    }
                } else if (found < 0) {
                    rc = report(found, "cannot read volume " + name + ": " + ErrorText(found));
                    break;
                }

                bool already = std::find(v.users.begin(), v.users.end(), containerId) != v.users.end();
                std::string mountpoint;
                rc = co_await store.acquire(v.name, containerId, mountpoint);
                if (rc < 0) {
                    rc = report(rc, store.lastError());
                    break;
                }

                if (!already) {
                    acquired.push_back(v.name);
                }

                hostSource = mountpoint;
                if (!req.volumeSubpath.empty()) {
                    // --> Resolve inside the volume so a symlink in it cannot point the bind elsewhere.
                    int32_t fd = OpenInRoot(mountpoint, req.volumeSubpath);
                    if (fd < 0) {
                        rc = report(fd, "cannot open volume-subpath " + req.volumeSubpath + ": " + ErrorText(fd));
                        break;
                    }

                    CFd held(fd);
                    char link[4096];
                    ssize_t n = ::readlink(("/proc/self/fd/" + std::to_string(fd)).c_str(), link, sizeof(link) - 1);
                    if (n <= 0) {
                        rc = report(-EIO, "cannot resolve volume-subpath " + req.volumeSubpath);
                        break;
                    }

                    hostSource.assign(link, size_t(n));
                    if (hostSource != mountpoint && hostSource.compare(0, mountpoint.size() + 1, mountpoint + "/") != 0) {
                        rc = report(-EXDEV, "volume-subpath leaves the volume: " + req.volumeSubpath);
                        break;
                    }
                } else if (!req.noCopy && !rootfs.empty()) {
                    int32_t fd = OpenInRoot(rootfs, req.target);
                    if (fd >= 0) {
                        CFd held(fd);
                        int32_t copied = CopyUpIfEmpty("/proc/self/fd/" + std::to_string(fd), mountpoint);
                        if (copied < 0) {
                            rc = report(copied, "cannot copy image content of " + req.target + " into volume " + v.name + ": " +
                                                ErrorText(copied));
                            break;
                        }
                    }
                }
            } else if (req.type == EMT_BIND) {
                rc = ValidateHostPath(req.source, req.createHostPath, hostSource, store.root());
                if (rc < 0) {
                    rc = report(rc, rc == -ENOENT ? "bind source path does not exist: " + req.source
                                                  : "invalid bind source " + req.source + ": " + ErrorText(rc));
                    break;
                }
            }

            CJson mount;
            rc = BuildOciMount(req, hostSource, mount);
            if (rc < 0) {
                rc = report(rc, "invalid mount for " + req.target);
                break;
            }

            out.push_back(std::move(mount));
        }

        if (rc < 0) {
            out.clear();
            for (const std::string& name : acquired) {
                co_await store.release(name, containerId);
            }

            for (const std::string& name : created) {
                co_await store.remove(name, false);
            }
        }

        co_return rc;
    }

}
}
