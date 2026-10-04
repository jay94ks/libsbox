#include <sbox/vol/store.hpp>

#include "util.hpp"

#include <sbox/core/file.hpp>
#include <sbox/vol/quota.hpp>
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

namespace sbox {
namespace vol {

    namespace {

        const char* METADATA_FILE = "volume.json";
        const char* STATE_FILE = "state.json";
        const char* OPTS_FILE = "opts.json";
        const char* DATA_DIR = "_data";

        /* Sums allocated bytes below a directory without crossing mounts or following links. */
        void sumTree(int dirFd, dev_t dev, std::set<std::pair<dev_t, ino_t>>& seen, uint64_t& total) {
            DIR* dir = ::fdopendir(dirFd);
            if (dir == nullptr) {
                ::close(dirFd);
                return;
            }

            while (dirent* de = ::readdir(dir)) {
                if (std::strcmp(de->d_name, ".") == 0 || std::strcmp(de->d_name, "..") == 0) {
                    continue;
                }

                struct stat st{};
                if (::fstatat(::dirfd(dir), de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 || st.st_dev != dev) {
                    continue;
                }

                if (st.st_nlink > 1 && !S_ISDIR(st.st_mode)) {
                    if (!seen.insert({ st.st_dev, st.st_ino }).second) {
                        continue;
                    }
                }

                total += uint64_t(st.st_blocks) * 512;
                if (S_ISDIR(st.st_mode)) {
                    int fd = ::openat(::dirfd(dir), de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                    if (fd >= 0) {
                        sumTree(fd, dev, seen, total);
                    }
                }
            }

            ::closedir(dir);
        }

        /* Returns true when the volume labels match every filter. */
        bool matchesLabels(const SVolume& v, const std::vector<std::string>& filters) {
            for (const std::string& f : filters) {
                bool negate = false;
                std::string expr = f;
                if (!expr.empty() && expr[0] == '!') {
                    negate = true;
                    expr.erase(0, 1);
                }

                std::string key = expr;
                std::string value;
                bool hasValue = false;
                size_t ne = expr.find("!=");
                size_t eq = expr.find('=');
                if (ne != std::string::npos && (eq == std::string::npos || ne < eq)) {
                    negate = !negate;
                    key = expr.substr(0, ne);
                    value = expr.substr(ne + 2);
                    hasValue = true;
                } else if (eq != std::string::npos) {
                    key = expr.substr(0, eq);
                    value = expr.substr(eq + 1);
                    hasValue = true;
                }

                auto it = v.labels.find(key);
                bool match = it != v.labels.end() && (!hasValue || it->second == value);
                if (match == negate) {
                    return false;
                }
            }

            return true;
        }

        /* Removes `user` from the list; returns true when it was present. */
        bool eraseUser(std::vector<std::string>& users, const std::string& user) {
            auto it = std::find(users.begin(), users.end(), user);
            if (it == users.end()) {
                return false;
            }

            users.erase(it);
            return true;
        }

    }

    /* Returns true when the volume was created without a name. */
    bool SVolume::isAnonymous() const noexcept {
        return labels.find(ANONYMOUS_LABEL) != labels.end();
    }

    /* Returns the Docker inspect document. */
    CJson SVolume::toJson(bool withUsage) const {
        CJson out = CJson::object();
        out.set("CreatedAt", CJson(createdAt));
        out.set("Driver", CJson(driver));
        out.set("Labels", MapToJson(labels));
        out.set("Mountpoint", CJson(mountpoint));
        out.set("Name", CJson(name));
        out.set("Options", MapToJson(options));
        out.set("Scope", CJson(scope));
        if (withUsage) {
            CJson usage = CJson::object();
            usage.set("RefCount", CJson(int64_t(users.size())));
            usage.set("Size", CJson(int64_t(-1)));
            out.set("UsageData", std::move(usage));
        }

        return out;
    }

    /* Returns the persisted metadata document. */
    CJson SVolume::toMetadata() const {
        CJson out = toJson(false);
        if (projectId != 0) {
            out.set("ProjectId", CJson(uint64_t(projectId)));
        }

        if (sizeLimit != 0) {
            out.set("SizeLimit", CJson(sizeLimit));
        }

        return out;
    }

    /* Parses a metadata document. */
    int32_t SVolume::fromMetadata(const CJson& json, SVolume& out) {
        if (!json.isObject() || !json.get("Name").isString()) {
            return -EINVAL;
        }

        out = SVolume();
        out.name = json.get("Name").asString();
        out.driver = json.get("Driver").isString() ? json.get("Driver").asString() : std::string("local");
        out.mountpoint = json.get("Mountpoint").asString();
        out.createdAt = json.get("CreatedAt").asString();
        out.scope = json.get("Scope").isString() ? json.get("Scope").asString() : std::string("local");
        out.labels = MapFromJson(json.get("Labels"));
        out.options = MapFromJson(json.get("Options"));
        out.projectId = uint32_t(json.get("ProjectId").asInt(0));
        out.sizeLimit = uint64_t(json.get("SizeLimit").asInt(0));
        return SBOX_OK;
    }

    /* Returns the default store directory. */
    std::string DefaultVolumeRoot() {
        if (::geteuid() == 0) {
            return "/var/lib/sbox/volumes";
        }

        const char* xdg = std::getenv("XDG_DATA_HOME");
        if (xdg != nullptr && xdg[0] == '/') {
            return CFile::join(xdg, "sbox/volumes");
        }

        const char* home = std::getenv("HOME");
        if (home != nullptr && home[0] == '/') {
            return CFile::join(home, ".local/share/sbox/volumes");
        }

        return "/tmp/sbox-" + std::to_string(::getuid()) + "/volumes";
    }

    /* Returns true for a valid local volume name. */
    bool IsValidVolumeName(std::string_view name) noexcept {
        if (name.size() < 2 || name.size() > 255) {
            return false;
        }

        for (size_t i = 0; i < name.size(); ++i) {
            char c = name[i];
            bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            if (!alnum && (i == 0 || (c != '_' && c != '.' && c != '-'))) {
                return false;
            }
        }

        return true;
    }

    /* Returns a random anonymous volume name. */
    std::string NewAnonymousVolumeName() {
        return RandomHex(32);
    }

    /* Creates a store. */
    CVolumeStore::CVolumeStore(SVolumeStoreOptions options) : _options(std::move(options)) {
        if (_options.root.empty()) {
            _options.root = DefaultVolumeRoot();
        }

        while (_options.root.size() > 1 && _options.root.back() == '/') {
            _options.root.pop_back();
        }

        if (_options.projectIdBase == 0) {
            _options.projectIdBase = 1;
        }
    }

    /* Returns the directory of a volume. */
    std::string CVolumeStore::volumeDir(const std::string& name) const {
        return CFile::join(_options.root, name);
    }

    /* Records a failure reason. */
    int32_t CVolumeStore::fail(int32_t code, std::string message) {
        _lastError = std::move(message);
        return code;
    }

    /* Reads metadata and runtime state of a volume. */
    int32_t CVolumeStore::load(const std::string& name, SVolume& out) const {
        if (!IsValidVolumeName(name)) {
            return -EINVAL;
        }

        std::string dir = volumeDir(name);
        CJson meta;
        int32_t rc = ReadJsonFile(CFile::join(dir, METADATA_FILE), meta);
        if (rc < 0) {
            return rc == -ENOTDIR ? -ENOENT : rc;
        }

        rc = SVolume::fromMetadata(meta, out);
        if (rc < 0 || out.name != name) {
            return -EINVAL;
        }

        out.mountpoint = CFile::join(dir, DATA_DIR);

        CJson state;
        if (ReadJsonFile(CFile::join(dir, STATE_FILE), state) == SBOX_OK && state.isObject()) {
            // --> Runtime state from before a reboot is meaningless: nobody uses it, nothing is mounted.
            std::string boot = BootId();
            if (boot.empty() || state.get("BootId").asString() == boot) {
                out.users = state.get("Users").asStrings();
                out.mounted = state.get("Mounted").asBool(false);
            }
        }

        return SBOX_OK;
    }

    /* Writes the runtime state of a volume. */
    int32_t CVolumeStore::saveState(const SVolume& volume) {
        CJson state = CJson::object();
        state.set("Users", CJson::fromStrings(volume.users));
        state.set("Mounted", CJson(volume.mounted));
        state.set("BootId", CJson(BootId()));
        return CFile::writeAtomic(CFile::join(volumeDir(volume.name), STATE_FILE), state.dump(true) + "\n", 0600);
    }

    /* Allocates the next project id. */
    int32_t CVolumeStore::allocateProjectId(uint32_t& id) {
        uint64_t next = _options.projectIdBase;
        CJson alloc;
        std::string path = CFile::join(_options.root, ".quota.json");
        if (ReadJsonFile(path, alloc) == SBOX_OK) {
            next = std::max<uint64_t>(next, uint64_t(alloc.get("NextProjectId").asInt(0)));
        }

        // --> Never collide with an id still in use, even if the allocation file was lost.
        std::vector<SVolume> all;
        list(all);
        for (const SVolume& v : all) {
            if (v.projectId != 0 && uint64_t(v.projectId) >= next) {
                next = uint64_t(v.projectId) + 1;
            }
        }

        if (next >= 0xFFFFFFFFull) {
            return -ENOSPC;
        }

        id = uint32_t(next);
        CJson out = CJson::object();
        out.set("NextProjectId", CJson(next + 1));
        return CFile::writeAtomic(path, out.dump(true) + "\n", 0600);
    }

    /* Parses the local options of a loaded volume. */
    int32_t CVolumeStore::localOptions(const SVolume& volume, SLocalOptions& out) {
        std::string why;
        int32_t rc = ParseLocalOptions(volume.options, out, &why);
        if (rc < 0) {
            return fail(rc, "volume " + volume.name + ": " + why);
        }

        return SBOX_OK;
    }

    /* Creates a volume. */
    TTask<int32_t> CVolumeStore::create(SVolumeCreate request, SVolume& out) {
        _lastError.clear();
        if (request.driver.empty()) {
            request.driver = "local";
        }

        if (request.driver != "local") {
            co_return fail(-ENOTSUP, "volume driver \"" + request.driver + "\" is not supported (only \"local\")");
        }

        if (request.name.empty()) {
            request.name = NewAnonymousVolumeName();
            request.labels[ANONYMOUS_LABEL] = "";
        }

        if (!IsValidVolumeName(request.name)) {
            co_return fail(-EINVAL, "\"" + request.name + "\" includes invalid characters for a local volume name, "
                                    "only \"[a-zA-Z0-9][a-zA-Z0-9_.-]\" are allowed");
        }

        SLocalOptions local;
        std::string why;
        if (ParseLocalOptions(request.options, local, &why) < 0) {
            co_return fail(-EINVAL, why);
        }

        int32_t rc = CFile::makeDirs(_options.root, 0701);
        if (rc < 0) {
            co_return fail(rc, "cannot create volume root " + _options.root + ": " + ErrorText(rc));
        }

        StoreLock lock;
        rc = co_await lock.lock(CFile::join(_options.root, ".lock"), _options.lockTimeoutMs);
        if (rc < 0) {
            co_return fail(rc, "cannot lock volume store: " + ErrorText(rc));
        }

        SVolume existing;
        rc = load(request.name, existing);
        if (rc == SBOX_OK) {
            if (existing.driver != request.driver) {
                co_return fail(-EEXIST, "volume " + request.name + " already exists with driver " + existing.driver);
            }

            out = std::move(existing);
            co_return SBOX_OK;
        }

        std::string dir = volumeDir(request.name);
        // --> A directory without metadata is the leftover of an interrupted create.
        if (CFile::exists(dir)) {
            if (IsMountPoint(CFile::join(dir, DATA_DIR))) {
                co_return fail(-EBUSY, "stale volume directory " + dir + " has a mount on it");
            }

            CFile::removeTree(dir);
        }

        if (local.quotaBytes != 0) {
            int32_t probe = ProbeProjectQuota(_options.root);
            if (probe < 0) {
                co_return fail(probe == -ENOTSUP ? -ENOTSUP : probe,
                               "quota size requested but no quota support: the filesystem of " + _options.root +
                               " needs project quotas (xfs mounted with pquota, or ext4 with the project,quota "
                               "features mounted with prjquota): " + ErrorText(probe));
            }
        }

        SVolume v;
        v.name = request.name;
        v.driver = request.driver;
        v.labels = request.labels;
        v.options = request.options;
        v.createdAt = NowRfc3339();
        v.mountpoint = CFile::join(dir, DATA_DIR);
        v.sizeLimit = local.quotaBytes;

        auto cleanup = [&](int32_t code, std::string message) -> int32_t {
            CFile::removeTree(dir);
            return fail(code, std::move(message));
        };

        if (::mkdir(dir.c_str(), 0755) != 0) {
            rc = -errno;
            co_return fail(rc, "cannot create " + dir + ": " + ErrorText(rc));
        }

        if (::mkdir(v.mountpoint.c_str(), 0755) != 0) {
            rc = -errno;
            co_return cleanup(rc, "cannot create " + v.mountpoint + ": " + ErrorText(rc));
        }

        if ((_options.dataUid != 0 || _options.dataGid != 0) &&
            ::chown(v.mountpoint.c_str(), _options.dataUid, _options.dataGid) != 0) {
            rc = -errno;
            co_return cleanup(rc, "cannot chown " + v.mountpoint + ": " + ErrorText(rc));
        }

        if (local.quotaBytes != 0) {
            rc = allocateProjectId(v.projectId);
            if (rc == SBOX_OK) {
                rc = SetProjectId(v.mountpoint, v.projectId, true);
            }

            if (rc == SBOX_OK) {
                rc = SetProjectLimit(v.mountpoint, v.projectId, local.quotaBytes);
            }

            if (rc < 0) {
                co_return cleanup(rc, "cannot set quota on " + v.mountpoint + ": " + ErrorText(rc));
            }
        }

        if (local.kind != ELK_DIRECTORY || local.quotaBytes != 0) {
            // --> Same file Docker's local driver keeps next to _data.
            CJson opts = CJson::object();
            opts.set("MountType", CJson(local.type));
            opts.set("MountOpts", CJson(local.o));
            opts.set("MountDevice", CJson(local.device));
            CJson quota = CJson::object();
            quota.set("Size", CJson(local.quotaBytes));
            opts.set("Quota", std::move(quota));
            rc = CFile::writeAtomic(CFile::join(dir, OPTS_FILE), opts.dump() + "\n", 0600);
            if (rc < 0) {
                co_return cleanup(rc, "cannot write " + std::string(OPTS_FILE) + ": " + ErrorText(rc));
            }
        }

        rc = saveState(v);
        if (rc == SBOX_OK) {
            // --> Metadata goes last: its presence marks the volume as complete.
            rc = CFile::writeAtomic(CFile::join(dir, METADATA_FILE), v.toMetadata().dump(true) + "\n", 0600);
        }

        if (rc < 0) {
            co_return cleanup(rc, "cannot write volume metadata: " + ErrorText(rc));
        }

        out = std::move(v);
        co_return SBOX_OK;
    }

    /* Reads a volume. */
    int32_t CVolumeStore::inspect(const std::string& name, SVolume& out) const {
        return load(name, out);
    }

    /* Lists all volumes. */
    int32_t CVolumeStore::list(std::vector<SVolume>& out) const {
        out.clear();
        DIR* dir = ::opendir(_options.root.c_str());
        if (dir == nullptr) {
            return errno == ENOENT ? SBOX_OK : -errno;
        }

        std::vector<std::string> names;
        while (dirent* de = ::readdir(dir)) {
            if (IsValidVolumeName(de->d_name)) {
                names.emplace_back(de->d_name);
            }
        }

        ::closedir(dir);
        std::sort(names.begin(), names.end());
        for (const std::string& n : names) {
            SVolume v;
            if (load(n, v) == SBOX_OK) {
                out.push_back(std::move(v));
            }
        }

        return SBOX_OK;
    }

    /* Removes a volume directory (lock held). */
    int32_t CVolumeStore::destroy(const SVolume& volume) {
        std::string dir = volumeDir(volume.name);
        if (IsMountPoint(volume.mountpoint)) {
            int32_t rc = UnmountLocalVolume(volume.mountpoint, true);
            if (rc < 0) {
                return fail(rc, "cannot unmount " + volume.mountpoint + ": " + ErrorText(rc));
            }
        }

        // --> Never delete through a mount: the backing data (a bind source, an NFS export) is not ours.
        if (IsMountPoint(volume.mountpoint)) {
            return fail(-EBUSY, volume.mountpoint + " is still a mount point");
        }

        if (volume.projectId != 0) {
            SetProjectLimit(volume.mountpoint, volume.projectId, 0);
        }

        // --> Rename first so a crash mid-delete leaves no half volume under a valid name.
        std::string trash = CFile::join(_options.root, ".trash-" + volume.name + "-" + RandomHex(4));
        if (::rename(dir.c_str(), trash.c_str()) != 0) {
            int32_t rc = -errno;
            return fail(rc, "cannot remove " + dir + ": " + ErrorText(rc));
        }

        int32_t rc = CFile::removeTree(trash);
        if (rc < 0) {
            return fail(rc, "cannot remove " + trash + ": " + ErrorText(rc));
        }

        return SBOX_OK;
    }

    /* Removes a volume. */
    TTask<int32_t> CVolumeStore::remove(std::string name, bool force) {
        _lastError.clear();
        StoreLock lock;
        int32_t rc = co_await lock.lock(CFile::join(_options.root, ".lock"), _options.lockTimeoutMs);
        if (rc < 0) {
            co_return fail(rc, rc == -ENOENT ? "no such volume: " + name : "cannot lock volume store: " + ErrorText(rc));
        }

        SVolume v;
        rc = load(name, v);
        if (rc < 0) {
            co_return fail(rc, rc == -ENOENT ? "no such volume: " + name : "cannot read volume " + name + ": " + ErrorText(rc));
        }

        if (!v.users.empty() && !force) {
            std::string ids;
            for (const std::string& u : v.users) {
                ids += (ids.empty() ? "" : ", ") + u;
            }

            co_return fail(-EBUSY, "volume is in use - [" + ids + "]");
        }

        co_return destroy(v);
    }

    /* Registers a user on a volume (lock held). */
    TTask<int32_t> CVolumeStore::acquireLocked(SVolume& v, std::string user) {
        if (std::find(v.users.begin(), v.users.end(), user) != v.users.end() &&
            (!v.mounted || IsMountPoint(v.mountpoint))) {
            co_return SBOX_OK;
        }

        SLocalOptions local;
        int32_t rc = localOptions(v, local);
        if (rc < 0) {
            co_return rc;
        }

        bool mountedHere = false;
        if (local.needsMount() && !IsMountPoint(v.mountpoint)) {
            rc = co_await MountLocalVolume(local, v.mountpoint);
            if (rc < 0) {
                co_return fail(rc, "cannot mount volume " + v.name + " (type " + local.type + ", device " + local.device +
                                   "): " + ErrorText(rc));
            }

            mountedHere = true;
        }

        v.mounted = local.needsMount();
        if (std::find(v.users.begin(), v.users.end(), user) == v.users.end()) {
            v.users.push_back(user);
        }

        rc = saveState(v);
        if (rc < 0) {
            if (mountedHere) {
                UnmountLocalVolume(v.mountpoint, true);
            }

            co_return fail(rc, "cannot write volume state: " + ErrorText(rc));
        }

        co_return SBOX_OK;
    }

    /* Registers a user on a volume. */
    TTask<int32_t> CVolumeStore::acquire(std::string name, std::string user, std::string& mountpoint) {
        _lastError.clear();
        if (user.empty()) {
            co_return fail(-EINVAL, "empty user id");
        }

        StoreLock lock;
        int32_t rc = co_await lock.lock(CFile::join(_options.root, ".lock"), _options.lockTimeoutMs);
        if (rc < 0) {
            co_return fail(rc, rc == -ENOENT ? "no such volume: " + name : "cannot lock volume store: " + ErrorText(rc));
        }

        SVolume v;
        rc = load(name, v);
        if (rc < 0) {
            co_return fail(rc, rc == -ENOENT ? "no such volume: " + name : "cannot read volume " + name + ": " + ErrorText(rc));
        }

        rc = co_await acquireLocked(v, user);
        if (rc == SBOX_OK) {
            mountpoint = v.mountpoint;
        }

        co_return rc;
    }

    /* Drops a user from a volume (lock held). */
    int32_t CVolumeStore::releaseLocked(SVolume& v, const std::string& user) {
        bool changed = eraseUser(v.users, user);
        if (v.users.empty() && (v.mounted || IsMountPoint(v.mountpoint))) {
            SLocalOptions local;
            if (localOptions(v, local) == SBOX_OK && local.needsMount()) {
                int32_t rc = UnmountLocalVolume(v.mountpoint, true);
                if (rc < 0) {
                    saveState(v);
                    return fail(rc, "cannot unmount " + v.mountpoint + ": " + ErrorText(rc));
                }
            }

            v.mounted = false;
            changed = true;
        }

        if (!changed) {
            return SBOX_OK;
        }

        int32_t rc = saveState(v);
        return rc < 0 ? fail(rc, "cannot write volume state: " + ErrorText(rc)) : SBOX_OK;
    }

    /* Drops a user from a volume. */
    TTask<int32_t> CVolumeStore::release(std::string name, std::string user) {
        _lastError.clear();
        StoreLock lock;
        int32_t rc = co_await lock.lock(CFile::join(_options.root, ".lock"), _options.lockTimeoutMs);
        if (rc < 0) {
            co_return fail(rc, rc == -ENOENT ? "no such volume: " + name : "cannot lock volume store: " + ErrorText(rc));
        }

        SVolume v;
        rc = load(name, v);
        if (rc < 0) {
            co_return fail(rc, rc == -ENOENT ? "no such volume: " + name : "cannot read volume " + name + ": " + ErrorText(rc));
        }

        co_return releaseLocked(v, user);
    }

    /* Releases every volume of a user. */
    TTask<int32_t> CVolumeStore::releaseUser(std::string user, bool removeAnonymous, std::vector<std::string>* released) {
        _lastError.clear();
        StoreLock lock;
        int32_t rc = co_await lock.lock(CFile::join(_options.root, ".lock"), _options.lockTimeoutMs);
        if (rc == -ENOENT) {
            co_return SBOX_OK;
        }

        if (rc < 0) {
            co_return fail(rc, "cannot lock volume store: " + ErrorText(rc));
        }

        std::vector<SVolume> all;
        list(all);
        int32_t first = SBOX_OK;
        for (SVolume& v : all) {
            if (std::find(v.users.begin(), v.users.end(), user) == v.users.end()) {
                continue;
            }

            rc = releaseLocked(v, user);
            if (rc == SBOX_OK && removeAnonymous && v.isAnonymous() && v.users.empty()) {
                rc = destroy(v);
            }

            if (rc < 0 && first == SBOX_OK) {
                first = rc;
            }

            if (rc == SBOX_OK && released != nullptr) {
                released->push_back(v.name);
            }
        }

        co_return first;
    }

    /* Removes unused volumes. */
    TTask<int32_t> CVolumeStore::prune(SPruneOptions options, SPruneReport& report) {
        _lastError.clear();
        report = SPruneReport();
        StoreLock lock;
        int32_t rc = co_await lock.lock(CFile::join(_options.root, ".lock"), _options.lockTimeoutMs);
        if (rc == -ENOENT) {
            co_return SBOX_OK;
        }

        if (rc < 0) {
            co_return fail(rc, "cannot lock volume store: " + ErrorText(rc));
        }

        std::vector<SVolume> all;
        list(all);
        int32_t first = SBOX_OK;
        for (const SVolume& v : all) {
            if (!v.users.empty() || (!options.all && !v.isAnonymous()) || !matchesLabels(v, options.labelFilters)) {
                continue;
            }

            SVolumeUsage u;
            usage(v.name, u);
            rc = destroy(v);
            if (rc < 0) {
                if (first == SBOX_OK) {
                    first = rc;
                }

                continue;
            }

            report.removed.push_back(v.name);
            report.reclaimedBytes += u.bytes;
        }

        co_return first;
    }

    /* Computes disk usage of a volume. */
    int32_t CVolumeStore::usage(const std::string& name, SVolumeUsage& out) const {
        out = SVolumeUsage();
        SVolume v;
        int32_t rc = load(name, v);
        if (rc < 0) {
            return rc;
        }

        out.refCount = v.users.size();
        out.limit = v.sizeLimit;
        if (v.projectId != 0) {
            SQuotaUsage q;
            if (GetProjectUsage(v.mountpoint, v.projectId, q) == SBOX_OK) {
                out.bytes = q.usedBytes;
                out.limit = q.limitBytes;
                return SBOX_OK;
            }
        }

        struct stat st{};
        if (::lstat(v.mountpoint.c_str(), &st) != 0) {
            return -errno;
        }

        int fd = ::open(v.mountpoint.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            return -errno;
        }

        std::set<std::pair<dev_t, ino_t>> seen;
        sumTree(fd, st.st_dev, seen, out.bytes);
        return SBOX_OK;
    }

    /* Copies image content into an empty volume. */
    int32_t CVolumeStore::copyUp(const std::string& name, const std::string& source) {
        SVolume v;
        int32_t rc = load(name, v);
        if (rc < 0) {
            return rc;
        }

        return CopyUpIfEmpty(source, v.mountpoint);
    }

}
}
