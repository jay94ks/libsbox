#include <sbox/image/snapshot.hpp>
#include "util.hpp"
#include <sbox/archive/extract.hpp>
#include <sbox/archive/tree.hpp>
#include <sbox/core/file.hpp>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif
#ifndef SYS_fsopen
#define SYS_fsopen 430
#endif
#ifndef SYS_fsconfig
#define SYS_fsconfig 431
#endif
#ifndef SYS_fsmount
#define SYS_fsmount 432
#endif

namespace sbox {
namespace image {

    namespace {

        // --> Values of the new mount API (linux/mount.h), spelled out because glibc's
        // <sys/mount.h> and <linux/mount.h> do not mix on every distribution.
        constexpr unsigned int K_FSOPEN_CLOEXEC = 0x00000001;
        constexpr unsigned int K_FSCONFIG_SET_FLAG = 0;
        constexpr unsigned int K_FSCONFIG_SET_STRING = 1;
        constexpr unsigned int K_FSCONFIG_CMD_CREATE = 6;
        constexpr unsigned int K_FSMOUNT_CLOEXEC = 0x00000001;
        constexpr unsigned int K_MOVE_MOUNT_F_EMPTY_PATH = 0x00000004;

        /* Sink adapter writing into a blob writer. */
        class BlobSink : public archive::IByteSink {
        public:
            CBlobWriter& writer;

            explicit BlobSink(CBlobWriter& w) : writer(w) {}

            int32_t write(const SReadOnlyByteSpan& data) override {
                return writer.write(data);
            }
        };

        /* Returns true for a valid container ID. */
        bool validId(std::string_view id) {
            if (id.empty() || id.size() > 128) {
                return false;
            }

            for (size_t i = 0; i < id.size(); ++i) {
                char c = id[i];
                bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
                if (!alnum && (i == 0 || (c != '_' && c != '.' && c != '-'))) {
                    return false;
                }
            }

            return true;
        }

        /* Reads the error log of an fs context (lines "e ...", "w ..."). */
        std::string fsContextLog(int fd) {
            std::string out;
            char buf[512];
            for (int i = 0; i < 16; ++i) {
                ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
                if (n <= 0) {
                    break;
                }

                if (!out.empty()) {
                    out += "; ";
                }

                out.append(buf, size_t(n));
            }

            return out;
        }

        /* Escapes characters overlayfs treats specially in lowerdir lists. */
        std::string escapeLower(const std::string& path) {
            std::string out;
            for (char c : path) {
                if (c == ':' || c == ',' || c == '\\') {
                    out.push_back('\\');
                }

                out.push_back(c);
            }

            return out;
        }

        /* Writes container metadata. */
        int32_t writeContainerMeta(const std::string& dir, const SContainerInfo& c) {
            CJson j = CJson::object();
            j.set("id", c.id);
            j.set("imageId", c.imageId);
            j.set("imageName", c.imageName);
            j.set("manifestDigest", c.manifestDigest);
            j.set("mode", SnapshotModeName(c.mode));
            j.set("rootfs", c.rootfs);
            j.set("chainIds", CJson::fromStrings(c.chainIds));
            j.set("created", c.created);
            if (c.mode == ESNAP_OVERLAY) {
                CJson p = CJson::object();
                p.set("lowerDirs", CJson::fromStrings(c.plan.lowerDirs));
                p.set("upperDir", c.plan.upperDir);
                p.set("workDir", c.plan.workDir);
                p.set("target", c.plan.target);
                p.set("options", CJson::fromStrings(c.plan.options));
                j.set("plan", std::move(p));
            }

            return WriteJsonFile(CFile::join(dir, "meta.json"), j, true);
        }

    }

    /* Returns a mode name. */
    const char* SnapshotModeName(ESnapshotMode mode) noexcept {
        switch (mode) {
        case ESNAP_AUTO: return "auto";
        case ESNAP_OVERLAY: return "overlay";
        case ESNAP_COPY: return "copy";
        default: return "invalid";
        }
    }

    /* Parses a mode name. */
    ESnapshotMode ParseSnapshotMode(std::string_view name) noexcept {
        if (name == "auto" || name.empty()) {
            return ESNAP_AUTO;
        }

        if (name == "overlay" || name == "overlayfs" || name == "overlay2") {
            return ESNAP_OVERLAY;
        }

        if (name == "copy" || name == "vfs" || name == "native") {
            return ESNAP_COPY;
        }

        return ESNAP_INVALID;
    }

    /* Returns the legacy mount data string. */
    std::string SMountPlan::toMountData() const {
        std::string data = "lowerdir=";
        for (size_t i = 0; i < lowerDirs.size(); ++i) {
            if (i) {
                data.push_back(':');
            }

            data += escapeLower(lowerDirs[i]);
        }

        if (!upperDir.empty()) {
            data += ",upperdir=" + upperDir + ",workdir=" + workDir;
        }

        for (const std::string& o : options) {
            data += "," + o;
        }

        return data;
    }

    /* Creates a snapshotter. */
    CSnapshotter::CSnapshotter(CContentStorePtr store, SSnapshotterOptions options)
        : _store(std::move(store)), _options(std::move(options)) {
        _rootless = _options.rootless < 0 ? !IsRealRoot() : _options.rootless != 0;
    }

    /* Returns the directory of a snapshot. */
    std::string CSnapshotter::snapshotDir(std::string_view chainId) const {
        return _store->path("snapshots/" + std::string(DigestHex(chainId)));
    }

    /* Returns true when a snapshot exists. */
    bool CSnapshotter::hasSnapshot(std::string_view chainId) const {
        return ValidateDigest(chainId) == SBOX_OK && CFile::exists(CFile::join(snapshotDir(chainId), "meta.json"));
    }

    /* Reads a snapshot's metadata. */
    int32_t CSnapshotter::snapshot(std::string_view chainId, SSnapshotInfo& out) const {
        out = SSnapshotInfo();
        if (ValidateDigest(chainId) != SBOX_OK) {
            return -EINVAL;
        }

        CJson j;
        std::string dir = snapshotDir(chainId);
        int32_t r = ReadJsonFile(CFile::join(dir, "meta.json"), j);
        if (r != SBOX_OK) {
            return r;
        }

        out.chainId = j.get("chainId").asString();
        out.diffId = j.get("diffId").asString();
        out.parent = j.get("parent").asString();
        out.whiteouts = j.get("whiteouts").asString();
        out.size = uint64_t(j.get("size").asInt(0));
        out.path = CFile::join(dir, "fs");
        return SBOX_OK;
    }

    /* Lists every snapshot. */
    int32_t CSnapshotter::listSnapshots(std::vector<SSnapshotInfo>& out) const {
        out.clear();
        std::vector<std::string> names;
        int32_t r = ListDirectory(_store->path("snapshots"), names);
        if (r != SBOX_OK) {
            return r;
        }

        std::sort(names.begin(), names.end());
        for (const std::string& n : names) {
            SSnapshotInfo s;
            if (IsFullHexId(n) && snapshot("sha256:" + n, s) == SBOX_OK) {
                out.push_back(std::move(s));
            }
        }

        return SBOX_OK;
    }

    /* Removes a snapshot. */
    int32_t CSnapshotter::removeSnapshot(std::string_view chainId) {
        if (ValidateDigest(chainId) != SBOX_OK) {
            return -EINVAL;
        }

        // --> Rename first so a half-deleted snapshot never looks complete.
        std::string dir = snapshotDir(chainId);
        std::string trash = _store->path("snapshots/rm-" + RandomHex(8));
        if (::rename(dir.c_str(), trash.c_str()) != 0) {
            return errno == ENOENT ? SBOX_OK : -errno;
        }

        return CFile::removeTree(trash);
    }

    /* Extracts one layer into its snapshot. */
    int32_t CSnapshotter::unpackLayer(const SDescriptor& layer, const std::string& diffId, const std::string& parentChainId,
                                      std::string& chainId) {
        chainId.clear();
        if (!diffId.empty()) {
            chainId = ChainId(parentChainId, diffId);
            if (hasSnapshot(chainId)) {
                return SBOX_OK;
            }
        }

        std::string blob = _store->blobPath(layer.digest);
        if (blob.empty()) {
            _lastError = "invalid layer digest " + layer.digest;
            return -EINVAL;
        }

        CFd fd(::open(blob.c_str(), O_RDONLY | O_CLOEXEC));
        if (!fd.isValid()) {
            int32_t err = -errno;
            _lastError = "layer " + layer.digest + " is not in the store";
            return err;
        }

        std::string tmp = _store->path("snapshots/tmp-" + RandomHex(8));
        std::string fs = CFile::join(tmp, "fs");
        int32_t r = CFile::makeDirs(fs, 0755);
        if (r != SBOX_OK) {
            return r;
        }

        if (_options.progress) {
            SProgress p;
            p.phase = EPP_EXTRACTING;
            p.digest = layer.digest;
            p.mediaType = layer.mediaType;
            p.total = uint64_t(layer.size);
            _options.progress(p);
        }

        archive::SExtractOptions xo;
        xo.whiteouts = _rootless ? archive::EWHT_OVERLAY_USERXATTR : archive::EWHT_OVERLAY;
        xo.ownership = archive::EOWN_AUTO;
        CDigester diff;
        archive::SPipelineHooks hooks;
        hooks.uncompressed = [&diff](const SReadOnlyByteSpan& s) { diff.update(s); };
        archive::CFdSource src(fd.get());
        archive::SExtractStats stats;
        r = archive::ExtractArchive(src, fs, xo, archive::ECOMP_AUTO, hooks, &stats);
        if (r != SBOX_OK) {
            CFile::removeTree(tmp);
            _lastError = "extracting layer " + layer.digest + ": " + std::strerror(-r);
            return r;
        }

        std::string actual = diff.finish();
        if (!diffId.empty() && actual != diffId) {
            CFile::removeTree(tmp);
            _lastError = "layer " + layer.digest + " has diffID " + actual + ", the image config says " + diffId;
            return -EBADMSG;
        }

        chainId = ChainId(parentChainId, actual);
        _store->recordDiffId(layer.digest, actual);

        CJson meta = CJson::object();
        meta.set("chainId", chainId);
        meta.set("diffId", actual);
        meta.set("parent", parentChainId);
        meta.set("blob", layer.digest);
        meta.set("whiteouts", _rootless ? "userxattr" : "overlay");
        meta.set("size", int64_t(stats.bytes));
        meta.set("created", NowRfc3339());
        r = WriteJsonFile(CFile::join(tmp, "meta.json"), meta, true);
        if (r != SBOX_OK) {
            CFile::removeTree(tmp);
            return r;
        }

        std::string dir = snapshotDir(chainId);
        if (::rename(tmp.c_str(), dir.c_str()) != 0) {
            int32_t err = errno;
            CFile::removeTree(tmp);
            // --> Another process unpacked the same layer meanwhile.
            if ((err == ENOTEMPTY || err == EEXIST) && hasSnapshot(chainId)) {
                return SBOX_OK;
            }

            return -err;
        }

        if (_options.progress) {
            SProgress p;
            p.phase = EPP_EXTRACTED;
            p.digest = layer.digest;
            p.mediaType = layer.mediaType;
            p.current = p.total = uint64_t(layer.size);
            _options.progress(p);
        }

        return SBOX_OK;
    }

    /* Unpacks every layer of an image. */
    int32_t CSnapshotter::unpack(const SImageInfo& image) {
        if (image.manifest.layers.size() != image.config.diffIds.size()) {
            _lastError = "the manifest has " + std::to_string(image.manifest.layers.size()) + " layers but the config " +
                         std::to_string(image.config.diffIds.size()) + " diffIDs";
            return -EBADMSG;
        }

        std::string parent;
        for (size_t i = 0; i < image.manifest.layers.size(); ++i) {
            std::string chain;
            int32_t r = unpackLayer(image.manifest.layers[i], image.config.diffIds[i], parent, chain);
            if (r != SBOX_OK) {
                return r;
            }

            parent = chain;
        }

        return SBOX_OK;
    }

    /* Flattens an image into a directory. */
    int32_t CSnapshotter::flatten(const SImageInfo& image, const std::string& dir) {
        if (image.manifest.layers.size() != image.config.diffIds.size()) {
            _lastError = "layer count does not match the config's diffIDs";
            return -EBADMSG;
        }

        int32_t r = CFile::makeDirs(dir, 0755);
        if (r != SBOX_OK) {
            return r;
        }

        for (size_t i = 0; i < image.manifest.layers.size(); ++i) {
            const SDescriptor& layer = image.manifest.layers[i];
            std::string blob = _store->blobPath(layer.digest);
            CFd fd(blob.empty() ? -1 : ::open(blob.c_str(), O_RDONLY | O_CLOEXEC));
            if (!fd.isValid()) {
                _lastError = "layer " + layer.digest + " is not in the store";
                return -ENOENT;
            }

            archive::SExtractOptions xo;
            xo.whiteouts = archive::EWHT_APPLY;
            xo.ownership = archive::EOWN_AUTO;
            CDigester diff;
            archive::SPipelineHooks hooks;
            hooks.uncompressed = [&diff](const SReadOnlyByteSpan& s) { diff.update(s); };
            archive::CFdSource src(fd.get());
            r = archive::ExtractArchive(src, dir, xo, archive::ECOMP_AUTO, hooks);
            if (r != SBOX_OK) {
                _lastError = "extracting layer " + layer.digest + ": " + std::strerror(-r);
                return r;
            }

            std::string actual = diff.finish();
            if (actual != image.config.diffIds[i]) {
                _lastError = "layer " + layer.digest + " has diffID " + actual + ", the image config says " + image.config.diffIds[i];
                return -EBADMSG;
            }
        }

        return SBOX_OK;
    }

    /* Probes whether this process can mount overlayfs. */
    bool CSnapshotter::overlaySupported() {
        std::string probe = _store->path("containers/.probe-" + RandomHex(6));
        SMountPlan plan;
        plan.lowerDirs = { CFile::join(probe, "lower") };
        plan.upperDir = CFile::join(probe, "upper");
        plan.workDir = CFile::join(probe, "work");
        plan.target = CFile::join(probe, "merged");
        if (_rootless) {
            plan.options.push_back("userxattr");
        }

        for (const std::string& d : { plan.lowerDirs[0], plan.upperDir, plan.workDir, plan.target }) {
            if (CFile::makeDirs(d, 0755) != SBOX_OK) {
                CFile::removeTree(probe);
                return false;
            }
        }

        std::string saved = _lastError;
        bool ok = mountPlan(plan) == SBOX_OK;
        if (ok) {
            ::umount2(plan.target.c_str(), MNT_DETACH);
        }

        _lastError = saved;
        CFile::removeTree(probe);
        return ok;
    }

    /* Mounts an overlay plan. */
    int32_t CSnapshotter::mountPlan(const SMountPlan& plan) {
        if (plan.lowerDirs.empty() || plan.target.empty()) {
            return -EINVAL;
        }

        if (!_options.legacyMount) {
            int fsfd = int(::syscall(SYS_fsopen, "overlay", K_FSOPEN_CLOEXEC));
            if (fsfd >= 0) {
                CFd ctx(fsfd);
                bool fallback = false;
                int32_t err = SBOX_OK;
                for (size_t i = 0; i < plan.lowerDirs.size() && err == SBOX_OK; ++i) {
                    if (::syscall(SYS_fsconfig, fsfd, K_FSCONFIG_SET_STRING, "lowerdir+", plan.lowerDirs[i].c_str(), 0) != 0) {
                        // --> "lowerdir+" needs Linux 6.8; older kernels reject the key.
                        if (i == 0 && errno == EINVAL) {
                            fallback = true;
                            break;
                        }

                        err = -errno;
                    }
                }

                if (!fallback) {
                    if (err == SBOX_OK && !plan.upperDir.empty()) {
                        if (::syscall(SYS_fsconfig, fsfd, K_FSCONFIG_SET_STRING, "upperdir", plan.upperDir.c_str(), 0) != 0 ||
                            ::syscall(SYS_fsconfig, fsfd, K_FSCONFIG_SET_STRING, "workdir", plan.workDir.c_str(), 0) != 0) {
                            err = -errno;
                        }
                    }

                    for (const std::string& o : plan.options) {
                        if (err != SBOX_OK) {
                            break;
                        }

                        size_t eq = o.find('=');
                        long rc;
                        if (eq == std::string::npos) {
                            rc = ::syscall(SYS_fsconfig, fsfd, K_FSCONFIG_SET_FLAG, o.c_str(), nullptr, 0);
                        } else {
                            std::string key = o.substr(0, eq);
                            std::string value = o.substr(eq + 1);
                            rc = ::syscall(SYS_fsconfig, fsfd, K_FSCONFIG_SET_STRING, key.c_str(), value.c_str(), 0);
                        }

                        if (rc != 0) {
                            err = -errno;
                        }
                    }

                    if (err == SBOX_OK && ::syscall(SYS_fsconfig, fsfd, K_FSCONFIG_CMD_CREATE, nullptr, nullptr, 0) != 0) {
                        err = -errno;
                    }

                    if (err == SBOX_OK) {
                        int mfd = int(::syscall(SYS_fsmount, fsfd, K_FSMOUNT_CLOEXEC, 0));
                        if (mfd < 0) {
                            err = -errno;
                        } else {
                            CFd mnt(mfd);
                            if (::syscall(SYS_move_mount, mfd, "", AT_FDCWD, plan.target.c_str(), K_MOVE_MOUNT_F_EMPTY_PATH) != 0) {
                                err = -errno;
                            }
                        }
                    }

                    if (err != SBOX_OK) {
                        _lastError = std::string("overlay mount: ") + std::strerror(-err);
                        std::string log = fsContextLog(fsfd);
                        if (!log.empty()) {
                            _lastError += " (" + log + ")";
                        }
                    }

                    return err;
                }
            } else if (errno != ENOSYS) {
                int32_t err = -errno;
                _lastError = std::string("fsopen(overlay): ") + std::strerror(-err);
                return err;
            }
        }

        // --> Legacy mount(2): the data string must fit in a page. Too long absolute paths are
        // made relative to the snapshots directory (the chdir trick overlay2 uses).
        long page = ::sysconf(_SC_PAGESIZE);
        std::string data = plan.toMountData();
        if (long(data.size()) < page) {
            if (::mount("overlay", plan.target.c_str(), "overlay", 0, data.c_str()) != 0) {
                int32_t err = -errno;
                _lastError = std::string("mount(overlay): ") + std::strerror(-err);
                return err;
            }

            return SBOX_OK;
        }

        // --> Short names: <root>/l/<12+ hex> -> ../snapshots/<hex>/fs (the overlay2 trick), and the
        // mount runs with <root>/l as the working directory so lowerdir holds only the short names.
        std::string base = _store->path("snapshots") + "/";
        std::string linkDir = _store->path("l");
        CFile::makeDirs(linkDir, 0700);
        SMountPlan rel = plan;
        for (std::string& l : rel.lowerDirs) {
            if (l.compare(0, base.size(), base) != 0) {
                continue;
            }

            std::string tail = l.substr(base.size());
            std::string hex = tail.substr(0, tail.find('/'));
            std::string target = "../snapshots/" + tail;
            if (!IsFullHexId(hex)) {
                l = target;
                continue;
            }

            for (size_t len = 12; len <= 64; len += 4) {
                std::string name = hex.substr(0, len);
                std::string link = CFile::join(linkDir, name);
                char buf[512];
                ssize_t n = ::readlink(link.c_str(), buf, sizeof(buf) - 1);
                if (n >= 0 && std::string(buf, size_t(n)) == target) {
                    l = name;
                    break;
                }

                if (n < 0 && errno == ENOENT && (::symlink(target.c_str(), link.c_str()) == 0 || errno == EEXIST)) {
                    n = ::readlink(link.c_str(), buf, sizeof(buf) - 1);
                    if (n >= 0 && std::string(buf, size_t(n)) == target) {
                        l = name;
                        break;
                    }
                }
            }
        }

        base = linkDir;
        data = rel.toMountData();
        if (long(data.size()) >= page) {
            _lastError = "overlay mount data too long (" + std::to_string(data.size()) + " bytes) for this kernel";
            return -E2BIG;
        }

        CFd cwd(::open(".", O_PATH | O_DIRECTORY | O_CLOEXEC));
        if (::chdir(base.c_str()) != 0) {
            return -errno;
        }

        int32_t err = SBOX_OK;
        if (::mount("overlay", plan.target.c_str(), "overlay", 0, data.c_str()) != 0) {
            err = -errno;
            _lastError = std::string("mount(overlay): ") + std::strerror(-err);
        }

        if (cwd.isValid()) {
            (void)::fchdir(cwd.get());
        }

        return err;
    }

    /* Creates a container root. */
    int32_t CSnapshotter::prepare(const std::string& id, const SImageInfo& image, ESnapshotMode mode, SContainerInfo& out,
                                  bool mountNow, const std::string& target) {
        out = SContainerInfo();
        std::string cid = id.empty() ? RandomHex(32) : id;
        if (!validId(cid)) {
            _lastError = "invalid container ID " + cid;
            return -EINVAL;
        }

        if (mode == ESNAP_AUTO) {
            mode = overlaySupported() ? ESNAP_OVERLAY : ESNAP_COPY;
        }

        if (mode != ESNAP_OVERLAY && mode != ESNAP_COPY) {
            return -EINVAL;
        }

        std::string dir = _store->path("containers/" + cid);
        if (::mkdir(dir.c_str(), 0711) != 0) {
            int32_t err = -errno;
            _lastError = err == -EEXIST ? "container " + cid + " already exists" : std::string(std::strerror(-err));
            return err;
        }

        out.id = cid;
        out.imageId = image.id;
        out.imageName = image.repoTags.empty() ? std::string() : image.repoTags.front();
        out.manifestDigest = image.manifestDigest;
        out.mode = mode;
        out.created = NowRfc3339();
        out.chainIds = ChainIds(image.config.diffIds);

        // --> Write the metadata first: it is the GC lease for the snapshots and blobs.
        int32_t r = writeContainerMeta(dir, out);
        if (r != SBOX_OK) {
            CFile::removeTree(dir);
            return r;
        }

        if (mode == ESNAP_COPY) {
            out.rootfs = target.empty() ? CFile::join(dir, "rootfs") : target;
            r = flatten(image, out.rootfs);
        } else {
            r = unpack(image);
            if (r == SBOX_OK) {
                out.rootfs = target.empty() ? CFile::join(dir, "merged") : target;
                out.plan.upperDir = CFile::join(dir, "upper");
                out.plan.workDir = CFile::join(dir, "work");
                out.plan.target = out.rootfs;
                for (auto it = out.chainIds.rbegin(); it != out.chainIds.rend(); ++it) {
                    out.plan.lowerDirs.push_back(CFile::join(snapshotDir(*it), "fs"));
                }

                if (out.plan.lowerDirs.empty()) {
                    std::string empty = _store->path("snapshots/empty");
                    CFile::makeDirs(empty, 0755);
                    out.plan.lowerDirs.push_back(empty);
                }

                if (_rootless) {
                    out.plan.options.push_back("userxattr");
                }

                for (const std::string& d : { out.plan.upperDir, out.plan.workDir, out.rootfs }) {
                    if (r == SBOX_OK) {
                        r = CFile::makeDirs(d, 0755);
                    }
                }
            }
        }

        if (r == SBOX_OK) {
            r = writeContainerMeta(dir, out);
        }

        if (r == SBOX_OK && mode == ESNAP_OVERLAY && mountNow) {
            r = mountPlan(out.plan);
        }

        if (r != SBOX_OK) {
            std::string saved = _lastError;
            CFile::removeTree(dir);
            _lastError = saved;
            return r;
        }

        return SBOX_OK;
    }

    /* Reads a container's metadata. */
    int32_t CSnapshotter::container(const std::string& id, SContainerInfo& out) const {
        out = SContainerInfo();
        if (!validId(id)) {
            return -EINVAL;
        }

        CJson j;
        int32_t r = ReadJsonFile(_store->path("containers/" + id + "/meta.json"), j);
        if (r != SBOX_OK) {
            return r;
        }

        out.id = j.get("id").asString();
        out.imageId = j.get("imageId").asString();
        out.imageName = j.get("imageName").asString();
        out.manifestDigest = j.get("manifestDigest").asString();
        out.mode = ParseSnapshotMode(j.get("mode").asString());
        out.rootfs = j.get("rootfs").asString();
        out.chainIds = j.get("chainIds").asStrings();
        out.created = j.get("created").asString();
        const CJson& p = j.get("plan");
        out.plan.lowerDirs = p.get("lowerDirs").asStrings();
        out.plan.upperDir = p.get("upperDir").asString();
        out.plan.workDir = p.get("workDir").asString();
        out.plan.target = p.get("target").asString();
        out.plan.options = p.get("options").asStrings();
        return SBOX_OK;
    }

    /* Lists every container root. */
    int32_t CSnapshotter::listContainers(std::vector<SContainerInfo>& out) const {
        out.clear();
        std::vector<std::string> names;
        int32_t r = ListDirectory(_store->path("containers"), names);
        if (r != SBOX_OK) {
            return r;
        }

        std::sort(names.begin(), names.end());
        for (const std::string& n : names) {
            SContainerInfo c;
            if (container(n, c) == SBOX_OK) {
                out.push_back(std::move(c));
            }
        }

        return SBOX_OK;
    }

    /* Mounts a container root. */
    int32_t CSnapshotter::mount(const std::string& id, const std::string& target) {
        SContainerInfo c;
        int32_t r = container(id, c);
        if (r != SBOX_OK) {
            _lastError = "no such container root: " + id;
            return r;
        }

        if (c.mode != ESNAP_OVERLAY) {
            return SBOX_OK;
        }

        SMountPlan plan = c.plan;
        if (!target.empty()) {
            plan.target = target;
        }

        return mountPlan(plan);
    }

    /* Unmounts a container root. */
    int32_t CSnapshotter::unmount(const std::string& id, const std::string& target) {
        SContainerInfo c;
        int32_t r = container(id, c);
        if (r != SBOX_OK) {
            return r;
        }

        if (c.mode != ESNAP_OVERLAY) {
            return SBOX_OK;
        }

        std::string t = target.empty() ? c.plan.target : target;
        if (::umount2(t.c_str(), 0) != 0) {
            if (errno == EINVAL || errno == ENOENT) {
                return SBOX_OK;
            }

            if (errno == EBUSY && ::umount2(t.c_str(), MNT_DETACH) == 0) {
                return SBOX_OK;
            }

            int32_t err = -errno;
            _lastError = "umount " + t + ": " + std::strerror(-err);
            return err;
        }

        return SBOX_OK;
    }

    /* Unmounts and deletes a container root. */
    int32_t CSnapshotter::remove(const std::string& id) {
        if (!validId(id)) {
            return -EINVAL;
        }

        std::string dir = _store->path("containers/" + id);
        if (!CFile::exists(dir)) {
            return -ENOENT;
        }

        int32_t r = unmount(id);
        if (r != SBOX_OK && r != -ENOENT) {
            return r;
        }

        return CFile::removeTree(dir);
    }

    /* Commits a container's changes into a new image. */
    int32_t CSnapshotter::commit(const std::string& id, const SCommitOptions& options, SImageInfo& out) {
        SContainerInfo c;
        int32_t r = container(id, c);
        if (r != SBOX_OK) {
            _lastError = "no such container root: " + id;
            return r;
        }

        if (c.mode != ESNAP_OVERLAY) {
            _lastError = "commit needs an overlay container (copy containers have no change set)";
            return -ENOTSUP;
        }

        SDescriptor parentDesc;
        parentDesc.digest = c.manifestDigest;
        parentDesc.size = _store->blobSize(c.manifestDigest);
        SImageInfo parent;
        r = _store->loadImage(parentDesc, parent);
        if (r != SBOX_OK) {
            _lastError = "the container's image " + c.imageId + " is gone";
            return r;
        }

        CLease lease;
        lease.open(*_store);

        // --> The upper directory, whiteouts turned back into ".wh." entries, as a gzip layer.
        CBlobWriter writer;
        r = writer.open(*_store);
        if (r != SBOX_OK) {
            return r;
        }

        BlobSink sink(writer);
        CDigester diff;
        archive::SPipelineHooks hooks;
        hooks.uncompressed = [&diff](const SReadOnlyByteSpan& s) { diff.update(s); };
        archive::STreeOptions to;
        to.overlayWhiteouts = true;
        to.xattrs = true;
        r = archive::WriteTreeArchive(c.plan.upperDir, sink, archive::ECOMP_GZIP, options.compressionLevel, to, hooks);
        if (r != SBOX_OK) {
            _lastError = std::string("archiving the upper directory: ") + std::strerror(-r);
            return r;
        }

        int64_t layerSize = int64_t(writer.offset());
        std::string layerDigest;
        r = writer.commit(std::string(), -1, &layerDigest);
        if (r != SBOX_OK) {
            return r;
        }

        lease.addBlob(layerDigest);
        std::string diffId = diff.finish();
        _store->recordDiffId(layerDigest, diffId);

        bool docker = parent.manifest.mediaType == MT_DOCKER_MANIFEST;
        std::string now = NowRfc3339();
        SImageConfig cfg = parent.config;
        if (options.hasConfigOverride) {
            const SImageConfig& o = options.config;
            cfg.user = o.user;
            cfg.workingDir = o.workingDir;
            cfg.stopSignal = o.stopSignal;
            cfg.env = o.env;
            cfg.entrypoint = o.entrypoint;
            cfg.cmd = o.cmd;
            cfg.exposedPorts = o.exposedPorts;
            cfg.volumes = o.volumes;
            cfg.labels = o.labels;
        }

        cfg.diffIds.push_back(diffId);
        cfg.created = now;
        if (!options.author.empty()) {
            cfg.author = options.author;
        }

        CJson raw = cfg.toJson();
        CJson h = CJson::object();
        h.set("created", now);
        h.set("created_by", options.createdBy);
        if (!options.author.empty()) {
            h.set("author", options.author);
        }

        if (!options.comment.empty()) {
            h.set("comment", options.comment);
        }

        raw["history"].push(std::move(h));
        SDescriptor configDesc;
        r = _store->writeJsonBlob(raw, docker ? MT_DOCKER_CONFIG : MT_OCI_CONFIG, configDesc);
        if (r != SBOX_OK) {
            return r;
        }

        lease.addBlob(configDesc.digest);
        SManifest m = parent.manifest;
        m.config = configDesc;
        SDescriptor layer;
        layer.mediaType = docker ? MT_DOCKER_LAYER_GZIP : MT_OCI_LAYER_GZIP;
        layer.digest = layerDigest;
        layer.size = layerSize;
        m.layers.push_back(layer);
        if (m.mediaType.empty()) {
            m.mediaType = MT_OCI_MANIFEST;
        }

        SDescriptor manifestDesc;
        r = _store->writeJsonBlob(m.toJson(), m.mediaType, manifestDesc);
        if (r != SBOX_OK) {
            return r;
        }

        std::string name;
        if (!options.reference.empty()) {
            SReference ref;
            if (ParseDockerReference(options.reference, ref) != SBOX_OK || ref.hasDigest()) {
                _lastError = "invalid reference " + options.reference;
                return -EINVAL;
            }

            name = ref.toString();
        }

        r = _store->setRecord(name, manifestDesc);
        if (r != SBOX_OK) {
            return r;
        }

        return _store->loadImage(manifestDesc, out);
    }

}
}
