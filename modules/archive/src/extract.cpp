#include <sbox/archive/extract.hpp>
#include "fsutil.hpp"
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <unordered_set>

namespace sbox {
namespace archive {

    namespace {

        constexpr const char* WH_PREFIX = ".wh.";
        constexpr const char* WH_META_PREFIX = ".wh..wh.";
        constexpr const char* WH_OPAQUE = ".wh..wh..opq";

        /* Joins two cleaned relative paths. */
        std::string joinRel(const std::string& a, const std::string& b) {
            if (a.empty()) {
                return b;
            }

            return a + "/" + b;
        }

        /* Converts an archive time to a timespec. */
        struct timespec toTimespec(const STarTime& t) {
            struct timespec ts;
            ts.tv_sec = time_t(t.sec);
            ts.tv_nsec = long(t.nsec);
            return ts;
        }

    }

    /* Cleans an archive path lexically. */
    int32_t CleanArchivePath(std::string_view path, std::string& out) {
        out.clear();
        if (path.find('\0') != std::string_view::npos) {
            return -EINVAL;
        }

        std::vector<std::string_view> stack;
        size_t start = 0;
        while (start <= path.size()) {
            size_t slash = path.find('/', start);
            if (slash == std::string_view::npos) {
                slash = path.size();
            }

            std::string_view c = path.substr(start, slash - start);
            start = slash + 1;
            if (c.empty() || c == ".") {
                continue;
            }

            if (c == "..") {
                if (stack.empty()) {
                    return -EXDEV;
                }

                stack.pop_back();
                continue;
            }

            stack.push_back(c);
        }

        for (size_t i = 0; i < stack.size(); ++i) {
            if (i) {
                out += '/';
            }

            out.append(stack[i].data(), stack[i].size());
        }

        return SBOX_OK;
    }

    struct CExtractor::SImpl {
        SExtractOptions opt;
        CFd root;
        bool noOpenat2;
        bool privileged;
        SExtractStats stats;

        STarEntry entry;
        std::string rel;
        CFd file;
        bool writing = false;

        std::string cachedRel;
        CFd cachedFd;
        bool cacheValid = false;

        /* Directory metadata applied at the end. */
        struct Deferred {
            std::string rel;
            uint32_t mode;
            STarTime mtime;
            STarTime atime;
        };

        std::vector<Deferred> deferred;
        std::unordered_set<std::string> unpacked;

        explicit SImpl(const SExtractOptions& o) : opt(o), noOpenat2(o.noOpenat2), privileged(::geteuid() == 0) {}

        /* Reports a non-fatal event. */
        void notice(EExtractNotice kind, const std::string& path, int32_t error) {
            if (opt.notice) {
                opt.notice(SExtractNotice{ kind, path, error });
            }
        }

        /* True when ownership should be applied. */
        bool wantChown() const noexcept {
            return opt.ownership == EOWN_PRESERVE || (opt.ownership == EOWN_AUTO && privileged);
        }

        /* Maps archive ids to host ids. */
        int32_t mapIds(int64_t uid, int64_t gid, uid_t& u, gid_t& g) const noexcept {
            int64_t mu = uid + opt.uidShift;
            int64_t mg = gid + opt.gidShift;
            if (mu < 0 || mg < 0 || mu > 0xFFFFFFFEll || mg > 0xFFFFFFFEll) {
                return -EOVERFLOW;
            }

            u = uid_t(mu);
            g = gid_t(mg);
            return SBOX_OK;
        }

        /* Turns a chown failure into an error or a notice according to the policy. */
        int32_t chownFailed(int32_t err, const std::string& path) {
            if (opt.ownership == EOWN_PRESERVE) {
                return err;
            }

            notice(EXN_CHOWN_FAILED, path, err);
            return SBOX_OK;
        }

        /* Turns an xattr failure into an error or a notice according to the policy. */
        int32_t xattrFailed(int32_t err, const std::string& path) {
            if (opt.xattrErrorsFatal) {
                return err;
            }

            notice(EXN_XATTR_FAILED, path, err);
            return SBOX_OK;
        }

        /* Applies ownership via a callback that performs the actual chown. */
        template<typename F>
        int32_t applyOwner(const STarEntry& e, const std::string& path, F&& chownFn) {
            if (!wantChown()) {
                return SBOX_OK;
            }

            uid_t u;
            gid_t g;
            int32_t rc = mapIds(e.uid, e.gid, u, g);
            if (rc < 0) {
                return opt.ownership == EOWN_PRESERVE ? rc : chownFailed(rc, path);
            }

            if (chownFn(u, g) != 0) {
                return chownFailed(-errno, path);
            }

            return SBOX_OK;
        }

        /* Applies xattrs via a callback. */
        template<typename F>
        int32_t applyXattrs(const STarEntry& e, const std::string& path, F&& setFn) {
            if (!opt.xattrs) {
                return SBOX_OK;
            }

            for (const auto& x : e.xattrs) {
                int32_t rc = setFn(x.first, x.second);
                if (rc < 0) {
                    rc = xattrFailed(rc, path);
                    if (rc < 0) {
                        return rc;
                    }
                }
            }

            return SBOX_OK;
        }

        /* Times of an entry (atime falls back to mtime). */
        void timesOf(const STarEntry& e, struct timespec ts[2]) const {
            ts[0] = toTimespec(e.hasAtime ? e.atime : e.mtime);
            ts[1] = toTimespec(e.mtime);
        }

        /* Creates the missing directories of `dirRel`. */
        int32_t makeDirs(const std::string& dirRel) {
            size_t pos = 0;
            while (pos <= dirRel.size()) {
                size_t slash = dirRel.find('/', pos);
                if (slash == std::string::npos) {
                    slash = dirRel.size();
                }

                std::string prefix = dirRel.substr(0, slash);
                pos = slash + 1;
                CFd fd;
                int32_t rc = fsutil::openDirInRoot(root.get(), prefix, noOpenat2, fd);
                if (rc == SBOX_OK) {
                    continue;
                }

                if (rc != -ENOENT) {
                    return rc;
                }

                std::string parent;
                std::string leaf;
                fsutil::splitPath(prefix, parent, leaf);
                CFd pfd;
                rc = fsutil::openDirInRoot(root.get(), parent, noOpenat2, pfd);
                if (rc < 0) {
                    return rc;
                }

                if (::mkdirat(pfd.get(), leaf.c_str(), 0755) != 0 && errno != EEXIST) {
                    return -errno;
                }

                ::fchmodat(pfd.get(), leaf.c_str(), 0755, 0);
                if (wantChown()) {
                    uid_t u;
                    gid_t g;
                    if (mapIds(0, 0, u, g) == SBOX_OK && ::fchownat(pfd.get(), leaf.c_str(), u, g, AT_SYMLINK_NOFOLLOW) != 0) {
                        rc = chownFailed(-errno, prefix);
                        if (rc < 0) {
                            return rc;
                        }
                    }
                }

                // --> The name may be a dangling symlink (mkdirat said EEXIST): the reopen tells.
                rc = fsutil::openDirInRoot(root.get(), prefix, noOpenat2, fd);
                if (rc < 0) {
                    return rc;
                }
            }

            return SBOX_OK;
        }

        /* Returns a (cached) O_PATH descriptor of directory `dirRel`, creating it when asked. */
        int32_t parentFd(const std::string& dirRel, bool create, int& fd) {
            if (cacheValid && cachedRel == dirRel) {
                fd = cachedFd.get();
                return SBOX_OK;
            }

            cacheValid = false;
            int32_t rc = fsutil::openDirInRoot(root.get(), dirRel, noOpenat2, cachedFd);
            if (rc == -ENOENT && create) {
                rc = makeDirs(dirRel);
                if (rc == SBOX_OK) {
                    rc = fsutil::openDirInRoot(root.get(), dirRel, noOpenat2, cachedFd);
                }
            }

            if (rc < 0) {
                return rc;
            }

            cachedRel = dirRel;
            cacheValid = true;
            fd = cachedFd.get();
            return SBOX_OK;
        }

        /* Records an extracted path (and its parents) for opaque-directory handling. */
        void markUnpacked(const std::string& path) {
            if (opt.whiteouts != EWHT_APPLY) {
                return;
            }

            std::string p = path;
            while (!p.empty() && unpacked.insert(p).second) {
                size_t slash = p.rfind('/');
                if (slash == std::string::npos) {
                    break;
                }

                p.resize(slash);
            }
        }

        /* Removes whatever exists at `leaf` unless it is a directory and `keepDir`. */
        int32_t clearExisting(int pfd, const std::string& leaf, bool keepDir, bool& isDir) {
            struct stat st{};
            isDir = false;
            if (::fstatat(pfd, leaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
                return errno == ENOENT ? SBOX_OK : -errno;
            }

            if (keepDir && S_ISDIR(st.st_mode)) {
                isDir = true;
                return SBOX_OK;
            }

            // --> Something is being replaced: a cached parent below it may be stale now.
            cacheValid = false;
            return fsutil::removeTreeAt(pfd, leaf.c_str());
        }

        /* Applies ownership, mode, xattrs and times to a non-regular, non-directory entry. */
        int32_t applyMetaAt(int pfd, const std::string& leaf, const STarEntry& e, bool symlink) {
            int32_t rc = applyOwner(e, rel, [&](uid_t u, gid_t g) {
                return ::fchownat(pfd, leaf.c_str(), u, g, AT_SYMLINK_NOFOLLOW);
            });

            if (rc < 0) {
                return rc;
            }

            if (!symlink && ::fchmodat(pfd, leaf.c_str(), e.mode & 07777u, 0) != 0) {
                return -errno;
            }

            rc = applyXattrs(e, rel, [&](const std::string& k, const std::string& v) {
                return fsutil::setXattrAt(pfd, leaf.c_str(), k, v);
            });

            if (rc < 0) {
                return rc;
            }

            if (opt.preserveTimes) {
                struct timespec ts[2];
                timesOf(e, ts);
                if (::utimensat(pfd, leaf.c_str(), ts, AT_SYMLINK_NOFOLLOW) != 0 && errno != EOPNOTSUPP) {
                    return -errno;
                }
            }

            return SBOX_OK;
        }

        /* Handles ".wh.*" entries according to the whiteout mode. */
        int32_t whiteout(const std::string& parentRel, const std::string& leaf, const STarEntry& e) {
            stats.whiteouts++;
            if (leaf == WH_OPAQUE) {
                return opaque(parentRel);
            }

            if (leaf.compare(0, std::strlen(WH_META_PREFIX), WH_META_PREFIX) == 0) {
                // --> aufs bookkeeping (".wh..wh.plnk", ".wh..wh.aufs"): meaningless here.
                notice(EXN_IGNORED_ENTRY, joinRel(parentRel, leaf), 0);
                return SBOX_OK;
            }

            std::string name = leaf.substr(std::strlen(WH_PREFIX));
            if (name.empty() || name == "." || name == "..") {
                return -EINVAL;
            }

            std::string target = joinRel(parentRel, name);
            int pfd = -1;
            if (opt.whiteouts == EWHT_APPLY) {
                int32_t rc = parentFd(parentRel, false, pfd);
                if (rc == -ENOENT || rc == -ENOTDIR) {
                    return SBOX_OK;
                }

                if (rc < 0) {
                    return rc;
                }

                cacheValid = false;
                return fsutil::removeTreeAt(pfd, name.c_str());
            }

            int32_t rc = parentFd(parentRel, true, pfd);
            if (rc < 0) {
                return rc;
            }

            bool isDir = false;
            rc = clearExisting(pfd, name, false, isDir);
            if (rc < 0) {
                return rc;
            }

            if (opt.whiteouts == EWHT_OVERLAY) {
                if (::mknodat(pfd, name.c_str(), S_IFCHR | 0, makedev(0, 0)) != 0) {
                    return -errno;
                }

                return applyOwner(e, target, [&](uid_t u, gid_t g) {
                    return ::fchownat(pfd, name.c_str(), u, g, AT_SYMLINK_NOFOLLOW);
                });
            }

            // --> userxattr mode: an empty file tagged as whiteout, and the parent marked as
            // possibly containing such entries ("x") unless it is already opaque ("y").
            int fd = ::openat(pfd, name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd < 0) {
                return -errno;
            }

            CFd f(fd);
            if (::fsetxattr(fd, "user.overlay.whiteout", "y", 1, 0) != 0) {
                return -errno;
            }

            rc = applyOwner(e, target, [&](uid_t u, gid_t g) { return ::fchown(fd, u, g); });
            if (rc < 0) {
                return rc;
            }

            CFd dir;
            rc = openRealDir(parentRel, dir);
            if (rc < 0) {
                return rc;
            }

            char cur[4] = { 0 };
            ssize_t n = ::fgetxattr(dir.get(), "user.overlay.opaque", cur, sizeof(cur));
            if (!(n == 1 && cur[0] == 'y') && ::fsetxattr(dir.get(), "user.overlay.opaque", "x", 1, 0) != 0) {
                return -errno;
            }

            return SBOX_OK;
        }

        /* Opens directory `dirRel` (inside the root) for reading. */
        int32_t openRealDir(const std::string& dirRel, CFd& out) {
            CFd path;
            int32_t rc = fsutil::openDirInRoot(root.get(), dirRel, noOpenat2, path);
            if (rc < 0) {
                return rc;
            }

            int fd = ::openat(path.get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (fd < 0) {
                return -errno;
            }

            out.reset(fd);
            return SBOX_OK;
        }

        /* Handles ".wh..wh..opq" for directory `dirRel`. */
        int32_t opaque(const std::string& dirRel) {
            if (opt.whiteouts == EWHT_APPLY) {
                CFd dir;
                int32_t rc = openRealDir(dirRel, dir);
                if (rc == -ENOENT || rc == -ENOTDIR) {
                    return SBOX_OK;
                }

                if (rc < 0) {
                    return rc;
                }

                cacheValid = false;
                return clearUnlisted(dir.get(), dirRel);
            }

            int32_t rc = makeDirs(dirRel);
            if (rc < 0) {
                return rc;
            }

            CFd dir;
            rc = openRealDir(dirRel, dir);
            if (rc < 0) {
                return rc;
            }

            const char* key = opt.whiteouts == EWHT_OVERLAY ? "trusted.overlay.opaque" : "user.overlay.opaque";
            if (::fsetxattr(dir.get(), key, "y", 1, 0) != 0) {
                return -errno;
            }

            return SBOX_OK;
        }

        /* Removes everything below `dfd` that this layer did not unpack (opaque directory, apply mode). */
        int32_t clearUnlisted(int dfd, const std::string& dirRel) {
            int dup = ::openat(dfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (dup < 0) {
                return -errno;
            }

            DIR* d = ::fdopendir(dup);
            if (!d) {
                int32_t err = -errno;
                ::close(dup);
                return err;
            }

            std::vector<std::string> names;
            while (struct dirent* ent = ::readdir(d)) {
                if (std::strcmp(ent->d_name, ".") && std::strcmp(ent->d_name, "..")) {
                    names.emplace_back(ent->d_name);
                }
            }

            ::closedir(d);
            for (const std::string& n : names) {
                std::string childRel = joinRel(dirRel, n);
                if (!unpacked.count(childRel)) {
                    int32_t rc = fsutil::removeTreeAt(dfd, n.c_str());
                    if (rc < 0) {
                        return rc;
                    }

                    continue;
                }

                int cfd = ::openat(dfd, n.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                if (cfd >= 0) {
                    CFd child(cfd);
                    int32_t rc = clearUnlisted(cfd, childRel);
                    if (rc < 0) {
                        return rc;
                    }
                }
            }

            return SBOX_OK;
        }

        /* Creates (or keeps) a directory and applies ownership and xattrs; mode and times are deferred. */
        int32_t makeDirEntry(int pfd, const std::string& leaf, const STarEntry& e) {
            bool isDir = false;
            int32_t rc = clearExisting(pfd, leaf, true, isDir);
            if (rc < 0) {
                return rc;
            }

            if (!isDir && ::mkdirat(pfd, leaf.c_str(), 0700) != 0) {
                return -errno;
            }

            int fd = ::openat(pfd, leaf.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) {
                return -errno;
            }

            CFd dir(fd);
            return dirMeta(fd, e);
        }

        /* Ownership and xattrs of a directory, plus the deferred mode/times record. */
        int32_t dirMeta(int fd, const STarEntry& e) {
            int32_t rc = applyOwner(e, rel, [&](uid_t u, gid_t g) { return ::fchown(fd, u, g); });
            if (rc < 0) {
                return rc;
            }

            rc = applyXattrs(e, rel, [&](const std::string& k, const std::string& v) {
                return ::fsetxattr(fd, k.c_str(), v.data(), v.size(), 0) == 0 ? SBOX_OK : -errno;
            });

            if (rc < 0) {
                return rc;
            }

            deferred.push_back(Deferred{ rel, e.mode & 07777u, e.mtime, e.hasAtime ? e.atime : e.mtime });
            stats.dirs++;
            return SBOX_OK;
        }

        /* Creates a hardlink to an earlier entry. */
        int32_t makeHardlink(int pfd, const std::string& leaf, const STarEntry& e) {
            std::string trel;
            int32_t rc = CleanArchivePath(e.linkPath, trel);
            if (rc < 0) {
                return rc;
            }

            if (trel.empty()) {
                return -EPERM;
            }

            if (trel == rel) {
                return SBOX_OK;
            }

            std::string tparent;
            std::string tleaf;
            fsutil::splitPath(trel, tparent, tleaf);
            CFd tfd;
            rc = fsutil::openDirInRoot(root.get(), tparent, noOpenat2, tfd);
            if (rc < 0) {
                return rc;
            }

            struct stat ts{};
            if (::fstatat(tfd.get(), tleaf.c_str(), &ts, AT_SYMLINK_NOFOLLOW) != 0) {
                return -errno;
            }

            if (S_ISDIR(ts.st_mode)) {
                return -EPERM;
            }

            struct stat ds{};
            if (::fstatat(pfd, leaf.c_str(), &ds, AT_SYMLINK_NOFOLLOW) == 0) {
                if (ds.st_dev == ts.st_dev && ds.st_ino == ts.st_ino) {
                    return SBOX_OK;
                }

                cacheValid = false;
                rc = fsutil::removeTreeAt(pfd, leaf.c_str());
                if (rc < 0) {
                    return rc;
                }
            }

            if (::linkat(tfd.get(), tleaf.c_str(), pfd, leaf.c_str(), 0) != 0) {
                return -errno;
            }

            stats.hardlinks++;
            return SBOX_OK;
        }

        /* Creates a char/block device or fifo. */
        int32_t makeNode(int pfd, const std::string& leaf, const STarEntry& e) {
            mode_t kind = e.type == ETAR_CHAR ? S_IFCHR : (e.type == ETAR_BLOCK ? S_IFBLK : S_IFIFO);
            if (kind != S_IFIFO && !opt.devices) {
                notice(EXN_DEVICE_SKIPPED, rel, 0);
                stats.skipped++;
                return SBOX_OK;
            }

            bool isDir = false;
            int32_t rc = clearExisting(pfd, leaf, false, isDir);
            if (rc < 0) {
                return rc;
            }

            dev_t dev = kind == S_IFIFO ? 0 : makedev(e.devMajor, e.devMinor);
            if (::mknodat(pfd, leaf.c_str(), kind | 0600, dev) != 0) {
                if (kind != S_IFIFO && (errno == EPERM || errno == EACCES)) {
                    notice(EXN_DEVICE_SKIPPED, rel, -errno);
                    stats.skipped++;
                    return SBOX_OK;
                }

                return -errno;
            }

            stats.devices++;
            return applyMetaAt(pfd, leaf, e, false);
        }

        /* Applies the deferred directory modes and times (last record per directory wins). */
        int32_t finishDirs() {
            std::unordered_set<std::string> seen;
            for (size_t i = deferred.size(); i-- > 0;) {
                const Deferred& d = deferred[i];
                if (!seen.insert(d.rel).second) {
                    continue;
                }

                CFd dir;
                int32_t rc;
                if (d.rel.empty()) {
                    int fd = ::openat(root.get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                    rc = fd < 0 ? -errno : SBOX_OK;
                    dir.reset(fd);
                } else {
                    std::string parent;
                    std::string leaf;
                    fsutil::splitPath(d.rel, parent, leaf);
                    CFd pfd;
                    rc = fsutil::openDirInRoot(root.get(), parent, noOpenat2, pfd);
                    if (rc == SBOX_OK) {
                        int fd = ::openat(pfd.get(), leaf.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                        rc = fd < 0 ? -errno : SBOX_OK;
                        dir.reset(fd);
                    }
                }

                if (rc == -ENOENT || rc == -ENOTDIR || rc == -ELOOP) {
                    // --> Removed or replaced by a later entry or whiteout.
                    continue;
                }

                if (rc < 0) {
                    return rc;
                }

                if (::fchmod(dir.get(), d.mode) != 0) {
                    return -errno;
                }

                if (opt.preserveTimes) {
                    struct timespec ts[2] = { toTimespec(d.atime), toTimespec(d.mtime) };
                    if (::futimens(dir.get(), ts) != 0) {
                        return -errno;
                    }
                }
            }

            deferred.clear();
            return SBOX_OK;
        }
    };

    /* Creates an extractor. */
    CExtractor::CExtractor(const SExtractOptions& options) : _impl(std::make_unique<SImpl>(options)) {}

    /* Destroys the extractor. */
    CExtractor::~CExtractor() = default;

    /* Opens the target root by path. */
    int32_t CExtractor::open(const std::string& root) {
        int fd = ::open(root.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) {
            return -errno;
        }

        _impl->root.reset(fd);
        _impl->cacheValid = false;
        return SBOX_OK;
    }

    /* Opens the target root from a descriptor. */
    int32_t CExtractor::open(int rootFd) {
        int fd = ::openat(rootFd, ".", O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) {
            return -errno;
        }

        _impl->root.reset(fd);
        _impl->cacheValid = false;
        return SBOX_OK;
    }

    /* Counters. */
    const SExtractStats& CExtractor::stats() const noexcept {
        return _impl->stats;
    }

    /* Creates or replaces one entry. */
    int32_t CExtractor::onEntry(const STarEntry& e) {
        SImpl& s = *_impl;
        if (!s.root.isValid()) {
            return -EBADF;
        }

        s.stats.entries++;
        s.writing = false;
        s.file.reset();

        int32_t rc = CleanArchivePath(e.path, s.rel);
        if (rc == SBOX_OK && e.type == ETAR_HARDLINK) {
            std::string trel;
            rc = CleanArchivePath(e.linkPath, trel);
        }

        if (rc == -EXDEV && s.opt.skipUnsafe) {
            s.notice(EXN_UNSAFE_SKIPPED, e.path, rc);
            s.stats.skipped++;
            return SBOX_OK;
        }

        if (rc < 0) {
            return rc;
        }

        std::string parent;
        std::string leaf;
        fsutil::splitPath(s.rel, parent, leaf);

        if (s.opt.whiteouts != EWHT_NONE && leaf.compare(0, 4, WH_PREFIX) == 0) {
            return s.whiteout(parent, leaf, e);
        }

        if (s.rel.empty()) {
            if (e.type != ETAR_DIR) {
                return -EINVAL;
            }

            // --> "./" carries the metadata of the root directory itself.
            int fd = ::openat(s.root.get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (fd < 0) {
                return -errno;
            }

            CFd dir(fd);
            return s.dirMeta(fd, e);
        }

        int pfd = -1;
        rc = s.parentFd(parent, true, pfd);
        if (rc < 0) {
            return rc;
        }

        switch (e.type) {
        case ETAR_DIR:
            rc = s.makeDirEntry(pfd, leaf, e);
            break;

        case ETAR_FILE: {
            bool isDir = false;
            rc = s.clearExisting(pfd, leaf, false, isDir);
            if (rc < 0) {
                return rc;
            }

            int fd = ::openat(pfd, leaf.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd < 0) {
                return -errno;
            }

            s.file.reset(fd);
            s.entry = e;
            s.writing = true;
            s.stats.files++;
            break;
        }

        case ETAR_SYMLINK: {
            bool isDir = false;
            rc = s.clearExisting(pfd, leaf, false, isDir);
            if (rc < 0) {
                return rc;
            }

            if (::symlinkat(e.linkPath.c_str(), pfd, leaf.c_str()) != 0) {
                return -errno;
            }

            s.stats.symlinks++;
            rc = s.applyMetaAt(pfd, leaf, e, true);
            break;
        }

        case ETAR_HARDLINK:
            rc = s.makeHardlink(pfd, leaf, e);
            break;

        case ETAR_CHAR:
        case ETAR_BLOCK:
        case ETAR_FIFO:
            rc = s.makeNode(pfd, leaf, e);
            break;

        default:
            return -EINVAL;
        }

        if (rc == SBOX_OK) {
            s.markUnpacked(s.rel);
        }

        return rc;
    }

    /* Writes file data. */
    int32_t CExtractor::onData(const SReadOnlyByteSpan& data) {
        SImpl& s = *_impl;
        if (!s.writing) {
            return SBOX_OK;
        }

        const uint8_t* p = data.data;
        size_t left = data.size;
        while (left) {
            ssize_t n = ::write(s.file.get(), p, left);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }

                return -errno;
            }

            p += n;
            left -= size_t(n);
        }

        s.stats.bytes += data.size;
        return SBOX_OK;
    }

    /* Applies metadata of a regular file. */
    int32_t CExtractor::onEntryEnd() {
        SImpl& s = *_impl;
        if (!s.writing) {
            return SBOX_OK;
        }

        s.writing = false;
        const int fd = s.file.get();
        const STarEntry& e = s.entry;
        int32_t rc = s.applyOwner(e, s.rel, [&](uid_t u, gid_t g) { return ::fchown(fd, u, g); });
        if (rc < 0) {
            return rc;
        }

        // --> After chown, which clears setuid/setgid and file capabilities.
        if (::fchmod(fd, e.mode & 07777u) != 0) {
            return -errno;
        }

        rc = s.applyXattrs(e, s.rel, [&](const std::string& k, const std::string& v) {
            return ::fsetxattr(fd, k.c_str(), v.data(), v.size(), 0) == 0 ? SBOX_OK : -errno;
        });

        if (rc < 0) {
            return rc;
        }

        if (s.opt.preserveTimes) {
            struct timespec ts[2];
            s.timesOf(e, ts);
            if (::futimens(fd, ts) != 0) {
                return -errno;
            }
        }

        s.file.reset();
        return SBOX_OK;
    }

    /* Applies deferred directory metadata. */
    int32_t CExtractor::onEnd() {
        _impl->file.reset();
        _impl->cacheValid = false;
        _impl->cachedFd.reset();
        return _impl->finishDirs();
    }

    namespace {

        /* Builds sink chains: [tap compressed] -> [decoder] -> [tap uncompressed] -> tar. */
        struct Chain {
            CTarSink tar;
            std::unique_ptr<CTapSink> tapU;
            std::unique_ptr<CCodecSink> dec;
            std::unique_ptr<CTapSink> tapC;
            IByteSink* top = nullptr;

            Chain(CExtractor& ex, ECompression compression, const SPipelineHooks& hooks) : tar(ex) {
                IByteSink* cur = &tar;
                if (hooks.uncompressed) {
                    tapU = std::make_unique<CTapSink>(*cur, hooks.uncompressed);
                    cur = tapU.get();
                }

                if (compression != ECOMP_NONE) {
                    dec = std::make_unique<CCodecSink>(CreateDecoder(compression), *cur);
                    cur = dec.get();
                }

                if (hooks.compressed) {
                    tapC = std::make_unique<CTapSink>(*cur, hooks.compressed);
                    cur = tapC.get();
                }

                top = cur;
            }
        };

    }

    /* Extracts from a synchronous source. */
    int32_t ExtractArchive(IByteSource& source, const std::string& root, const SExtractOptions& options,
                           ECompression compression, const SPipelineHooks& hooks, SExtractStats* stats) {
        if (compression == ECOMP_INVALID) {
            return -EINVAL;
        }

        CExtractor ex(options);
        int32_t rc = ex.open(root);
        if (rc < 0) {
            return rc;
        }

        Chain chain(ex, compression, hooks);
        rc = Pump(source, *chain.top);
        if (stats) {
            *stats = ex.stats();
        }

        return rc;
    }

    /* Extracts from a coroutine stream. */
    TTask<int32_t> ExtractArchiveAsync(IStream& stream, std::string root, SExtractOptions options,
                                       ECompression compression, SPipelineHooks hooks, SExtractStats* stats,
                                       int64_t timeoutMs) {
        if (compression == ECOMP_INVALID) {
            co_return -EINVAL;
        }

        CExtractor ex(options);
        int32_t rc = ex.open(root);
        if (rc < 0) {
            co_return rc;
        }

        Chain chain(ex, compression, hooks);
        rc = co_await PumpStreamToSink(stream, *chain.top, timeoutMs);
        if (stats) {
            *stats = ex.stats();
        }

        co_return rc;
    }

}
}
