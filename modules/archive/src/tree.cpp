#include <sbox/archive/tree.hpp>
#include "fsutil.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <deque>
#include <dirent.h>
#include <fcntl.h>
#include <map>
#include <sys/sysmacros.h>
#include <unistd.h>

namespace sbox {
namespace archive {

    namespace {

        /* Lists a directory's names, sorted bytewise. */
        int32_t listDir(int fd, std::vector<std::string>& names) {
            names.clear();
            int dup = ::openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (dup < 0) {
                return -errno;
            }

            DIR* d = ::fdopendir(dup);
            if (!d) {
                int32_t err = -errno;
                ::close(dup);
                return err;
            }

            errno = 0;
            while (struct dirent* ent = ::readdir(d)) {
                if (std::strcmp(ent->d_name, ".") && std::strcmp(ent->d_name, "..")) {
                    names.emplace_back(ent->d_name);
                }
            }

            ::closedir(d);
            std::sort(names.begin(), names.end());
            return SBOX_OK;
        }

        /* True for the xattrs overlayfs uses for its own bookkeeping. */
        bool isOverlayXattr(const std::string& name) {
            return name.compare(0, 16, "trusted.overlay.") == 0 || name.compare(0, 13, "user.overlay.") == 0;
        }

        /*
         * Walks a directory tree and emits tar entries one step at a time, so both the push
         * (WriteTree) and the pull (CTreeTarSource) producers share it.
         */
        class TreeWalker {
        private:
            struct Frame {
                CFd fd;
                std::string rel;
                std::vector<std::string> names;
                size_t idx = 0;
            };

            STreeOptions _opt;
            std::string _rootPath;
            std::string _prefix;
            CFd _root;
            std::vector<Frame> _stack;
            std::deque<STarEntry> _queued;
            std::map<std::pair<dev_t, ino_t>, std::string> _links;
            CFd _file;
            uint64_t _fileLeft = 0;
            std::vector<uint8_t> _buf;
            bool _started = false;
            bool _done = false;

        public:
            TreeWalker(const std::string& root, const STreeOptions& options)
                : _opt(options), _rootPath(root), _buf(65536) {
                _prefix = _opt.prefix;
                while (!_prefix.empty() && _prefix[0] == '/') {
                    _prefix.erase(0, 1);
                }

                if (!_prefix.empty() && _prefix.back() != '/') {
                    _prefix += '/';
                }
            }

            /* True once every entry was written. */
            bool done() const noexcept { return _done; }

            /* Emits the next header or data chunk. */
            int32_t step(CTarWriter& w) {
                if (!_started) {
                    return start(w);
                }

                if (_file.isValid()) {
                    return pumpFile(w);
                }

                if (!_queued.empty()) {
                    STarEntry e = std::move(_queued.front());
                    _queued.pop_front();
                    return w.writeHeader(e);
                }

                while (!_stack.empty()) {
                    Frame& f = _stack.back();
                    if (f.idx == f.names.size()) {
                        _stack.pop_back();
                        continue;
                    }

                    std::string name = f.names[f.idx++];
                    bool wrote = false;
                    int32_t rc = visit(f, name, w, wrote);
                    if (rc < 0 || wrote) {
                        return rc;
                    }
                }

                _done = true;
                return SBOX_OK;
            }

        private:
            /* Opens the root and pushes its frame. */
            int32_t start(CTarWriter& w) {
                _started = true;
                int fd = ::open(_rootPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (fd < 0) {
                    return -errno;
                }

                _root.reset(fd);
                Frame f;
                f.fd.reset(::fcntl(fd, F_DUPFD_CLOEXEC, 0));
                if (!f.fd.isValid()) {
                    return -errno;
                }

                int32_t rc = listDir(fd, f.names);
                if (rc < 0) {
                    return rc;
                }

                _stack.push_back(std::move(f));
                if (_opt.includeRoot) {
                    struct stat st{};
                    if (::fstat(fd, &st) != 0) {
                        return -errno;
                    }

                    STarEntry e;
                    rc = fill(e, st, ".", _root.get(), _prefix.empty() ? "./" : _prefix);
                    if (rc < 0) {
                        return rc;
                    }

                    e.type = ETAR_DIR;
                    return w.writeHeader(e);
                }

                return SBOX_OK;
            }

            /* Common metadata of an entry. */
            int32_t fill(STarEntry& e, const struct stat& st, const char* name, int dirfd, const std::string& path) {
                e.path = path;
                e.mode = uint32_t(st.st_mode) & 07777u;
                e.uid = int64_t(st.st_uid) - _opt.uidShift;
                e.gid = int64_t(st.st_gid) - _opt.gidShift;
                if (e.uid < 0 || e.gid < 0) {
                    return -EOVERFLOW;
                }

                e.mtime.sec = int64_t(st.st_mtim.tv_sec);
                e.mtime.nsec = _opt.preciseTimes ? uint32_t(st.st_mtim.tv_nsec) : 0;
                if (_opt.xattrs) {
                    std::vector<std::string> names;
                    int32_t rc = fsutil::listXattrsAt(dirfd, name, names);
                    if (rc < 0 && rc != -ENOTSUP && rc != -EOPNOTSUPP) {
                        notify(EXN_XATTR_FAILED, path, rc);
                    }

                    std::sort(names.begin(), names.end());
                    for (const std::string& n : names) {
                        if (_opt.overlayWhiteouts && isOverlayXattr(n)) {
                            continue;
                        }

                        std::string v;
                        rc = fsutil::getXattrAt(dirfd, name, n, v);
                        if (rc < 0) {
                            notify(EXN_XATTR_FAILED, path, rc);
                            continue;
                        }

                        e.xattrs.emplace_back(n, std::move(v));
                    }
                }

                return SBOX_OK;
            }

            /* Reports a non-fatal event. */
            void notify(EExtractNotice kind, const std::string& path, int32_t error) {
                if (_opt.notice) {
                    _opt.notice(SExtractNotice{ kind, path, error });
                }
            }

            /* Reads an overlay bookkeeping xattr (trusted. or user. prefix). */
            std::string overlayXattr(int dirfd, const char* name, const char* key) {
                std::string v;
                if (fsutil::getXattrAt(dirfd, name, std::string("trusted.overlay.") + key, v) == SBOX_OK) {
                    return v.empty() ? std::string("\x01", 1) : v;
                }

                if (fsutil::getXattrAt(dirfd, name, std::string("user.overlay.") + key, v) == SBOX_OK) {
                    return v.empty() ? std::string("\x01", 1) : v;
                }

                return std::string();
            }

            /* Builds the ".wh.<name>" entry for a whiteout. */
            STarEntry whiteoutEntry(const Frame& f, const std::string& name, const STarEntry& from) {
                STarEntry e;
                e.path = _prefix + (f.rel.empty() ? std::string() : f.rel + "/") + ".wh." + name;
                e.mode = 0600;
                e.uid = from.uid;
                e.gid = from.gid;
                e.mtime = from.mtime;
                return e;
            }

            /* Emits the entry for one directory member. */
            int32_t visit(Frame& f, const std::string& name, CTarWriter& w, bool& wrote) {
                struct stat st{};
                if (::fstatat(f.fd.get(), name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
                    // --> Vanished since the directory was listed.
                    return errno == ENOENT ? SBOX_OK : -errno;
                }

                std::string rel = f.rel.empty() ? name : f.rel + "/" + name;
                if (_opt.filter && !_opt.filter(rel, st)) {
                    return SBOX_OK;
                }

                if (S_ISSOCK(st.st_mode)) {
                    notify(EXN_SOCKET_SKIPPED, rel, 0);
                    return SBOX_OK;
                }

                STarEntry e;
                int32_t rc = fill(e, st, name.c_str(), f.fd.get(), _prefix + rel);
                if (rc < 0) {
                    return rc;
                }

                wrote = true;
                if (S_ISREG(st.st_mode)) {
                    if (_opt.overlayWhiteouts && st.st_size == 0 && !overlayXattr(f.fd.get(), name.c_str(), "whiteout").empty()) {
                        return w.writeHeader(whiteoutEntry(f, name, e));
                    }

                    if (st.st_nlink > 1) {
                        auto key = std::make_pair(st.st_dev, st.st_ino);
                        auto it = _links.find(key);
                        if (it != _links.end()) {
                            e.type = ETAR_HARDLINK;
                            e.linkPath = it->second;
                            e.xattrs.clear();
                            return w.writeHeader(e);
                        }

                        _links.emplace(key, e.path);
                    }

                    int fd = ::openat(f.fd.get(), name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                    if (fd < 0) {
                        return -errno;
                    }

                    CFd file(fd);
                    struct stat fs{};
                    if (::fstat(fd, &fs) != 0) {
                        return -errno;
                    }

                    e.type = ETAR_FILE;
                    e.size = uint64_t(fs.st_size);
                    rc = w.writeHeader(e);
                    if (rc < 0) {
                        return rc;
                    }

                    if (e.size) {
                        _file = std::move(file);
                        _fileLeft = e.size;
                    }

                    return SBOX_OK;
                }

                if (S_ISDIR(st.st_mode)) {
                    e.type = ETAR_DIR;
                    Frame child;
                    int fd = ::openat(f.fd.get(), name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                    if (fd < 0) {
                        return -errno;
                    }

                    child.fd.reset(fd);
                    child.rel = rel;
                    rc = listDir(fd, child.names);
                    if (rc < 0) {
                        return rc;
                    }

                    if (_opt.overlayWhiteouts && overlayXattr(f.fd.get(), name.c_str(), "opaque") == "y") {
                        STarEntry opq;
                        opq.path = _prefix + rel + "/.wh..wh..opq";
                        opq.mode = e.mode & 0777u;
                        opq.uid = e.uid;
                        opq.gid = e.gid;
                        opq.mtime = e.mtime;
                        _queued.push_back(std::move(opq));
                    }

                    rc = w.writeHeader(e);
                    if (rc < 0) {
                        return rc;
                    }

                    // --> Frames live in a vector: `f` is invalid after this push.
                    _stack.push_back(std::move(child));
                    return SBOX_OK;
                }

                if (S_ISLNK(st.st_mode)) {
                    std::vector<char> target(size_t(st.st_size > 0 ? st.st_size : 0) + 4096);
                    ssize_t n = ::readlinkat(f.fd.get(), name.c_str(), target.data(), target.size());
                    if (n < 0) {
                        return -errno;
                    }

                    e.type = ETAR_SYMLINK;
                    e.linkPath.assign(target.data(), size_t(n));
                    return w.writeHeader(e);
                }

                if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)) {
                    if (_opt.overlayWhiteouts && S_ISCHR(st.st_mode) && st.st_rdev == makedev(0, 0)) {
                        return w.writeHeader(whiteoutEntry(f, name, e));
                    }

                    e.type = S_ISCHR(st.st_mode) ? ETAR_CHAR : ETAR_BLOCK;
                    e.devMajor = major(st.st_rdev);
                    e.devMinor = minor(st.st_rdev);
                    return w.writeHeader(e);
                }

                if (S_ISFIFO(st.st_mode)) {
                    e.type = ETAR_FIFO;
                    return w.writeHeader(e);
                }

                wrote = false;
                return SBOX_OK;
            }

            /* Copies the next chunk of the current file. */
            int32_t pumpFile(CTarWriter& w) {
                size_t want = _fileLeft < _buf.size() ? size_t(_fileLeft) : _buf.size();
                ssize_t n = ::read(_file.get(), _buf.data(), want);
                if (n < 0) {
                    if (errno == EINTR) {
                        return SBOX_OK;
                    }

                    return -errno;
                }

                if (n == 0) {
                    // --> The file shrank while being archived: pad to the size already announced.
                    std::memset(_buf.data(), 0, want);
                    n = ssize_t(want);
                }

                _fileLeft -= uint64_t(n);
                int32_t rc = w.writeData(SReadOnlyByteSpan(_buf.data(), size_t(n)));
                if (_fileLeft == 0) {
                    _file.reset();
                }

                return rc;
            }
        };

    }

    /* Writes a tree into a tar writer. */
    int32_t WriteTree(const std::string& root, CTarWriter& writer, const STreeOptions& options) {
        TreeWalker walker(root, options);
        while (!walker.done()) {
            int32_t rc = walker.step(writer);
            if (rc < 0) {
                return rc;
            }
        }

        return SBOX_OK;
    }

    /* Writes a tree as a (compressed) archive into a sink. */
    int32_t WriteTreeArchive(const std::string& root, IByteSink& out, ECompression compression, int32_t level,
                             const STreeOptions& options, const SPipelineHooks& hooks) {
        if (compression == ECOMP_ZSTD || compression == ECOMP_AUTO || compression == ECOMP_INVALID) {
            return -ENOTSUP;
        }

        IByteSink* cur = &out;
        std::unique_ptr<CTapSink> tapC;
        std::unique_ptr<CCodecSink> enc;
        std::unique_ptr<CTapSink> tapU;
        if (hooks.compressed) {
            tapC = std::make_unique<CTapSink>(*cur, hooks.compressed);
            cur = tapC.get();
        }

        if (compression != ECOMP_NONE) {
            enc = std::make_unique<CCodecSink>(CreateEncoder(compression, level), *cur);
            cur = enc.get();
        }

        if (hooks.uncompressed) {
            tapU = std::make_unique<CTapSink>(*cur, hooks.uncompressed);
            cur = tapU.get();
        }

        CTarWriter writer(*cur, options.format);
        int32_t rc = WriteTree(root, writer, options);
        if (rc < 0) {
            return rc;
        }

        return writer.finish();
    }

    struct CTreeTarSource::SImpl {
        std::vector<uint8_t> out;
        size_t pos = 0;
        CVectorSink sink;
        CTarWriter writer;
        TreeWalker walker;
        bool finished = false;
        int32_t error = SBOX_OK;

        SImpl(const std::string& root, const STreeOptions& options)
            : sink(out), writer(sink, options.format), walker(root, options) {}
    };

    /* Prepares the producer. */
    CTreeTarSource::CTreeTarSource(const std::string& root, const STreeOptions& options)
        : _impl(std::make_unique<SImpl>(root, options)) {}

    /* Destroys the producer. */
    CTreeTarSource::~CTreeTarSource() = default;

    /* Produces the next archive bytes. */
    SIoResult CTreeTarSource::read(const SByteSpan& buffer) {
        SImpl& s = *_impl;
        if (s.error) {
            return SIoResult{ s.error, 0 };
        }

        while (s.out.size() - s.pos < buffer.size && !s.finished) {
            if (s.pos && s.pos == s.out.size()) {
                s.out.clear();
                s.pos = 0;
            }

            int32_t rc;
            if (s.walker.done()) {
                rc = s.writer.finish();
                s.finished = true;
            } else {
                rc = s.walker.step(s.writer);
            }

            if (rc < 0) {
                s.error = rc;
                return SIoResult{ rc, 0 };
            }
        }

        size_t n = s.out.size() - s.pos;
        if (n > buffer.size) {
            n = buffer.size;
        }

        if (n) {
            std::memcpy(buffer.data, s.out.data() + s.pos, n);
        }

        s.pos += n;
        if (s.pos == s.out.size()) {
            s.out.clear();
            s.pos = 0;
        }

        return SIoResult{ SBOX_OK, n };
    }

}
}
