#include <sbox/image/store.hpp>
#include "util.hpp"
#include <sbox/core/file.hpp>
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace sbox {
namespace image {

    namespace {

        /* Writes all bytes to a descriptor. */
        int32_t writeAll(int fd, const uint8_t* data, size_t size) {
            while (size > 0) {
                ssize_t n = ::write(fd, data, size);
                if (n < 0) {
                    if (errno == EINTR) {
                        continue;
                    }

                    return -errno;
                }

                data += n;
                size -= size_t(n);
            }

            return SBOX_OK;
        }

        /* Returns true when `prefix` starts `text`. */
        bool startsWith(std::string_view text, std::string_view prefix) {
            return text.substr(0, prefix.size()) == prefix;
        }

        /* Returns the image name of an index.json entry. */
        std::string recordName(const SDescriptor& d) {
            std::string name = d.annotation(ANNOTATION_IMAGE_NAME);
            if (!name.empty()) {
                return name;
            }

            // --> Plain OCI layouts only carry ref.name; accept it when it is a full reference.
            std::string ref = d.annotation(ANNOTATION_REF_NAME);
            SReference parsed;
            if (!ref.empty() && ParseNormalizedReference(ref, parsed) == SBOX_OK && ref.find('/') != std::string::npos) {
                return parsed.toString();
            }

            return std::string();
        }

    }

    /* Returns the default store root. */
    std::string DefaultStoreRoot() {
        if (::geteuid() == 0) {
            return "/var/lib/sbox/image";
        }

        const char* xdg = std::getenv("XDG_DATA_HOME");
        if (xdg && *xdg) {
            return CFile::join(xdg, "sbox/image");
        }

        const char* home = std::getenv("HOME");
        return CFile::join(home && *home ? home : "/tmp", ".local/share/sbox/image");
    }

    /* Takes the store lock. */
    CStoreLock::CStoreLock(CContentStore& store) : _store(&store) {
        if (_store->_lockDepth++ == 0 && _store->_lockFd.isValid()) {
            while (::flock(_store->_lockFd.get(), LOCK_EX) != 0 && errno == EINTR) {
            }
        }
    }

    /* Releases the store lock. */
    CStoreLock::~CStoreLock() {
        if (--_store->_lockDepth == 0 && _store->_lockFd.isValid()) {
            ::flock(_store->_lockFd.get(), LOCK_UN);
        }
    }

    /* Removes an uncommitted, non-resumable ingest. */
    CBlobWriter::~CBlobWriter() {
        if (!_committed && !_keep && !_path.empty()) {
            ::unlink(_path.c_str());
        }
    }

    /* Opens an ingest file. */
    int32_t CBlobWriter::open(CContentStore& store, const std::string& name, bool resume, EDigestAlgorithm algorithm) {
        if (!_committed && !_keep && !_path.empty()) {
            ::unlink(_path.c_str());
        }

        _fd.reset();
        _path.clear();
        _store = &store;
        _committed = false;
        _keep = !name.empty();
        _digester = CDigester(algorithm);
        _offset = 0;
        std::string dir = store.path("ingest");
        CFile::makeDirs(dir, 0700);
        _path = CFile::join(dir, name.empty() ? "tmp-" + RandomHex(12) : name);

        int flags = O_RDWR | O_CREAT | O_CLOEXEC;
        if (name.empty()) {
            flags |= O_EXCL;
        }

        int fd = ::open(_path.c_str(), flags, 0600);
        if (fd < 0) {
            int32_t err = -errno;
            _path.clear();
            return err;
        }

        _fd.reset(fd);
        if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
            int32_t err = errno == EWOULDBLOCK ? -EBUSY : -errno;
            _fd.reset();
            _keep = true;       // --> Somebody else's ingest: never delete it.
            _path.clear();
            return err;
        }

        if (!resume) {
            return truncate();
        }

        // --> Re-hash what an earlier attempt already wrote, then append after it.
        std::vector<uint8_t> buf(size_t(1) << 17);
        while (true) {
            ssize_t n = ::read(fd, buf.data(), buf.size());
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }

                return -errno;
            }

            if (n == 0) {
                break;
            }

            _digester.update(SReadOnlyByteSpan(buf.data(), size_t(n)));
            _offset += uint64_t(n);
        }

        return SBOX_OK;
    }

    /* Appends bytes. */
    int32_t CBlobWriter::write(const SReadOnlyByteSpan& data) {
        if (!_fd.isValid()) {
            return -EBADF;
        }

        int32_t r = writeAll(_fd.get(), data.data, data.size);
        if (r != SBOX_OK) {
            return r;
        }

        _digester.update(data);
        _offset += data.size;
        return SBOX_OK;
    }

    /* Restarts the ingest. */
    int32_t CBlobWriter::truncate() {
        if (!_fd.isValid()) {
            return -EBADF;
        }

        if (::ftruncate(_fd.get(), 0) != 0 || ::lseek(_fd.get(), 0, SEEK_SET) < 0) {
            return -errno;
        }

        _digester.finish();
        _offset = 0;
        return SBOX_OK;
    }

    /* Verifies and moves the blob into place. */
    int32_t CBlobWriter::commit(const std::string& expectedDigest, int64_t expectedSize, std::string* digest) {
        if (!_fd.isValid()) {
            return -EBADF;
        }

        EDigestAlgorithm alg = expectedDigest.empty() ? EDIGEST_SHA256 : DigestAlgorithm(expectedDigest);
        std::string actual = _digester.finish();
        if (alg == EDIGEST_SHA512 && actual.substr(0, 7) != "sha512:") {
            // --> The writer was opened for sha256; recompute from the file.
            if (DigestFile(_path, actual, nullptr, EDIGEST_SHA512) != SBOX_OK) {
                abort();
                return -EIO;
            }
        }

        if ((!expectedDigest.empty() && actual != expectedDigest) || (expectedSize >= 0 && uint64_t(expectedSize) != _offset)) {
            _keep = false;
            abort();
            return -EBADMSG;
        }

        if (digest) {
            *digest = actual;
        }

        if (::fsync(_fd.get()) != 0) {
            int32_t err = -errno;
            abort();
            return err;
        }

        std::string target = _store->blobPath(actual);
        CFile::makeDirs(target.substr(0, target.rfind('/')), 0755);
        ::fchmod(_fd.get(), 0644);
        // --> A blob that already exists has the same content (content addressing): keep it.
        if (_store->hasBlob(actual)) {
            ::unlink(_path.c_str());
        } else if (::rename(_path.c_str(), target.c_str()) != 0) {
            int32_t err = -errno;
            abort();
            return err;
        }

        _committed = true;
        _fd.reset();
        _path.clear();
        return SBOX_OK;
    }

    /* Discards the ingest file. */
    void CBlobWriter::abort() noexcept {
        if (!_path.empty() && !_committed) {
            ::unlink(_path.c_str());
        }

        _fd.reset();
        _path.clear();
        _offset = 0;
    }

    /* Constructs a store object. */
    CContentStore::CContentStore(std::string root) : _root(std::move(root)) {}

    /* Opens a store. */
    int32_t CContentStore::open(const std::string& root, CContentStorePtr& out) {
        out.reset();
        if (root.empty()) {
            return -EINVAL;
        }

        int32_t r = CFile::makeDirs(root, 0711);
        if (r != SBOX_OK) {
            return r;
        }

        auto store = std::make_shared<CContentStore>(root);
        for (const char* d : { "blobs/sha256", "ingest", "snapshots", "containers" }) {
            r = CFile::makeDirs(store->path(d), std::string_view(d) == "ingest" ? 0700 : 0711);
            if (r != SBOX_OK) {
                return r;
            }
        }

        int fd = ::open(store->path("lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0) {
            return -errno;
        }

        store->_lockFd.reset(fd);
        CStoreLock lock(*store);
        if (!CFile::exists(store->path("oci-layout"))) {
            CJson layout = CJson::object();
            layout.set("imageLayoutVersion", "1.0.0");
            r = WriteJsonFile(store->path("oci-layout"), layout);
            if (r != SBOX_OK) {
                return r;
            }
        }

        if (!CFile::exists(store->path("index.json"))) {
            SIndex index;
            index.mediaType = MT_OCI_INDEX;
            r = store->writeIndex(index);
            if (r != SBOX_OK) {
                return r;
            }
        }

        out = std::move(store);
        return SBOX_OK;
    }

    /* Returns a path below the root. */
    std::string CContentStore::path(std::string_view leaf) const {
        return CFile::join(_root, leaf);
    }

    /* Returns the path of a blob. */
    std::string CContentStore::blobPath(std::string_view digest) const {
        if (ValidateDigest(digest) != SBOX_OK) {
            return std::string();
        }

        size_t colon = digest.find(':');
        return path("blobs/" + std::string(digest.substr(0, colon)) + "/" + std::string(digest.substr(colon + 1)));
    }

    /* Returns true when a blob exists. */
    bool CContentStore::hasBlob(std::string_view digest) const {
        std::string p = blobPath(digest);
        return !p.empty() && ::access(p.c_str(), F_OK) == 0;
    }

    /* Returns the size of a blob. */
    int64_t CContentStore::blobSize(std::string_view digest) const {
        std::string p = blobPath(digest);
        if (p.empty()) {
            return -EINVAL;
        }

        struct stat st{};
        if (::stat(p.c_str(), &st) != 0) {
            return -errno;
        }

        return int64_t(st.st_size);
    }

    /* Reads a blob, verifying its digest. */
    int32_t CContentStore::readBlob(std::string_view digest, std::string& out, size_t limit) const {
        std::string p = blobPath(digest);
        if (p.empty()) {
            return -EINVAL;
        }

        int32_t r = CFile::readAll(p, out, limit);
        if (r != SBOX_OK) {
            return r;
        }

        if (DigestOf(out, DigestAlgorithm(digest)) != digest) {
            return -EBADMSG;
        }

        return SBOX_OK;
    }

    /* Reads a blob as JSON. */
    int32_t CContentStore::readJsonBlob(std::string_view digest, CJson& out) const {
        std::string text;
        int32_t r = readBlob(digest, text, size_t(16) << 20);
        if (r != SBOX_OK) {
            return r;
        }

        return CJson::parse(text, out);
    }

    /* Stores bytes as a blob. */
    int32_t CContentStore::writeBlob(const SReadOnlyByteSpan& data, std::string& digest, const std::string& expectedDigest) {
        EDigestAlgorithm alg = expectedDigest.empty() ? EDIGEST_SHA256 : DigestAlgorithm(expectedDigest);
        if (alg == EDIGEST_INVALID) {
            return -ENOTSUP;
        }

        digest = DigestOf(data, alg);
        if (!expectedDigest.empty() && digest != expectedDigest) {
            return -EBADMSG;
        }

        if (hasBlob(digest)) {
            return SBOX_OK;
        }

        CBlobWriter w;
        int32_t r = w.open(*this, std::string(), false, alg);
        if (r == SBOX_OK) {
            r = w.write(data);
        }

        if (r == SBOX_OK) {
            r = w.commit(digest, int64_t(data.size));
        }

        return r;
    }

    /* Stores a JSON document as a blob. */
    int32_t CContentStore::writeJsonBlob(const CJson& json, std::string_view mediaType, SDescriptor& out) {
        std::string text = json.dump();
        out = SDescriptor();
        out.mediaType = std::string(mediaType);
        out.size = int64_t(text.size());
        return writeBlob(BytesOf(text), out.digest);
    }

    /* Removes a blob. */
    int32_t CContentStore::deleteBlob(std::string_view digest) {
        std::string p = blobPath(digest);
        if (p.empty()) {
            return -EINVAL;
        }

        if (::unlink(p.c_str()) != 0 && errno != ENOENT) {
            return -errno;
        }

        return SBOX_OK;
    }

    /* Lists all blobs. */
    std::vector<std::string> CContentStore::listBlobs() const {
        std::vector<std::string> out;
        std::vector<std::string> algs;
        if (ListDirectory(path("blobs"), algs) != SBOX_OK) {
            return out;
        }

        for (const std::string& alg : algs) {
            std::vector<std::string> names;
            if (ListDirectory(path("blobs/" + alg), names) != SBOX_OK) {
                continue;
            }

            for (const std::string& n : names) {
                std::string d = alg + ":" + n;
                if (ValidateDigest(d) == SBOX_OK) {
                    out.push_back(std::move(d));
                }
            }
        }

        std::sort(out.begin(), out.end());
        return out;
    }

    /* Reads index.json. */
    int32_t CContentStore::readIndex(SIndex& out) const {
        CJson json;
        int32_t r = ReadJsonFile(path("index.json"), json);
        if (r == -ENOENT) {
            out = SIndex();
            out.mediaType = MT_OCI_INDEX;
            return SBOX_OK;
        }

        if (r != SBOX_OK) {
            return r;
        }

        return SIndex::fromJson(json, out);
    }

    /* Writes index.json. */
    int32_t CContentStore::writeIndex(const SIndex& index) {
        return WriteJsonFile(path("index.json"), index.toJson());
    }

    /* Reads every index.json entry. */
    int32_t CContentStore::listRecords(std::vector<SImageRecord>& out) const {
        out.clear();
        SIndex index;
        int32_t r = readIndex(index);
        if (r != SBOX_OK) {
            return r;
        }

        for (const SDescriptor& d : index.manifests) {
            SImageRecord rec;
            rec.name = recordName(d);
            rec.target = d;
            out.push_back(std::move(rec));
        }

        return SBOX_OK;
    }

    /* Points a name at a manifest. */
    int32_t CContentStore::setRecord(const std::string& name, const SDescriptor& target) {
        CStoreLock lock(*this);
        SIndex index;
        int32_t r = readIndex(index);
        if (r != SBOX_OK) {
            return r;
        }

        SDescriptor d = target;
        d.annotations.clear();
        d.hasPlatform = target.hasPlatform;
        if (!name.empty()) {
            SReference ref;
            if (SReference::parse(name, ref) != SBOX_OK) {
                return -EINVAL;
            }

            d.annotation(ANNOTATION_IMAGE_NAME, name);
            if (ref.hasTag() && !ref.hasDigest()) {
                d.annotation(ANNOTATION_REF_NAME, ref.tag);
            }
        }

        std::vector<SDescriptor> kept;
        for (SDescriptor& e : index.manifests) {
            std::string en = recordName(e);
            if (!name.empty() && en == name) {
                continue;
            }

            // --> A dangling entry for the same manifest is superseded by a named one.
            if (en.empty() && e.digest == d.digest) {
                continue;
            }

            kept.push_back(std::move(e));
        }

        if (name.empty()) {
            for (const SDescriptor& e : kept) {
                if (e.digest == d.digest) {
                    // --> The manifest is already reachable through a name.
                    index.manifests = std::move(kept);
                    return writeIndex(index);
                }
            }
        }

        kept.push_back(std::move(d));
        index.manifests = std::move(kept);
        return writeIndex(index);
    }

    /* Removes the entry of a name. */
    int32_t CContentStore::removeRecord(const std::string& name) {
        CStoreLock lock(*this);
        SIndex index;
        int32_t r = readIndex(index);
        if (r != SBOX_OK) {
            return r;
        }

        size_t before = index.manifests.size();
        std::vector<SDescriptor> kept;
        for (SDescriptor& e : index.manifests) {
            if (recordName(e) != name) {
                kept.push_back(std::move(e));
            }
        }

        if (kept.size() == before) {
            return -ENOENT;
        }

        index.manifests = std::move(kept);
        return writeIndex(index);
    }

    /* Removes every entry of a manifest. */
    int32_t CContentStore::removeRecordsForManifest(const std::string& manifestDigest) {
        CStoreLock lock(*this);
        SIndex index;
        int32_t r = readIndex(index);
        if (r != SBOX_OK) {
            return r;
        }

        std::vector<SDescriptor> kept;
        int32_t removed = 0;
        for (SDescriptor& e : index.manifests) {
            if (e.digest == manifestDigest) {
                ++removed;
            } else {
                kept.push_back(std::move(e));
            }
        }

        index.manifests = std::move(kept);
        r = writeIndex(index);
        return r == SBOX_OK ? removed : r;
    }

    /* Loads the information of an image. */
    int32_t CContentStore::loadImage(const SDescriptor& manifest, SImageInfo& out) const {
        out = SImageInfo();
        CJson mj;
        int32_t r = readJsonBlob(manifest.digest, mj);
        if (r != SBOX_OK) {
            return r;
        }

        r = SManifest::fromJson(mj, out.manifest);
        if (r != SBOX_OK) {
            return r;
        }

        CJson cj;
        r = readJsonBlob(out.manifest.config.digest, cj);
        if (r != SBOX_OK) {
            return r;
        }

        r = SImageConfig::fromJson(cj, out.config);
        if (r != SBOX_OK) {
            return r;
        }

        out.id = out.manifest.config.digest;
        out.manifestDigest = manifest.digest;
        out.manifestDescriptor = manifest;
        out.manifestDescriptor.annotations.clear();
        for (const SDescriptor& l : out.manifest.layers) {
            out.size += l.size;
        }

        return SBOX_OK;
    }

    /* Lists every image. */
    int32_t CContentStore::listImages(std::vector<SImageInfo>& out) const {
        out.clear();
        std::vector<SImageRecord> records;
        int32_t r = listRecords(records);
        if (r != SBOX_OK) {
            return r;
        }

        for (const SImageRecord& rec : records) {
            SImageInfo* found = nullptr;
            for (SImageInfo& i : out) {
                if (i.manifestDigest == rec.target.digest) {
                    found = &i;
                    break;
                }
            }

            if (!found) {
                SImageInfo info;
                if (loadImage(rec.target, info) != SBOX_OK) {
                    continue;
                }

                // --> Two manifests can share a config (same image ID): merge them.
                for (SImageInfo& i : out) {
                    if (i.id == info.id) {
                        found = &i;
                        break;
                    }
                }

                if (!found) {
                    out.push_back(std::move(info));
                    found = &out.back();
                }
            }

            if (!rec.name.empty()) {
                SReference ref;
                if (SReference::parse(rec.name, ref) == SBOX_OK && ref.hasDigest()) {
                    found->repoDigests.push_back(rec.name);
                } else {
                    found->repoTags.push_back(rec.name);
                }
            }
        }

        return SBOX_OK;
    }

    /* Resolves a user string to an image. */
    int32_t CContentStore::resolve(std::string_view nameOrId, SImageInfo& out) const {
        std::vector<SImageInfo> images;
        int32_t r = listImages(images);
        if (r != SBOX_OK) {
            return r;
        }

        std::string id;
        if (startsWith(nameOrId, "sha256:") && ValidateDigest(nameOrId) == SBOX_OK) {
            id = std::string(nameOrId);
        } else if (IsFullHexId(nameOrId)) {
            id = "sha256:" + std::string(nameOrId);
        }

        if (!id.empty()) {
            for (SImageInfo& i : images) {
                if (i.id == id || i.manifestDigest == id) {
                    out = std::move(i);
                    return SBOX_OK;
                }
            }

            return -ENOENT;
        }

        SReference ref;
        if (ParseDockerReference(nameOrId, ref) == SBOX_OK) {
            std::string full = ref.toString();
            for (SImageInfo& i : images) {
                for (const std::string& n : i.repoTags) {
                    if (n == full) {
                        out = std::move(i);
                        return SBOX_OK;
                    }
                }

                for (const std::string& n : i.repoDigests) {
                    if (n == full) {
                        out = std::move(i);
                        return SBOX_OK;
                    }
                }
            }

            // --> name@digest where the digest is the platform manifest itself.
            if (ref.hasDigest()) {
                for (SImageInfo& i : images) {
                    if (i.manifestDigest == ref.digest) {
                        bool sameRepo = false;
                        for (const std::string& n : i.repoTags) {
                            SReference t;
                            if (SReference::parse(n, t) == SBOX_OK && t.name() == ref.name()) {
                                sameRepo = true;
                            }
                        }

                        if (sameRepo) {
                            out = std::move(i);
                            return SBOX_OK;
                        }
                    }
                }
            }
        }

        // --> Short image ID ("sha256:" optional).
        std::string_view prefix = nameOrId;
        if (startsWith(prefix, "sha256:")) {
            prefix = prefix.substr(7);
        }

        if (prefix.empty() || prefix.size() > 64) {
            return -ENOENT;
        }

        for (char c : prefix) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return -ENOENT;
            }
        }

        SImageInfo* match = nullptr;
        for (SImageInfo& i : images) {
            if (startsWith(DigestHex(i.id), prefix)) {
                if (match && match->id != i.id) {
                    return -EEXIST;
                }

                match = &i;
            }
        }

        if (!match) {
            return -ENOENT;
        }

        out = std::move(*match);
        return SBOX_OK;
    }

    /* Reads db.json. */
    int32_t CContentStore::readDb(CJson& out) const {
        int32_t r = ReadJsonFile(path("db.json"), out);
        if (r == -ENOENT) {
            out = CJson::object();
            out.set("version", 1);
            return SBOX_OK;
        }

        if (r == SBOX_OK && !out.isObject()) {
            return -EINVAL;
        }

        return r;
    }

    /* Replaces db.json. */
    int32_t CContentStore::writeDb(const CJson& db) {
        return WriteJsonFile(path("db.json"), db);
    }

    /* Returns the diffID of a layer blob. */
    std::string CContentStore::diffIdOf(std::string_view blobDigest) const {
        CJson db;
        if (readDb(db) != SBOX_OK) {
            return std::string();
        }

        return db.get("diffIds").get(blobDigest).asString();
    }

    /* Records the diffID of a layer blob. */
    int32_t CContentStore::recordDiffId(std::string_view blobDigest, std::string_view diffId) {
        CStoreLock lock(*this);
        CJson db;
        int32_t r = readDb(db);
        if (r != SBOX_OK) {
            return r;
        }

        if (db.get("diffIds").get(blobDigest).asString() == diffId) {
            return SBOX_OK;
        }

        db["diffIds"].set(blobDigest, std::string(diffId));
        return writeDb(db);
    }

}
}
