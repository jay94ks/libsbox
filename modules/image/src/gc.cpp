#include <sbox/image/gc.hpp>
#include <sbox/image/snapshot.hpp>
#include "util.hpp"
#include <sbox/core/fd.hpp>
#include <sbox/core/file.hpp>
#include <algorithm>
#include <cerrno>
#include <ctime>
#include <fcntl.h>
#include <set>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace sbox {
namespace image {

    namespace {

        /* Returns the age of a path in seconds (0 when it cannot be read). */
        int64_t ageOf(const std::string& path) {
            struct stat st{};
            if (::lstat(path.c_str(), &st) != 0) {
                return 0;
            }

            return int64_t(::time(nullptr)) - int64_t(st.st_mtime);
        }

        /* Marks a manifest (or index) and everything it references. */
        void markManifest(const CContentStore& store, const std::string& digest, std::set<std::string>& blobs,
                          std::set<std::string>& snapshots, int32_t depth = 0) {
            if (depth > 4 || blobs.count(digest)) {
                return;
            }

            blobs.insert(digest);
            CJson doc;
            if (store.readJsonBlob(digest, doc) != SBOX_OK) {
                return;
            }

            EManifestKind kind = ClassifyManifest(doc);
            if (kind == EMK_INDEX) {
                SIndex idx;
                if (SIndex::fromJson(doc, idx) == SBOX_OK) {
                    for (const SDescriptor& d : idx.manifests) {
                        if (store.hasBlob(d.digest)) {
                            markManifest(store, d.digest, blobs, snapshots, depth + 1);
                        }
                    }
                }

                return;
            }

            SManifest m;
            if (SManifest::fromJson(doc, m) != SBOX_OK) {
                return;
            }

            blobs.insert(m.config.digest);
            for (const SDescriptor& l : m.layers) {
                blobs.insert(l.digest);
            }

            CJson cj;
            SImageConfig cfg;
            if (store.readJsonBlob(m.config.digest, cj) == SBOX_OK && SImageConfig::fromJson(cj, cfg) == SBOX_OK) {
                for (const std::string& c : ChainIds(cfg.diffIds)) {
                    snapshots.insert(c);
                }
            }
        }

        /* Returns the image ID a manifest blob names (its config digest). */
        std::string imageIdOf(const CContentStore& store, const std::string& manifestDigest) {
            CJson doc;
            SManifest m;
            if (store.readJsonBlob(manifestDigest, doc) != SBOX_OK || SManifest::fromJson(doc, m) != SBOX_OK) {
                return std::string();
            }

            return m.config.digest;
        }

    }

    /* Mark and sweep over the store. */
    int32_t CollectGarbage(CContentStore& store, const SGcOptions& options, SGcResult& out) {
        out = SGcResult();
        CStoreLock lock(store);
        CContentStorePtr shared(std::shared_ptr<CContentStore>(), &store);
        CSnapshotter snap(shared);
        std::vector<SContainerInfo> containers;
        snap.listContainers(containers);
        std::set<std::string> usedImages;
        for (const SContainerInfo& c : containers) {
            usedImages.insert(c.imageId);
        }

        std::vector<SImageRecord> records;
        int32_t r = store.listRecords(records);
        if (r != SBOX_OK) {
            return r;
        }

        // --> Pruning drops index.json entries first; the sweep below does the rest.
        if (options.pruneDangling || options.pruneUnused) {
            std::vector<SImageInfo> images;
            store.listImages(images);
            for (const SImageInfo& img : images) {
                bool drop = options.pruneUnused ? !usedImages.count(img.id) : (img.repoTags.empty() && !usedImages.count(img.id));
                if (!drop) {
                    continue;
                }

                out.removedImages.push_back(img.id);
                if (options.dryRun) {
                    continue;
                }

                for (const SImageRecord& rec : records) {
                    if (imageIdOf(store, rec.target.digest) == img.id) {
                        if (rec.name.empty()) {
                            store.removeRecordsForManifest(rec.target.digest);
                        } else {
                            store.removeRecord(rec.name);
                        }
                    }
                }
            }

            store.listRecords(records);
            if (options.dryRun) {
                std::vector<SImageRecord> kept;
                for (const SImageRecord& rec : records) {
                    if (std::find(out.removedImages.begin(), out.removedImages.end(), imageIdOf(store, rec.target.digest)) ==
                        out.removedImages.end()) {
                        kept.push_back(rec);
                    }
                }

                records = std::move(kept);
            }
        }

        // --> Mark.
        std::set<std::string> blobs;
        std::set<std::string> snapshots;
        for (const SImageRecord& rec : records) {
            markManifest(store, rec.target.digest, blobs, snapshots);
            // --> A repo digest names the index the tag resolved to: keep that document too.
            SReference ref;
            if (!rec.name.empty() && SReference::parse(rec.name, ref) == SBOX_OK && ref.hasDigest()) {
                blobs.insert(ref.digest);
            }
        }

        for (const SContainerInfo& c : containers) {
            if (!c.manifestDigest.empty()) {
                markManifest(store, c.manifestDigest, blobs, snapshots);
            }

            for (const std::string& ch : c.chainIds) {
                snapshots.insert(ch);
            }
        }

        std::vector<std::string> leasedBlobs;
        std::vector<std::string> leasedSnapshots;
        CLease::collect(store, leasedBlobs, leasedSnapshots);
        blobs.insert(leasedBlobs.begin(), leasedBlobs.end());
        snapshots.insert(leasedSnapshots.begin(), leasedSnapshots.end());

        // --> Sweep blobs.
        for (const std::string& b : store.listBlobs()) {
            if (blobs.count(b)) {
                continue;
            }

            int64_t size = store.blobSize(b);
            out.removedBlobs.push_back(b);
            out.reclaimedBytes += size > 0 ? uint64_t(size) : 0;
            if (!options.dryRun) {
                store.deleteBlob(b);
            }
        }

        // --> Sweep snapshots and stale temporary directories.
        std::vector<std::string> names;
        ListDirectory(store.path("snapshots"), names);
        for (const std::string& n : names) {
            std::string dir = store.path("snapshots/" + n);
            if (IsFullHexId(n)) {
                std::string chain = "sha256:" + n;
                if (snapshots.count(chain)) {
                    continue;
                }

                out.removedSnapshots.push_back(chain);
                out.reclaimedBytes += TreeSize(dir);
                if (!options.dryRun) {
                    snap.removeSnapshot(chain);
                }
            } else if ((n.compare(0, 4, "tmp-") == 0 && ageOf(dir) > 3600) || n.compare(0, 3, "rm-") == 0) {
                if (!options.dryRun) {
                    CFile::removeTree(dir);
                }
            }
        }

        // --> Short lowerdir links (legacy overlay mounts) whose snapshot is gone.
        ListDirectory(store.path("l"), names);
        for (const std::string& n : names) {
            std::string link = store.path("l/" + n);
            struct stat st{};
            if (!options.dryRun && ::stat(link.c_str(), &st) != 0 && errno == ENOENT) {
                ::unlink(link.c_str());
            }
        }

        // --> Abandoned ingests (a live writer holds its flock).
        ListDirectory(store.path("ingest"), names);
        for (const std::string& n : names) {
            std::string p = store.path("ingest/" + n);
            int64_t age = ageOf(p);
            if (age < options.ingestMaxAgeSec || options.dryRun) {
                continue;
            }

            if (IsDirectory(p)) {
                CFile::removeTree(p);
                continue;
            }

            CFd fd(::open(p.c_str(), O_RDONLY | O_CLOEXEC));
            if (fd.isValid() && ::flock(fd.get(), LOCK_EX | LOCK_NB) == 0) {
                ::unlink(p.c_str());
            }
        }

        // --> Probe directories left behind by a crash.
        ListDirectory(store.path("containers"), names);
        for (const std::string& n : names) {
            if (n.compare(0, 7, ".probe-") == 0 && !options.dryRun && ageOf(store.path("containers/" + n)) > 60) {
                CFile::removeTree(store.path("containers/" + n));
            }
        }

        // --> diffID records of removed blobs.
        if (!options.dryRun && !out.removedBlobs.empty()) {
            CJson db;
            if (store.readDb(db) == SBOX_OK) {
                for (const std::string& b : out.removedBlobs) {
                    db["diffIds"].remove(b);
                    db["sources"].remove(b);
                }

                store.writeDb(db);
            }
        }

        return SBOX_OK;
    }

    /* Removes an image name or an image. */
    int32_t RemoveImage(CContentStore& store, std::string_view nameOrId, bool force, SRemoveResult& out, std::string* error) {
        out = SRemoveResult();
        CStoreLock lock(store);
        SImageInfo info;
        int32_t r = store.resolve(nameOrId, info);
        if (r != SBOX_OK) {
            if (error) {
                *error = r == -EEXIST ? "ambiguous image ID prefix " + std::string(nameOrId) : "no such image: " + std::string(nameOrId);
            }

            return r;
        }

        CContentStorePtr shared(std::shared_ptr<CContentStore>(), &store);
        CSnapshotter snap(shared);
        std::vector<SContainerInfo> containers;
        snap.listContainers(containers);
        std::string user;
        for (const SContainerInfo& c : containers) {
            if (c.imageId == info.id) {
                user = c.id;
            }
        }

        // --> Was a name given (and which one)?
        std::string name;
        SReference ref;
        if (ParseDockerReference(nameOrId, ref) == SBOX_OK) {
            std::string full = ref.toString();
            for (const std::string& t : info.repoTags) {
                name = t == full ? t : name;
            }

            for (const std::string& t : info.repoDigests) {
                name = t == full ? t : name;
            }
        }

        std::vector<SImageRecord> records;
        store.listRecords(records);
        if (!name.empty()) {
            bool lastTag = info.repoTags.size() + info.repoDigests.size() <= 1 ||
                           (info.repoTags.size() <= 1 && std::find(info.repoTags.begin(), info.repoTags.end(), name) != info.repoTags.end());
            if (!lastTag) {
                store.removeRecord(name);
                out.untagged.push_back(name);
                return SBOX_OK;
            }

            if (!user.empty() && !force) {
                if (error) {
                    *error = "conflict: unable to remove repository reference \"" + std::string(nameOrId) +
                             "\" (must force) - container " + user + " is using its referenced image " + info.id;
                }

                return -EBUSY;
            }
        } else {
            if (!user.empty() && !force) {
                if (error) {
                    *error = "conflict: unable to delete " + std::string(DigestHex(info.id)).substr(0, 12) +
                             " (must be forced) - image is being used by container " + user;
                }

                return -EBUSY;
            }

            if (info.repoTags.size() > 1 && !force) {
                if (error) {
                    *error = "conflict: unable to delete " + std::string(DigestHex(info.id)).substr(0, 12) +
                             " (must be forced) - image is referenced in multiple repositories";
                }

                return -EEXIST;
            }
        }

        // --> Delete the image: every entry whose manifest names this image ID.
        for (const SImageRecord& rec : records) {
            if (imageIdOf(store, rec.target.digest) != info.id) {
                continue;
            }

            if (rec.name.empty()) {
                store.removeRecordsForManifest(rec.target.digest);
            } else {
                store.removeRecord(rec.name);
                out.untagged.push_back(rec.name);
            }
        }

        out.deleted.push_back(info.id);
        SGcResult gc;
        r = CollectGarbage(store, SGcOptions(), gc);
        for (const std::string& b : gc.removedBlobs) {
            if (b != info.id) {
                out.deleted.push_back(b);
            }
        }

        return r;
    }

}
}
