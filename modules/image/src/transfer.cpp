#include <sbox/image/transfer.hpp>
#include "util.hpp"
#include <sbox/archive/codec.hpp>
#include <sbox/archive/extract.hpp>
#include <sbox/archive/tar.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/file.hpp>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace sbox {
namespace image {

    namespace {

        /* Sets an error message and returns `code`. */
        int32_t failWith(std::string* error, int32_t code, std::string message) {
            if (error) {
                *error = std::move(message);
            }

            return code;
        }

        /*
         * One image selected for export with the names it is exported under.
         */
        struct Selected {
            SImageInfo info;
            std::vector<std::string> names;     // --> Full references (tags only for docker save).
        };

        /* Resolves the export selection (see SaveDockerArchive for the rules). */
        int32_t select(CContentStore& store, const std::vector<std::string>& images, bool includeDigests, std::vector<Selected>& out,
                       std::string* error) {
            out.clear();
            for (const std::string& want : images) {
                SImageInfo info;
                int32_t r = store.resolve(want, info);
                if (r != SBOX_OK) {
                    return failWith(error, r == -EEXIST ? -EEXIST : -ENOENT, "no such image: " + want);
                }

                std::vector<std::string> names;
                SReference ref;
                bool isId = IsFullHexId(want) || (want.compare(0, 7, "sha256:") == 0) ||
                            ParseNormalizedReference(want, ref) != SBOX_OK;
                if (!isId) {
                    bool matched = false;
                    for (const std::string& t : info.repoTags) {
                        matched = matched || t == WithDefaultTag(ref).toString();
                    }

                    for (const std::string& t : info.repoDigests) {
                        matched = matched || t == ref.toString();
                    }

                    // --> A short ID that also parses as a name.
                    isId = !matched && !ref.hasTag() && !ref.hasDigest() &&
                           std::string_view(DigestHex(info.id)).substr(0, want.size()) == want;
                }

                if (!isId) {
                    if (ref.hasTag() || ref.hasDigest()) {
                        std::string full = ref.toString();
                        if (!ref.hasDigest() || includeDigests) {
                            names.push_back(full);
                        }
                    } else {
                        // --> A bare repository: every tag of it.
                        std::vector<SImageInfo> all;
                        store.listImages(all);
                        for (const SImageInfo& i : all) {
                            if (i.id != info.id) {
                                continue;
                            }

                            for (const std::string& t : i.repoTags) {
                                SReference tr;
                                if (SReference::parse(t, tr) == SBOX_OK && tr.name() == ref.name()) {
                                    names.push_back(t);
                                }
                            }
                        }
                    }
                }

                Selected* existing = nullptr;
                for (Selected& s : out) {
                    if (s.info.id == info.id) {
                        existing = &s;
                    }
                }

                if (!existing) {
                    out.push_back(Selected{ info, {} });
                    existing = &out.back();
                }

                for (const std::string& n : names) {
                    if (std::find(existing->names.begin(), existing->names.end(), n) == existing->names.end()) {
                        existing->names.push_back(n);
                    }
                }
            }

            return SBOX_OK;
        }

        /*
         * Tar writer helpers with fixed metadata.
         */
        struct TarOut {
            archive::CTarWriter writer;
            std::vector<std::string> dirs;

            explicit TarOut(archive::IByteSink& sink) : writer(sink) {}

            int32_t dir(const std::string& path) {
                if (std::find(dirs.begin(), dirs.end(), path) != dirs.end()) {
                    return SBOX_OK;
                }

                dirs.push_back(path);
                archive::STarEntry e;
                e.type = archive::ETAR_DIR;
                e.path = path + "/";
                e.mode = 0755;
                return writer.writeHeader(e);
            }

            int32_t text(const std::string& path, std::string_view data) {
                archive::STarEntry e;
                e.path = path;
                e.mode = 0644;
                e.size = data.size();
                return writer.writeEntry(e, BytesOf(data));
            }

            int32_t file(const std::string& path, const std::string& source) {
                CFd fd(::open(source.c_str(), O_RDONLY | O_CLOEXEC));
                if (!fd.isValid()) {
                    return -errno;
                }

                struct stat st{};
                if (::fstat(fd.get(), &st) != 0) {
                    return -errno;
                }

                archive::STarEntry e;
                e.path = path;
                e.mode = 0644;
                e.size = uint64_t(st.st_size);
                int32_t r = writer.writeHeader(e);
                if (r != SBOX_OK) {
                    return r;
                }

                std::vector<uint8_t> buf(size_t(1) << 17);
                uint64_t left = e.size;
                while (left > 0) {
                    ssize_t n = ::read(fd.get(), buf.data(), size_t(std::min<uint64_t>(left, buf.size())));
                    if (n < 0 && errno == EINTR) {
                        continue;
                    }

                    if (n <= 0) {
                        return n < 0 ? -errno : -EIO;
                    }

                    r = writer.writeData(SReadOnlyByteSpan(buf.data(), size_t(n)));
                    if (r != SBOX_OK) {
                        return r;
                    }

                    left -= uint64_t(n);
                }

                return SBOX_OK;
            }

            int32_t blob(const std::string& digest, const std::string& source) {
                int32_t r = dir("blobs");
                if (r == SBOX_OK) {
                    r = dir("blobs/sha256");
                }

                if (r == SBOX_OK) {
                    r = file("blobs/sha256/" + std::string(DigestHex(digest)), source);
                }

                return r;
            }
        };

        /*
         * Decompresses a layer blob into a temporary file, returning its diffID.
         */
        int32_t uncompressLayer(CContentStore& store, const std::string& digest, const std::string& target, std::string& diffId) {
            CFd in(::open(store.blobPath(digest).c_str(), O_RDONLY | O_CLOEXEC));
            if (!in.isValid()) {
                return -errno;
            }

            CFd outFd(::open(target.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
            if (!outFd.isValid()) {
                return -errno;
            }

            archive::CFdSource src(in.get());
            archive::CCodecSource dec(archive::CreateDecoder(archive::ECOMP_AUTO), src);
            archive::CFdSink sink(outFd.get());
            CDigester d;
            archive::CTapSink tap(sink, [&d](const SReadOnlyByteSpan& s) { d.update(s); });
            int32_t r = archive::Pump(dec, tap);
            if (r != SBOX_OK) {
                return r;
            }

            diffId = d.finish();
            return SBOX_OK;
        }

        /* Computes the digest of a file and its diffID (decompressed digest) and compression. */
        int32_t analyzeLayer(const std::string& path, std::string& digest, std::string& diffId, archive::ECompression& comp,
                             uint64_t& size) {
            CFd in(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
            if (!in.isValid()) {
                return -errno;
            }

            uint8_t head[8] = {};
            ssize_t n = ::pread(in.get(), head, sizeof(head), 0);
            comp = archive::DetectCompression(SReadOnlyByteSpan(head, n > 0 ? size_t(n) : 0), true);
            CDigester raw;
            CDigester diff;
            archive::CFdSource src(in.get());
            archive::CTapSource tapRaw(src, [&raw](const SReadOnlyByteSpan& s) { raw.update(s); });
            archive::CCodecSource dec(archive::CreateDecoder(archive::ECOMP_AUTO), tapRaw);
            std::vector<uint8_t> buf(size_t(1) << 17);
            while (true) {
                SIoResult io = dec.read(SByteSpan(buf.data(), buf.size()));
                if (!io.ok()) {
                    return io.error;
                }

                if (io.bytes == 0) {
                    break;
                }

                diff.update(SReadOnlyByteSpan(buf.data(), io.bytes));
            }

            size = raw.size();
            digest = raw.finish();
            diffId = diff.finish();
            return SBOX_OK;
        }

        /* Moves a verified file into the blob store. */
        int32_t importFile(CContentStore& store, const std::string& path, const std::string& digest) {
            if (store.hasBlob(digest)) {
                ::unlink(path.c_str());
                return SBOX_OK;
            }

            std::string target = store.blobPath(digest);
            CFile::makeDirs(target.substr(0, target.rfind('/')), 0711);
            ::chmod(path.c_str(), 0644);
            if (::rename(path.c_str(), target.c_str()) != 0) {
                return -errno;
            }

            return SBOX_OK;
        }

        /* Returns a path inside the extracted archive, refusing escapes. */
        bool insidePath(const std::string& root, const std::string& rel, std::string& out) {
            std::string clean;
            if (archive::CleanArchivePath(rel, clean) != SBOX_OK || clean.empty()) {
                return false;
            }

            out = CFile::join(root, clean);
            return true;
        }

        /* Imports a blob of an OCI layout after checking its digest. */
        int32_t importLayoutBlob(CContentStore& store, const std::string& root, const std::string& digest, CLease& lease,
                                 std::string* error) {
            if (ValidateDigest(digest) != SBOX_OK) {
                return failWith(error, -EINVAL, "invalid digest " + digest);
            }

            lease.addBlob(digest);
            if (store.hasBlob(digest)) {
                return SBOX_OK;
            }

            std::string path = CFile::join(root, "blobs/" + std::string(digest.substr(0, digest.find(':'))) + "/" +
                                                     std::string(DigestHex(digest)));
            std::string actual;
            int32_t r = DigestFile(path, actual, nullptr, DigestAlgorithm(digest));
            if (r != SBOX_OK) {
                return failWith(error, r == -ENOENT ? -ENOENT : r, "the archive lacks blob " + digest);
            }

            if (actual != digest) {
                return failWith(error, -EBADMSG, "blob " + digest + " in the archive has digest " + actual);
            }

            return importFile(store, path, digest);
        }

    }

    /* Writes images as a docker save archive. */
    int32_t SaveDockerArchive(CContentStore& store, const std::vector<std::string>& images, archive::IByteSink& out, std::string* error) {
        std::vector<Selected> sel;
        int32_t r = select(store, images, false, sel, error);
        if (r != SBOX_OK) {
            return r;
        }

        std::string tmpDir = store.path("ingest/save-" + RandomHex(8));
        r = CFile::makeDirs(tmpDir, 0700);
        if (r != SBOX_OK) {
            return r;
        }

        TarOut tar(out);
        CJson manifestJson = CJson::array();
        CJson repositories = CJson::object();
        SIndex index;
        index.mediaType = MT_OCI_INDEX;
        std::vector<std::string> written;
        r = tar.text("oci-layout", "{\"imageLayoutVersion\":\"1.0.0\"}");
        for (const Selected& s : sel) {
            if (r != SBOX_OK) {
                break;
            }

            const SImageInfo& img = s.info;
            if (img.manifest.layers.size() != img.config.diffIds.size()) {
                r = failWith(error, -EBADMSG, "image " + img.id + " has a layer/diffID count mismatch");
                break;
            }

            SManifest m;
            m.mediaType = MT_OCI_MANIFEST;
            m.config = img.manifest.config;
            m.config.mediaType = MT_OCI_CONFIG;
            CJson layers = CJson::array();
            for (size_t i = 0; i < img.manifest.layers.size() && r == SBOX_OK; ++i) {
                const std::string& diffId = img.config.diffIds[i];
                std::string tmp = CFile::join(tmpDir, std::string(DigestHex(diffId)));
                if (std::find(written.begin(), written.end(), diffId) == written.end()) {
                    std::string actual;
                    r = uncompressLayer(store, img.manifest.layers[i].digest, tmp, actual);
                    if (r != SBOX_OK) {
                        r = failWith(error, r, "cannot read layer " + img.manifest.layers[i].digest + ": " + std::strerror(-r));
                        break;
                    }

                    if (actual != diffId) {
                        r = failWith(error, -EBADMSG, "layer " + img.manifest.layers[i].digest + " does not match diffID " + diffId);
                        break;
                    }

                    r = tar.blob(diffId, tmp);
                    written.push_back(diffId);
                }

                struct stat st{};
                ::stat(tmp.c_str(), &st);
                SDescriptor d;
                d.mediaType = MT_OCI_LAYER;
                d.digest = diffId;
                d.size = int64_t(st.st_size);
                m.layers.push_back(d);
                layers.push("blobs/sha256/" + std::string(DigestHex(diffId)));
            }

            if (r != SBOX_OK) {
                break;
            }

            if (std::find(written.begin(), written.end(), img.id) == written.end()) {
                r = tar.blob(img.id, store.blobPath(img.id));
                written.push_back(img.id);
            }

            std::string manifestText = m.toJson().dump();
            std::string manifestDigest = DigestOf(manifestText);
            std::string manifestTmp = CFile::join(tmpDir, "manifest-" + std::string(DigestHex(manifestDigest)));
            if (r == SBOX_OK && std::find(written.begin(), written.end(), manifestDigest) == written.end()) {
                r = CFile::writeAtomic(manifestTmp, manifestText, 0600);
                if (r == SBOX_OK) {
                    r = tar.blob(manifestDigest, manifestTmp);
                }

                written.push_back(manifestDigest);
            }

            CJson entry = CJson::object();
            entry.set("Config", "blobs/sha256/" + std::string(DigestHex(img.id)));
            CJson tags = CJson::array();
            for (const std::string& n : s.names) {
                SReference ref;
                if (SReference::parse(n, ref) == SBOX_OK && ref.hasTag()) {
                    tags.push(ref.familiarString());
                    repositories[ref.familiarName()].set(ref.tag, std::string(DigestHex(img.config.diffIds.empty() ? img.id : img.config.diffIds.back())));
                }

                SDescriptor d;
                d.mediaType = MT_OCI_MANIFEST;
                d.digest = manifestDigest;
                d.size = int64_t(manifestText.size());
                d.annotation(ANNOTATION_IMAGE_NAME, n);
                if (ref.hasTag()) {
                    d.annotation(ANNOTATION_REF_NAME, ref.tag);
                }

                index.manifests.push_back(d);
            }

            if (s.names.empty()) {
                SDescriptor d;
                d.mediaType = MT_OCI_MANIFEST;
                d.digest = manifestDigest;
                d.size = int64_t(manifestText.size());
                index.manifests.push_back(d);
            }

            entry.set("RepoTags", tags.size() ? std::move(tags) : CJson());
            entry.set("Layers", std::move(layers));
            manifestJson.push(std::move(entry));
        }

        if (r == SBOX_OK) {
            r = tar.text("index.json", index.toJson().dump());
        }

        if (r == SBOX_OK) {
            r = tar.text("manifest.json", manifestJson.dump());
        }

        if (r == SBOX_OK && repositories.size() > 0) {
            r = tar.text("repositories", repositories.dump());
        }

        if (r == SBOX_OK) {
            r = tar.writer.finish();
        }

        CFile::removeTree(tmpDir);
        return r;
    }

    /* Writes images as an OCI layout archive. */
    int32_t SaveOciArchive(CContentStore& store, const std::vector<std::string>& images, archive::IByteSink& out, std::string* error) {
        std::vector<Selected> sel;
        int32_t r = select(store, images, true, sel, error);
        if (r != SBOX_OK) {
            return r;
        }

        TarOut tar(out);
        SIndex index;
        index.mediaType = MT_OCI_INDEX;
        std::vector<std::string> written;
        r = tar.text("oci-layout", "{\"imageLayoutVersion\":\"1.0.0\"}");
        for (const Selected& s : sel) {
            std::vector<std::string> blobs = { s.info.manifestDigest, s.info.id };
            for (const SDescriptor& l : s.info.manifest.layers) {
                blobs.push_back(l.digest);
            }

            for (const std::string& b : blobs) {
                if (r == SBOX_OK && std::find(written.begin(), written.end(), b) == written.end()) {
                    if (!store.hasBlob(b)) {
                        return failWith(error, -ENOENT, "blob " + b + " of image " + s.info.id + " is missing");
                    }

                    r = tar.blob(b, store.blobPath(b));
                    written.push_back(b);
                }
            }

            SDescriptor base = s.info.manifestDescriptor;
            base.annotations.clear();
            if (base.mediaType.empty()) {
                base.mediaType = s.info.manifest.mediaType.empty() ? MT_OCI_MANIFEST : s.info.manifest.mediaType;
            }

            if (s.names.empty()) {
                index.manifests.push_back(base);
            }

            for (const std::string& n : s.names) {
                SDescriptor d = base;
                d.annotation(ANNOTATION_IMAGE_NAME, n);
                SReference ref;
                if (SReference::parse(n, ref) == SBOX_OK && ref.hasTag()) {
                    d.annotation(ANNOTATION_REF_NAME, ref.tag);
                }

                index.manifests.push_back(d);
            }
        }

        if (r == SBOX_OK) {
            r = tar.text("index.json", index.toJson().dump());
        }

        if (r == SBOX_OK) {
            r = tar.writer.finish();
        }

        return r;
    }

    /* Loads a docker save or OCI layout archive. */
    int32_t LoadImageArchive(CContentStore& store, archive::IByteSource& in, const SLoadOptions& options, SLoadResult& out,
                             std::string* error) {
        out = SLoadResult();
        CLease lease;
        int32_t r = lease.open(store);
        if (r != SBOX_OK) {
            return failWith(error, r, "cannot create a lease");
        }

        std::string root = store.path("ingest/load-" + RandomHex(8));
        r = CFile::makeDirs(root, 0700);
        if (r != SBOX_OK) {
            return r;
        }

        // --> Unpack the archive into a private directory first: manifest.json may come after
        // the blobs it describes, and every member must be verified before it is used.
        archive::SExtractOptions xo;
        xo.ownership = archive::EOWN_IGNORE;
        xo.xattrs = false;
        xo.devices = false;
        xo.preserveTimes = false;
        r = archive::ExtractArchive(in, root, xo, archive::ECOMP_AUTO);
        if (r != SBOX_OK) {
            CFile::removeTree(root);
            return failWith(error, r, std::string("cannot read the archive: ") + std::strerror(-r));
        }

        struct Cleanup {
            std::string dir;
            ~Cleanup() { CFile::removeTree(dir); }
        } cleanup{ root };

        CJson manifestJson;
        bool hasDockerManifest = ReadJsonFile(CFile::join(root, "manifest.json"), manifestJson) == SBOX_OK;
        CJson indexJson;
        bool hasIndex = ReadJsonFile(CFile::join(root, "index.json"), indexJson) == SBOX_OK;
        SIndex layoutIndex;
        if (hasIndex && SIndex::fromJson(indexJson, layoutIndex) != SBOX_OK) {
            hasIndex = false;
        }

        if (hasDockerManifest) {
            out.format = "docker";
            if (!manifestJson.isArray()) {
                return failWith(error, -EINVAL, "manifest.json is not a list");
            }

            for (size_t i = 0; i < manifestJson.size(); ++i) {
                const CJson& entry = manifestJson.at(i);
                std::string configPath;
                if (!insidePath(root, entry.get("Config").asString(), configPath)) {
                    return failWith(error, -EINVAL, "manifest.json entry " + std::to_string(i) + " has no valid Config");
                }

                std::string configText;
                r = CFile::readAll(configPath, configText, size_t(16) << 20);
                if (r != SBOX_OK) {
                    return failWith(error, r, "cannot read " + entry.get("Config").asString());
                }

                CJson cj;
                SImageConfig config;
                if (CJson::parse(configText, cj) != SBOX_OK || SImageConfig::fromJson(cj, config) != SBOX_OK) {
                    return failWith(error, -EBADMSG, "malformed image config " + entry.get("Config").asString());
                }

                std::vector<std::string> layerPaths = entry.get("Layers").asStrings();
                if (layerPaths.size() != config.diffIds.size()) {
                    return failWith(error, -EBADMSG, "image config lists " + std::to_string(config.diffIds.size()) +
                                                         " diffIDs for " + std::to_string(layerPaths.size()) + " layers");
                }

                std::string configDigest;
                r = store.writeBlob(BytesOf(configText), configDigest);
                if (r != SBOX_OK) {
                    return failWith(error, r, "cannot store the config");
                }

                lease.addBlob(configDigest);
                SManifest m;
                m.mediaType = MT_OCI_MANIFEST;
                m.config.mediaType = MT_OCI_CONFIG;
                m.config.digest = configDigest;
                m.config.size = int64_t(configText.size());
                for (size_t l = 0; l < layerPaths.size(); ++l) {
                    std::string path;
                    if (!insidePath(root, layerPaths[l], path)) {
                        return failWith(error, -EINVAL, "invalid layer path " + layerPaths[l]);
                    }

                    std::string digest;
                    std::string diffId;
                    archive::ECompression comp = archive::ECOMP_NONE;
                    uint64_t size = 0;
                    r = analyzeLayer(path, digest, diffId, comp, size);
                    if (r != SBOX_OK) {
                        return failWith(error, r, "cannot read layer " + layerPaths[l] + ": " + std::strerror(-r));
                    }

                    if (diffId != config.diffIds[l]) {
                        return failWith(error, -EBADMSG, "layer " + layerPaths[l] + " has diffID " + diffId + ", the config says " +
                                                             config.diffIds[l]);
                    }

                    lease.addBlob(digest);
                    // --> The same file may back several images: copy only once.
                    if (!store.hasBlob(digest)) {
                        std::string copy = path + ".import";
                        if (::link(path.c_str(), copy.c_str()) != 0) {
                            return failWith(error, -errno, "cannot stage layer " + layerPaths[l]);
                        }

                        r = importFile(store, copy, digest);
                        if (r != SBOX_OK) {
                            return failWith(error, r, "cannot store layer " + digest);
                        }
                    }

                    store.recordDiffId(digest, diffId);
                    SDescriptor d;
                    d.mediaType = comp == archive::ECOMP_GZIP ? MT_OCI_LAYER_GZIP : comp == archive::ECOMP_ZSTD ? MT_OCI_LAYER_ZSTD : MT_OCI_LAYER;
                    d.digest = digest;
                    d.size = int64_t(size);
                    m.layers.push_back(d);
                }

                // --> Reuse the archive's own manifest (Docker 25+ layout) when it describes
                // exactly these blobs, so the manifest digest survives the round trip.
                SDescriptor manifestDesc;
                bool reused = false;
                if (hasIndex) {
                    for (const SDescriptor& d : layoutIndex.manifests) {
                        std::string text;
                        std::string path = CFile::join(root, "blobs/sha256/" + std::string(DigestHex(d.digest)));
                        CJson mj;
                        SManifest am;
                        if (CFile::readAll(path, text) != SBOX_OK || DigestOf(text) != d.digest || CJson::parse(text, mj) != SBOX_OK ||
                            SManifest::fromJson(mj, am) != SBOX_OK || am.config.digest != configDigest ||
                            am.layers.size() != m.layers.size()) {
                            continue;
                        }

                        bool same = true;
                        for (size_t l = 0; l < am.layers.size(); ++l) {
                            same = same && am.layers[l].digest == m.layers[l].digest;
                        }

                        if (same && store.writeBlob(BytesOf(text), manifestDesc.digest, d.digest) == SBOX_OK) {
                            manifestDesc.mediaType = am.mediaType.empty() ? MT_OCI_MANIFEST : am.mediaType;
                            manifestDesc.size = int64_t(text.size());
                            reused = true;
                            break;
                        }
                    }
                }

                if (!reused) {
                    r = store.writeJsonBlob(m.toJson(), MT_OCI_MANIFEST, manifestDesc);
                    if (r != SBOX_OK) {
                        return failWith(error, r, "cannot store the manifest");
                    }
                }

                lease.addBlob(manifestDesc.digest);
                manifestDesc.platform = config.platform();
                manifestDesc.hasPlatform = !config.os.empty();
                std::vector<std::string> tags = entry.get("RepoTags").asStrings();
                if (tags.empty()) {
                    r = store.setRecord(std::string(), manifestDesc);
                }

                for (const std::string& t : tags) {
                    SReference ref;
                    if (ParseDockerReference(t, ref) != SBOX_OK || ref.hasDigest()) {
                        return failWith(error, -EINVAL, "invalid RepoTags entry " + t);
                    }

                    r = store.setRecord(ref.toString(), manifestDesc);
                    if (r != SBOX_OK) {
                        break;
                    }

                    out.tags.push_back(ref.toString());
                }

                if (r != SBOX_OK) {
                    return failWith(error, r, "cannot update index.json");
                }

                out.imageIds.push_back(configDigest);
            }

            return SBOX_OK;
        }

        if (hasIndex && CFile::exists(CFile::join(root, "oci-layout"))) {
            out.format = "oci";
            SPlatform want = options.platform.empty() ? HostPlatform() : options.platform;
            for (const SDescriptor& top : layoutIndex.manifests) {
                SDescriptor manifestDesc = top;
                r = importLayoutBlob(store, root, top.digest, lease, error);
                if (r != SBOX_OK) {
                    return r;
                }

                CJson doc;
                if (store.readJsonBlob(top.digest, doc) != SBOX_OK) {
                    return failWith(error, -EBADMSG, "unreadable manifest " + top.digest);
                }

                EManifestKind kind = ClassifyManifest(doc, top.mediaType);
                if (kind == EMK_INDEX) {
                    SIndex nested;
                    if (SIndex::fromJson(doc, nested) != SBOX_OK) {
                        return failWith(error, -EBADMSG, "malformed nested index " + top.digest);
                    }

                    int32_t pick = nested.select(want);
                    if (pick < 0) {
                        return failWith(error, -ENOEXEC, "no manifest for " + want.toString() + " in " + top.digest);
                    }

                    manifestDesc = nested.manifests[size_t(pick)];
                    r = importLayoutBlob(store, root, manifestDesc.digest, lease, error);
                    if (r != SBOX_OK) {
                        return r;
                    }

                    if (store.readJsonBlob(manifestDesc.digest, doc) != SBOX_OK) {
                        return failWith(error, -EBADMSG, "unreadable manifest " + manifestDesc.digest);
                    }

                    kind = ClassifyManifest(doc, manifestDesc.mediaType);
                }

                if (kind != EMK_MANIFEST) {
                    return failWith(error, -ENOTSUP, "index entry " + top.digest + " is not an image manifest");
                }

                SManifest m;
                if (SManifest::fromJson(doc, m) != SBOX_OK) {
                    return failWith(error, -EBADMSG, "malformed manifest " + manifestDesc.digest);
                }

                r = importLayoutBlob(store, root, m.config.digest, lease, error);
                for (size_t l = 0; l < m.layers.size() && r == SBOX_OK; ++l) {
                    r = importLayoutBlob(store, root, m.layers[l].digest, lease, error);
                }

                if (r != SBOX_OK) {
                    return r;
                }

                std::string name = top.annotation(ANNOTATION_IMAGE_NAME);
                std::string refName = top.annotation(ANNOTATION_REF_NAME);
                SReference ref;
                if (name.empty() && !refName.empty()) {
                    // --> A full reference in ref.name, or a bare tag combined with the given name.
                    if (refName.find('/') != std::string::npos && ParseDockerReference(refName, ref) == SBOX_OK) {
                        name = ref.toString();
                    } else if (!options.name.empty() && IsValidTag(refName)) {
                        SReference base;
                        if (ParseNormalizedReference(options.name, base) == SBOX_OK) {
                            base.tag = refName;
                            base.digest.clear();
                            name = base.toString();
                        }
                    }
                } else if (name.empty() && !options.name.empty()) {
                    if (ParseDockerReference(options.name, ref) == SBOX_OK) {
                        name = ref.toString();
                    }
                }

                if (!name.empty()) {
                    if (ParseDockerReference(name, ref) != SBOX_OK) {
                        return failWith(error, -EINVAL, "invalid image name " + name);
                    }

                    name = ref.toString();
                }

                SDescriptor rec;
                rec.mediaType = m.mediaType.empty() ? (manifestDesc.mediaType.empty() ? std::string(MT_OCI_MANIFEST) : manifestDesc.mediaType) : m.mediaType;
                rec.digest = manifestDesc.digest;
                rec.size = manifestDesc.size;
                rec.platform = manifestDesc.platform;
                rec.hasPlatform = manifestDesc.hasPlatform;
                r = store.setRecord(name, rec);
                if (r != SBOX_OK) {
                    return failWith(error, r, "cannot update index.json");
                }

                if (!name.empty()) {
                    out.tags.push_back(name);
                }

                if (std::find(out.imageIds.begin(), out.imageIds.end(), m.config.digest) == out.imageIds.end()) {
                    out.imageIds.push_back(m.config.digest);
                }
            }

            return SBOX_OK;
        }

        if (CFile::exists(CFile::join(root, "repositories"))) {
            return failWith(error, -ENOTSUP, "this is a pre-1.10 docker save archive (no manifest.json); it is not supported");
        }

        return failWith(error, -EINVAL, "not an image archive: neither manifest.json nor an OCI layout found");
    }

}
}
