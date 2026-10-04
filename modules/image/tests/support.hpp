#ifndef __TESTS_IMAGE_SUPPORT_HPP__
#define __TESTS_IMAGE_SUPPORT_HPP__

// Helpers shared by the image tests (each test file is its own executable): temporary
// directories, a builder for layer tarballs and images, and an in-process registry.

#include <sbox/archive/codec.hpp>
#include <sbox/archive/stream.hpp>
#include <sbox/archive/tar.hpp>
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/socket.hpp>
#include <sbox/http/auth.hpp>
#include <sbox/http/headers.hpp>
#include <sbox/http/server.hpp>
#include <sbox/image/digest.hpp>
#include <sbox/image/spec.hpp>
#include <sbox/image/store.hpp>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace testsupport {

    using namespace sbox;
    using namespace sbox::image;

    /**
     * mkdtemp under /var/tmp (traversable by other users, unlike the scratch directory) that
     * removes itself.
     */
    struct TempDir {
        std::string path;

        TempDir() {
            char tmpl[] = "/var/tmp/sbox-image-test-XXXXXX";
            char* p = ::mkdtemp(tmpl);
            path = p ? p : "";
            ::chmod(path.c_str(), 0755);
        }

        ~TempDir() {
            if (!path.empty()) {
                // --> Leftover mounts (failed tests) are detached first so removal works.
                CFile::removeTree(path);
            }
        }

        std::string sub(const std::string& leaf) const {
            return CFile::join(path, leaf);
        }
    };

    /**
     * One entry of a test layer.
     */
    struct LayerEntry {
        archive::ETarEntryType type = archive::ETAR_FILE;
        std::string path;
        std::string data;           // --> File content, or link target.
        uint32_t mode = 0644;
        int64_t uid = 0;
        int64_t gid = 0;
    };

    /** Shorthand for a regular file entry. */
    inline LayerEntry File(const std::string& path, const std::string& data, uint32_t mode = 0644) {
        LayerEntry e;
        e.path = path;
        e.data = data;
        e.mode = mode;
        return e;
    }

    /** Shorthand for a directory entry. */
    inline LayerEntry Dir(const std::string& path, uint32_t mode = 0755) {
        LayerEntry e;
        e.type = archive::ETAR_DIR;
        e.path = path;
        e.mode = mode;
        return e;
    }

    /** Shorthand for a symlink entry. */
    inline LayerEntry Link(const std::string& path, const std::string& target) {
        LayerEntry e;
        e.type = archive::ETAR_SYMLINK;
        e.path = path;
        e.data = target;
        e.mode = 0777;
        return e;
    }

    /**
     * Builds an uncompressed tar from entries.
     */
    inline std::string BuildTar(const std::vector<LayerEntry>& entries) {
        std::vector<uint8_t> out;
        archive::CVectorSink sink(out);
        archive::CTarWriter w(sink);
        for (const LayerEntry& e : entries) {
            archive::STarEntry te;
            te.type = e.type;
            te.path = e.path;
            te.mode = e.mode;
            te.uid = e.uid;
            te.gid = e.gid;
            te.mtime.sec = 1700000000;
            if (e.type == archive::ETAR_SYMLINK || e.type == archive::ETAR_HARDLINK) {
                te.linkPath = e.data;
                w.writeEntry(te);
            } else if (e.type == archive::ETAR_FILE) {
                te.size = e.data.size();
                w.writeEntry(te, BytesOf(e.data));
            } else {
                w.writeEntry(te);
            }
        }

        w.finish();
        return std::string(out.begin(), out.end());
    }

    /**
     * Compresses with gzip.
     */
    inline std::string Gzip(const std::string& data) {
        std::vector<uint8_t> out;
        archive::CVectorSink sink(out);
        archive::CCodecSink gz(archive::CreateEncoder(archive::ECOMP_GZIP, 6), sink);
        gz.write(BytesOf(data));
        gz.finish();
        return std::string(out.begin(), out.end());
    }

    /**
     * A built image: blobs keyed by digest plus the documents.
     */
    struct TestImage {
        std::map<std::string, std::string> blobs;
        std::string manifest;           // --> Exact manifest bytes.
        std::string manifestDigest;
        std::string manifestType;
        std::string config;
        std::string configDigest;
        std::vector<std::string> diffIds;
        std::vector<std::string> layerDigests;
    };

    /**
     * Builds an image from layers (gzip compressed) and container defaults.
     * @param docker Use Docker schema 2 media types instead of OCI.
     */
    inline TestImage BuildImage(const std::vector<std::vector<LayerEntry>>& layers, const std::string& arch = "",
                                bool docker = false, const std::vector<std::string>& cmd = { "/bin/sh" },
                                const std::string& user = "", const std::vector<std::string>& env = { "PATH=/usr/bin:/bin" }) {
        TestImage img;
        SManifest m;
        m.mediaType = docker ? MT_DOCKER_MANIFEST : MT_OCI_MANIFEST;
        for (const auto& entries : layers) {
            std::string tar = BuildTar(entries);
            std::string gz = Gzip(tar);
            std::string diff = DigestOf(tar);
            std::string dg = DigestOf(gz);
            img.blobs[dg] = gz;
            img.diffIds.push_back(diff);
            img.layerDigests.push_back(dg);
            SDescriptor d;
            d.mediaType = docker ? MT_DOCKER_LAYER_GZIP : MT_OCI_LAYER_GZIP;
            d.digest = dg;
            d.size = int64_t(gz.size());
            m.layers.push_back(d);
        }

        SImageConfig c;
        c.architecture = arch.empty() ? HostPlatform().architecture : arch;
        c.os = "linux";
        if (arch.empty()) {
            c.variant = HostPlatform().variant;
        }

        c.created = "2024-01-01T00:00:00Z";
        c.diffIds = img.diffIds;
        c.cmd = cmd;
        c.env = env;
        c.user = user;
        c.workingDir = "/";
        c.exposedPorts = { "80/tcp" };
        c.volumes = { "/data" };
        c.labels = { { "org.example.test", "yes" } };
        CJson raw = c.toJson();
        raw["history"].push(CJson::object());
        img.config = raw.dump();
        img.configDigest = DigestOf(img.config);
        img.blobs[img.configDigest] = img.config;
        m.config.mediaType = docker ? MT_DOCKER_CONFIG : MT_OCI_CONFIG;
        m.config.digest = img.configDigest;
        m.config.size = int64_t(img.config.size());
        img.manifest = m.toJson().dump();
        img.manifestDigest = DigestOf(img.manifest);
        img.manifestType = m.mediaType;
        return img;
    }

    /**
     * Builds an index document over manifests of images with their platforms.
     */
    inline std::string BuildIndex(const std::vector<std::pair<const TestImage*, std::string>>& entries, bool docker = false) {
        SIndex idx;
        idx.mediaType = docker ? MT_DOCKER_MANIFEST_LIST : MT_OCI_INDEX;
        for (const auto& [img, plat] : entries) {
            SDescriptor d;
            d.mediaType = img->manifestType;
            d.digest = img->manifestDigest;
            d.size = int64_t(img->manifest.size());
            SPlatform::parse(plat, d.platform);
            d.hasPlatform = true;
            idx.manifests.push_back(d);
        }

        return idx.toJson().dump();
    }

    /**
     * Puts a built image into a store under `name` ("" for untagged).
     */
    inline int32_t ImportImage(CContentStore& store, const TestImage& img, const std::string& name) {
        for (const auto& [d, b] : img.blobs) {
            std::string stored;
            int32_t r = store.writeBlob(BytesOf(b), stored, d);
            if (r != SBOX_OK) {
                return r;
            }
        }

        SDescriptor md;
        md.mediaType = img.manifestType;
        int32_t r = store.writeBlob(BytesOf(img.manifest), md.digest, img.manifestDigest);
        if (r != SBOX_OK) {
            return r;
        }

        md.size = int64_t(img.manifest.size());
        return store.setRecord(name, md);
    }

    /**
     * Reads a file into a string ("" when missing).
     */
    inline std::string ReadText(const std::string& path) {
        std::string s;
        CFile::readAll(path, s);
        return s;
    }

    /**
     * Returns true when the process is root (tests needing mknod/mount check this).
     */
    inline bool IsRoot() {
        return ::geteuid() == 0;
    }

    /**
     * Stream that yields bytes of a string and fails (-ECONNRESET) after `failAt` bytes when set.
     */
    class CutStream : public IStream {
    public:
        std::string data;
        size_t pos = 0;
        size_t failAt;

        CutStream(std::string d, size_t start, size_t fail) : data(std::move(d)), pos(start), failAt(fail) {}

        TTask<SIoResult> recv(const SByteSpan& buffer, int64_t) override {
            if (pos >= failAt) {
                co_return SIoResult{ -ECONNRESET, 0 };
            }

            size_t n = std::min(buffer.size, std::min(data.size(), failAt) - pos);
            std::memcpy(buffer.data, data.data() + pos, n);
            pos += n;
            co_return SIoResult{ SBOX_OK, n };
        }

        TTask<SIoResult> send(const SReadOnlyByteSpan&, int64_t) override {
            co_return SIoResult{ -ENOTSUP, 0 };
        }

        void close() noexcept override {}
    };

    /**
     * In-process registry: Bearer token auth (token endpoint on the same server), manifests,
     * blob GET redirected to a second "CDN" server on 127.0.0.2, Range support, uploads.
     */
    struct TestRegistry {
        http::CHttpServer api;
        http::CHttpServer cdn;
        CListener apiListener;
        CListener cdnListener;
        bool apiDone = false;
        bool cdnDone = false;

        std::map<std::string, std::string> blobs;                           // --> digest -> bytes.
        std::map<std::string, std::map<std::string, std::pair<std::string, std::string>>> manifests;  // --> repo -> ref -> (type, body).
        std::map<std::string, std::string> uploads;                         // --> upload id -> bytes so far.
        std::set<std::string> repoBlobs;                                    // --> "repo|digest" present.

        bool requireAuth = true;
        std::string basicUser;          // --> When set, the token endpoint requires Basic credentials.
        std::string basicPassword;
        bool redirectBlobs = true;
        std::map<std::string, size_t> cutOnce;     // --> digest -> cut the first CDN response after N bytes.
        int32_t tokenRequests = 0;
        int32_t cdnAuthLeaks = 0;                  // --> CDN requests that carried Authorization.
        int32_t rangeRequests = 0;
        int32_t blobGets = 0;
        int32_t mounts = 0;
        int32_t patches = 0;
        std::vector<std::string> tokenScopes;

        /** Returns the API base URL. */
        std::string base() const {
            return "http://127.0.0.1:" + std::to_string(apiListener.localEndpoint().port());
        }

        /** Returns "127.0.0.1:port" (the registry domain in references). */
        std::string domain() const {
            return "127.0.0.1:" + std::to_string(apiListener.localEndpoint().port());
        }

        /** Returns the CDN base URL. */
        std::string cdnBase() const {
            return "http://127.0.0.2:" + std::to_string(cdnListener.localEndpoint().port());
        }

        /** Publishes an image under repo:tag. */
        void add(const std::string& repo, const std::string& tag, const TestImage& img) {
            for (const auto& [d, b] : img.blobs) {
                blobs[d] = b;
                repoBlobs.insert(repo + "|" + d);
            }

            manifests[repo][img.manifestDigest] = { img.manifestType, img.manifest };
            if (!tag.empty()) {
                manifests[repo][tag] = { img.manifestType, img.manifest };
            }
        }

        /** Publishes a raw manifest document under repo:ref. */
        void addManifest(const std::string& repo, const std::string& ref, const std::string& type, const std::string& body) {
            manifests[repo][ref] = { type, body };
            manifests[repo][DigestOf(body)] = { type, body };
        }

        /** Returns the challenge header for a scope. */
        std::string challenge(const std::string& scope) const {
            std::string c = "Bearer realm=\"" + base() + "/token\",service=\"test-registry\"";
            if (!scope.empty()) {
                c += ",scope=\"" + scope + "\"";
            }

            return c;
        }

        /** Checks a bearer token for an action on a repository. */
        bool authorized(const http::SServerRequest& req, const std::string& repo, const std::string& action) const {
            if (!requireAuth) {
                return true;
            }

            std::string auth = req.headers.get("Authorization");
            if (auth.compare(0, 7, "Bearer ") != 0) {
                return false;
            }

            // --> Tokens are "tok|scope1|scope2...".
            std::string token = auth.substr(7);
            size_t pos = 0;
            while ((pos = token.find("repository:" + repo + ":", pos)) != std::string::npos) {
                size_t end = token.find('|', pos);
                std::string scope = token.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
                std::string actions = scope.substr(scope.rfind(':') + 1);
                if (actions.find(action) != std::string::npos) {
                    return true;
                }

                pos += 1;
            }

            return false;
        }

        /** Answers 401 with a challenge. */
        void deny(http::SServerResponse& res, const std::string& scope) const {
            res.headers.set("WWW-Authenticate", challenge(scope));
            res.setJson(CJson::object(), 401);
            CJson err;
            CJson::parse(R"({"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]})", err);
            res.setJson(err, 401);
        }

        /** Splits "/v2/<name>/<kind>/<rest>" (name may contain slashes). */
        static bool splitPath(const std::string& path, std::string& name, std::string& kind, std::string& rest) {
            if (path.compare(0, 4, "/v2/") != 0) {
                return false;
            }

            std::string p = path.substr(4);
            for (const char* k : { "/manifests/", "/blobs/uploads/", "/blobs/", "/tags/list" }) {
                size_t at = p.rfind(k);
                if (at != std::string::npos) {
                    name = p.substr(0, at);
                    kind = k;
                    rest = p.substr(at + std::strlen(k));
                    return true;
                }

                if (std::string(k) == "/blobs/uploads/" && p.size() >= 14 && p.compare(p.size() - 14, 14, "/blobs/uploads") == 0) {
                    name = p.substr(0, p.size() - 14);
                    kind = k;
                    rest.clear();
                    return true;
                }
            }

            return false;
        }

        /** Serves a blob (with Range). */
        static void serveBlob(TestRegistry* self, const http::SServerRequest& req, http::SServerResponse& res, const std::string& digest) {
            auto it = self->blobs.find(digest);
            if (it == self->blobs.end()) {
                res.setText("", 404);
                return;
            }

            const std::string& data = it->second;
            uint64_t first = 0;
            uint64_t last = data.size() ? data.size() - 1 : 0;
            const std::string* range = req.headers.find("Range");
            if (range) {
                ++self->rangeRequests;
                if (http::ParseRange(*range, data.size(), first, last) != SBOX_OK) {
                    res.status = 416;
                    res.headers.set("Content-Range", "bytes */" + std::to_string(data.size()));
                    return;
                }

                res.status = 206;
                http::SContentRange cr;
                cr.first = first;
                cr.last = last;
                cr.completeLength = int64_t(data.size());
                res.headers.set("Content-Range", cr.toString());
            }

            size_t len = data.empty() ? 0 : size_t(last - first + 1);
            size_t failAt = first + len;
            auto cut = self->cutOnce.find(digest);
            if (cut != self->cutOnce.end() && !range) {
                failAt = cut->second;
                self->cutOnce.erase(cut);
            }

            int32_t status = res.status;
            res.setStream(std::make_shared<CutStream>(data.substr(0, first + len), first, failAt), int64_t(len));
            res.status = status;
            res.headers.set("Docker-Content-Digest", digest);
        }

        /** Starts both servers. */
        int32_t start() {
            SEndpoint ep;
            SEndpoint::fromIp("127.0.0.1", 0, ep);
            int32_t r = apiListener.listen(ep);
            if (r != SBOX_OK) {
                return r;
            }

            SEndpoint ep2;
            SEndpoint::fromIp("127.0.0.2", 0, ep2);
            r = cdnListener.listen(ep2);
            if (r != SBOX_OK) {
                return r;
            }

            TestRegistry* self = this;
            api.route("GET", "/token", [self](http::SServerRequest& req, http::SServerResponse& res) -> TTask<void> {
                ++self->tokenRequests;
                if (!self->basicUser.empty()) {
                    std::string u;
                    std::string p;
                    if (http::DecodeBasicAuth(req.headers.get("Authorization"), u, p) != SBOX_OK || u != self->basicUser ||
                        p != self->basicPassword) {
                        CJson err = CJson::object();
                        err.set("details", "incorrect username or password");
                        res.setJson(err, 401);
                        co_return;
                    }
                }

                std::string token = "tok";
                http::SQueryParams params;
                http::ParseQuery(req.query, params);
                for (const auto& [k, v] : params) {
                    if (k == "scope") {
                        token += "|" + v;
                        self->tokenScopes.push_back(v);
                    }
                }

                CJson out = CJson::object();
                out.set("token", token);
                out.set("expires_in", 300);
                res.setJson(out);
                co_return;
            });

            api.route("GET", "/v2/", [self](http::SServerRequest& req, http::SServerResponse& res) -> TTask<void> {
                if (self->requireAuth && req.headers.get("Authorization").empty()) {
                    self->deny(res, "");
                    co_return;
                }

                res.setJson(CJson::object());
                co_return;
            });

            api.routePrefix("*", "/v2/", [self](http::SServerRequest& req, http::SServerResponse& res) -> TTask<void> {
                std::string name;
                std::string kind;
                std::string rest;
                if (!splitPath(req.path, name, kind, rest)) {
                    res.setText("", 404);
                    co_return;
                }

                bool write = req.method != "GET" && req.method != "HEAD";
                if (!self->authorized(req, name, write ? "push" : "pull")) {
                    self->deny(res, "repository:" + name + (write ? ":pull,push" : ":pull"));
                    co_return;
                }

                if (kind == "/manifests/") {
                    if (req.method == "PUT") {
                        std::string body;
                        co_await req.readText(body);
                        std::string type = req.headers.get("Content-Type");
                        self->manifests[name][rest] = { type, body };
                        self->manifests[name][DigestOf(body)] = { type, body };
                        res.headers.set("Docker-Content-Digest", DigestOf(body));
                        res.headers.set("Location", "/v2/" + name + "/manifests/" + DigestOf(body));
                        res.setText("", 201);
                        co_return;
                    }

                    auto repo = self->manifests.find(name);
                    if (repo == self->manifests.end() || !repo->second.count(rest)) {
                        CJson err;
                        CJson::parse(R"({"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]})", err);
                        res.setJson(err, 404);
                        co_return;
                    }

                    const auto& [type, body] = repo->second[rest];
                    res.setText(body, 200, type);
                    res.headers.set("Docker-Content-Digest", DigestOf(body));
                    co_return;
                }

                if (kind == "/blobs/uploads/") {
                    if (req.method == "POST") {
                        http::SQueryParams q;
                        http::ParseQuery(req.query, q);
                        std::string mount;
                        std::string from;
                        for (const auto& [k, v] : q) {
                            if (k == "mount") {
                                mount = v;
                            } else if (k == "from") {
                                from = v;
                            }
                        }

                        if (!mount.empty() && self->repoBlobs.count(from + "|" + mount) && self->authorized(req, from, "pull")) {
                            ++self->mounts;
                            self->repoBlobs.insert(name + "|" + mount);
                            res.headers.set("Location", "/v2/" + name + "/blobs/" + mount);
                            res.setText("", 201);
                            co_return;
                        }

                        std::string id = "up" + std::to_string(self->uploads.size() + 1);
                        self->uploads[id] = "";
                        res.headers.set("Location", "/v2/" + name + "/blobs/uploads/" + id + "?_state=x");
                        res.headers.set("Range", "0-0");
                        res.setText("", 202);
                        co_return;
                    }

                    auto up = self->uploads.find(rest);
                    if (up == self->uploads.end()) {
                        res.setText("", 404);
                        co_return;
                    }

                    std::string body;
                    co_await req.readText(body);
                    if (req.method == "PATCH") {
                        ++self->patches;
                        std::string cr = req.headers.get("Content-Range");
                        if (!cr.empty() && cr.compare(0, std::to_string(up->second.size()).size() + 1, std::to_string(up->second.size()) + "-") != 0) {
                            res.setText("", 416);
                            co_return;
                        }

                        up->second += body;
                        res.headers.set("Location", "/v2/" + name + "/blobs/uploads/" + rest + "?_state=y");
                        res.headers.set("Range", "0-" + std::to_string(up->second.size() - 1));
                        res.setText("", 202);
                        co_return;
                    }

                    if (req.method == "PUT") {
                        up->second += body;
                        std::string digest = req.queryParam("digest");
                        if (DigestOf(up->second) != digest) {
                            CJson err;
                            CJson::parse(R"({"errors":[{"code":"DIGEST_INVALID","message":"digest mismatch"}]})", err);
                            res.setJson(err, 400);
                            co_return;
                        }

                        self->blobs[digest] = up->second;
                        self->repoBlobs.insert(name + "|" + digest);
                        self->uploads.erase(up);
                        res.headers.set("Docker-Content-Digest", digest);
                        res.setText("", 201);
                        co_return;
                    }

                    res.setText("", 405);
                    co_return;
                }

                if (kind == "/blobs/") {
                    if (!self->repoBlobs.count(name + "|" + rest) || !self->blobs.count(rest)) {
                        CJson err;
                        CJson::parse(R"({"errors":[{"code":"BLOB_UNKNOWN","message":"blob unknown to registry"}]})", err);
                        res.setJson(err, 404);
                        co_return;
                    }

                    if (req.method == "HEAD") {
                        res.headers.set("Content-Length", std::to_string(self->blobs[rest].size()));
                        res.headers.set("Docker-Content-Digest", rest);
                        res.status = 200;
                        co_return;
                    }

                    ++self->blobGets;
                    if (self->redirectBlobs) {
                        res.headers.set("Location", self->cdnBase() + "/cdn/" + rest + "?sig=abc");
                        res.setText("", 307);
                        co_return;
                    }

                    serveBlob(self, req, res, rest);
                    co_return;
                }

                if (kind == "/tags/list") {
                    CJson out = CJson::object();
                    out.set("name", name);
                    std::vector<std::string> tags;
                    for (const auto& [ref, doc] : self->manifests[name]) {
                        if (ref.compare(0, 7, "sha256:") != 0) {
                            tags.push_back(ref);
                        }
                    }

                    // --> Paginate one tag per page to exercise Link.
                    std::string last = req.queryParam("last");
                    std::vector<std::string> page;
                    for (const std::string& t : tags) {
                        if (last.empty() || t > last) {
                            page.push_back(t);
                            break;
                        }
                    }

                    out.set("tags", CJson::fromStrings(page));
                    if (!page.empty() && page.back() != tags.back()) {
                        res.headers.set("Link", "</v2/" + name + "/tags/list?n=1&last=" + page.back() + ">; rel=\"next\"");
                    }

                    res.setJson(out);
                    co_return;
                }

                res.setText("", 404);
                co_return;
            });

            cdn.routePrefix("GET", "/cdn/", [self](http::SServerRequest& req, http::SServerResponse& res) -> TTask<void> {
                if (req.headers.has("Authorization")) {
                    ++self->cdnAuthLeaks;
                }

                serveBlob(self, req, res, req.routeRest);
                co_return;
            });

            CEventLoop::current()->spawn([](TestRegistry* s) -> TTask<void> {
                co_await s->api.serve(s->apiListener);
                s->apiDone = true;
            }(this));
            CEventLoop::current()->spawn([](TestRegistry* s) -> TTask<void> {
                co_await s->cdn.serve(s->cdnListener);
                s->cdnDone = true;
            }(this));
            return SBOX_OK;
        }

        /** Stops both servers. */
        TTask<void> stop() {
            api.stop(true);
            cdn.stop(true);
            while (!apiDone || !cdnDone) {
                co_await CEventLoop::current()->sleepFor(1);
            }
        }
    };

}

#endif
