#include <sbox/image/spec.hpp>
#include <sbox/image/digest.hpp>
#include <cerrno>
#include <cstdio>
#include <ctime>
#include <sys/utsname.h>

namespace sbox {
namespace image {

    namespace {

        /* Returns a lower-cased copy. */
        std::string lower(std::string_view s) {
            std::string out(s);
            for (char& c : out) {
                if (c >= 'A' && c <= 'Z') {
                    c = char(c - 'A' + 'a');
                }
            }

            return out;
        }

        /* Reads a string member ("" when absent or not a string). */
        std::string str(const CJson& obj, std::string_view key) {
            const CJson* v = obj.find(key);
            return v && v->isString() ? v->asString() : std::string();
        }

        /* Reads a string->string object into pairs. */
        void readPairs(const CJson* obj, std::vector<std::pair<std::string, std::string>>& out) {
            out.clear();
            if (!obj || !obj->isObject()) {
                return;
            }

            for (size_t i = 0; i < obj->size(); ++i) {
                out.emplace_back(obj->keyAt(i), obj->at(i).asString());
            }
        }

        /* Writes pairs as a string->string object. */
        CJson writePairs(const std::vector<std::pair<std::string, std::string>>& pairs) {
            CJson o = CJson::object();
            for (const auto& [k, v] : pairs) {
                o.set(k, v);
            }

            return o;
        }

        /* Reads the keys of an object ({"80/tcp": {}}). */
        std::vector<std::string> readKeys(const CJson* obj) {
            std::vector<std::string> out;
            if (obj && obj->isObject()) {
                for (size_t i = 0; i < obj->size(); ++i) {
                    out.push_back(obj->keyAt(i));
                }
            }

            return out;
        }

        /* Writes keys as an object of empty objects. */
        CJson writeKeys(const std::vector<std::string>& keys) {
            CJson o = CJson::object();
            for (const std::string& k : keys) {
                o.set(k, CJson::object());
            }

            return o;
        }

        /* Sets a member when `value` is non-empty, removes it otherwise. */
        void setOrRemove(CJson& obj, std::string_view key, const std::string& value) {
            if (value.empty()) {
                obj.remove(key);
            } else {
                obj.set(key, value);
            }
        }

        /* Parses an arm variant "vN" into N (0 when not of that form). */
        int32_t variantNumber(std::string_view v) {
            if (v.size() < 2 || v[0] != 'v') {
                return 0;
            }

            int32_t n = 0;
            for (char c : v.substr(1)) {
                if (c < '0' || c > '9') {
                    return 0;
                }

                n = n * 10 + (c - '0');
            }

            return n;
        }

    }

    /* Returns true for an index media type. */
    bool IsIndexMediaType(std::string_view mediaType) noexcept {
        return mediaType == MT_OCI_INDEX || mediaType == MT_DOCKER_MANIFEST_LIST;
    }

    /* Returns true for a manifest media type. */
    bool IsManifestMediaType(std::string_view mediaType) noexcept {
        return mediaType == MT_OCI_MANIFEST || mediaType == MT_DOCKER_MANIFEST;
    }

    /* Returns true for a layer media type. */
    bool IsLayerMediaType(std::string_view mediaType) noexcept {
        static const char* const TYPES[] = {
            MT_OCI_LAYER, MT_OCI_LAYER_GZIP, MT_OCI_LAYER_ZSTD,
            "application/vnd.oci.image.layer.nondistributable.v1.tar",
            "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
            "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
            MT_DOCKER_LAYER_GZIP, MT_DOCKER_LAYER, MT_DOCKER_FOREIGN_LAYER,
            "application/vnd.docker.image.rootfs.diff.tar.zstd",
        };

        for (const char* t : TYPES) {
            if (mediaType == t) {
                return true;
            }
        }

        return false;
    }

    /* Returns true for schema 1 media types. */
    bool IsSchema1MediaType(std::string_view mediaType) noexcept {
        return mediaType == MT_DOCKER_SCHEMA1 || mediaType == MT_DOCKER_SCHEMA1_SIGNED;
    }

    /* Parses "os/arch/variant". */
    int32_t SPlatform::parse(std::string_view text, SPlatform& out) {
        out = SPlatform();
        std::vector<std::string> parts;
        size_t start = 0;
        while (true) {
            size_t slash = text.find('/', start);
            parts.emplace_back(lower(text.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start)));
            if (slash == std::string_view::npos) {
                break;
            }

            start = slash + 1;
        }

        for (const std::string& p : parts) {
            if (p.empty()) {
                return -EINVAL;
            }
        }

        if (parts.size() == 1) {
            // --> A bare OS name keeps the host architecture; anything else is an architecture.
            if (parts[0] == "linux" || parts[0] == "windows" || parts[0] == "darwin") {
                out = HostPlatform();
                out.os = parts[0];
            } else {
                out.os = "linux";
                out.architecture = parts[0];
            }
        } else if (parts.size() <= 3) {
            out.os = parts[0];
            out.architecture = parts[1];
            if (parts.size() == 3) {
                out.variant = parts[2];
            }
        } else {
            return -EINVAL;
        }

        out = out.normalized();
        return SBOX_OK;
    }

    /* Returns "os/arch[/variant]". */
    std::string SPlatform::toString() const {
        std::string s = os + "/" + architecture;
        if (!variant.empty()) {
            s += "/" + variant;
        }

        return s;
    }

    /* Returns the canonical spelling. */
    SPlatform SPlatform::normalized() const {
        SPlatform p = *this;
        p.os = lower(p.os);
        if (p.os == "macos") {
            p.os = "darwin";
        }

        std::string arch = lower(p.architecture);
        std::string var = lower(p.variant);
        if (arch == "i386") {
            arch = "386";
            var.clear();
        } else if (arch == "x86_64" || arch == "x86-64" || arch == "amd64") {
            arch = "amd64";
            if (var == "v1") {
                var.clear();
            }
        } else if (arch == "aarch64" || arch == "arm64") {
            arch = "arm64";
            if (var == "8" || var == "v8" || var == "v8.0") {
                var.clear();
            }
        } else if (arch == "armhf") {
            arch = "arm";
            var = "v7";
        } else if (arch == "armel") {
            arch = "arm";
            var = "v6";
        } else if (arch == "arm") {
            if (var.empty() || var == "7") {
                var = "v7";
            } else if (var == "5" || var == "6" || var == "8") {
                var = "v" + var;
            }
        }

        p.architecture = arch;
        p.variant = var;
        return p;
    }

    /* Reads an OCI platform object. */
    SPlatform SPlatform::fromJson(const CJson& json) {
        SPlatform p;
        p.os = str(json, "os");
        p.architecture = str(json, "architecture");
        p.variant = str(json, "variant");
        p.osVersion = str(json, "os.version");
        const CJson* f = json.find("os.features");
        if (f) {
            p.osFeatures = f->asStrings();
        }

        return p;
    }

    /* Writes an OCI platform object. */
    CJson SPlatform::toJson() const {
        CJson o = CJson::object();
        o.set("architecture", architecture);
        o.set("os", os);
        if (!osVersion.empty()) {
            o.set("os.version", osVersion);
        }

        if (!osFeatures.empty()) {
            o.set("os.features", CJson::fromStrings(osFeatures));
        }

        if (!variant.empty()) {
            o.set("variant", variant);
        }

        return o;
    }

    /* Returns the host platform. */
    SPlatform HostPlatform() {
        SPlatform p;
        p.os = "linux";
        struct utsname u{};
        if (::uname(&u) == 0) {
            std::string m = u.machine;
            if (m == "armv7l" || m == "armv7") {
                p.architecture = "arm";
                p.variant = "v7";
            } else if (m == "armv6l" || m == "armv6") {
                p.architecture = "arm";
                p.variant = "v6";
            } else if (m == "armv5tel" || m == "armv5") {
                p.architecture = "arm";
                p.variant = "v5";
            } else if (m == "i686" || m == "i586" || m == "i486") {
                p.architecture = "386";
            } else if (m == "ppc64le" || m == "s390x" || m == "riscv64" || m == "mips64" || m == "loong64") {
                p.architecture = m;
            } else if (m == "loongarch64") {
                p.architecture = "loong64";
            } else {
                p.architecture = m;
            }
        }

        return p.normalized();
    }

    /* Scores a candidate platform. */
    int32_t PlatformScore(const SPlatform& want, const SPlatform& candidate) {
        SPlatform w = want.normalized();
        SPlatform c = candidate.normalized();
        if (w.os != c.os || w.architecture != c.architecture) {
            return 0;
        }

        if (w.variant == c.variant) {
            return 1000;
        }

        if (w.architecture == "arm") {
            // --> An arm v7 machine runs v6 and v5 images (older variants score lower).
            int32_t wn = variantNumber(w.variant);
            int32_t cn = variantNumber(c.variant);
            if (wn > 0 && cn > 0 && cn < wn) {
                return 500 - (wn - cn);
            }

            return 0;
        }

        if (w.architecture == "amd64") {
            // --> amd64 microarchitecture levels: a v3 host runs v2, v1 ("") images.
            int32_t wn = variantNumber(w.variant);
            int32_t cn = c.variant.empty() ? 1 : variantNumber(c.variant);
            if (w.variant.empty()) {
                wn = 1;
            }

            if (wn > 0 && cn > 0 && cn <= wn) {
                return 500 - (wn - cn);
            }

            return 0;
        }

        if (w.variant.empty() || c.variant.empty()) {
            return 100;
        }

        return 0;
    }

    /* Reads a descriptor. */
    int32_t SDescriptor::fromJson(const CJson& json, SDescriptor& out) {
        out = SDescriptor();
        if (!json.isObject()) {
            return -EINVAL;
        }

        out.mediaType = str(json, "mediaType");
        out.digest = str(json, "digest");
        out.artifactType = str(json, "artifactType");
        const CJson* size = json.find("size");
        if (!size || size->type() != EJSON_INT || size->asInt() < 0) {
            return -EINVAL;
        }

        out.size = size->asInt();
        if (ValidateDigest(out.digest) != SBOX_OK) {
            return -EINVAL;
        }

        const CJson* urls = json.find("urls");
        if (urls) {
            out.urls = urls->asStrings();
        }

        readPairs(json.find("annotations"), out.annotations);
        const CJson* platform = json.find("platform");
        if (platform && platform->isObject()) {
            out.platform = SPlatform::fromJson(*platform);
            out.hasPlatform = true;
        }

        return SBOX_OK;
    }

    /* Writes a descriptor. */
    CJson SDescriptor::toJson() const {
        CJson o = CJson::object();
        o.set("mediaType", mediaType);
        o.set("digest", digest);
        o.set("size", size);
        if (!urls.empty()) {
            o.set("urls", CJson::fromStrings(urls));
        }

        if (!annotations.empty()) {
            o.set("annotations", writePairs(annotations));
        }

        if (hasPlatform) {
            o.set("platform", platform.toJson());
        }

        if (!artifactType.empty()) {
            o.set("artifactType", artifactType);
        }

        return o;
    }

    /* Returns an annotation value. */
    std::string SDescriptor::annotation(std::string_view key) const {
        for (const auto& [k, v] : annotations) {
            if (k == key) {
                return v;
            }
        }

        return std::string();
    }

    /* Sets or removes an annotation. */
    void SDescriptor::annotation(std::string_view key, std::string_view value) {
        for (size_t i = 0; i < annotations.size(); ++i) {
            if (annotations[i].first == key) {
                if (value.empty()) {
                    annotations.erase(annotations.begin() + ptrdiff_t(i));
                } else {
                    annotations[i].second = std::string(value);
                }

                return;
            }
        }

        if (!value.empty()) {
            annotations.emplace_back(std::string(key), std::string(value));
        }
    }

    /* Reads a manifest. */
    int32_t SManifest::fromJson(const CJson& json, SManifest& out) {
        out = SManifest();
        if (!json.isObject()) {
            return -EINVAL;
        }

        out.schemaVersion = int32_t(json.get("schemaVersion").asInt(0));
        out.mediaType = str(json, "mediaType");
        out.artifactType = str(json, "artifactType");
        if (out.schemaVersion != 2) {
            return -EINVAL;
        }

        const CJson* config = json.find("config");
        if (!config || SDescriptor::fromJson(*config, out.config) != SBOX_OK) {
            return -EINVAL;
        }

        const CJson* layers = json.find("layers");
        if (layers) {
            if (!layers->isArray()) {
                return -EINVAL;
            }

            for (size_t i = 0; i < layers->size(); ++i) {
                SDescriptor d;
                if (SDescriptor::fromJson(layers->at(i), d) != SBOX_OK) {
                    return -EINVAL;
                }

                out.layers.push_back(std::move(d));
            }
        }

        readPairs(json.find("annotations"), out.annotations);
        return SBOX_OK;
    }

    /* Writes a manifest. */
    CJson SManifest::toJson() const {
        CJson o = CJson::object();
        o.set("schemaVersion", schemaVersion);
        if (!mediaType.empty()) {
            o.set("mediaType", mediaType);
        }

        if (!artifactType.empty()) {
            o.set("artifactType", artifactType);
        }

        o.set("config", config.toJson());
        CJson l = CJson::array();
        for (const SDescriptor& d : layers) {
            l.push(d.toJson());
        }

        o.set("layers", std::move(l));
        if (!annotations.empty()) {
            o.set("annotations", writePairs(annotations));
        }

        return o;
    }

    /* Reads an index. */
    int32_t SIndex::fromJson(const CJson& json, SIndex& out) {
        out = SIndex();
        if (!json.isObject()) {
            return -EINVAL;
        }

        out.schemaVersion = int32_t(json.get("schemaVersion").asInt(0));
        out.mediaType = str(json, "mediaType");
        if (out.schemaVersion != 2) {
            return -EINVAL;
        }

        const CJson* manifests = json.find("manifests");
        if (!manifests || !manifests->isArray()) {
            return -EINVAL;
        }

        for (size_t i = 0; i < manifests->size(); ++i) {
            SDescriptor d;
            if (SDescriptor::fromJson(manifests->at(i), d) != SBOX_OK) {
                return -EINVAL;
            }

            out.manifests.push_back(std::move(d));
        }

        readPairs(json.find("annotations"), out.annotations);
        return SBOX_OK;
    }

    /* Writes an index. */
    CJson SIndex::toJson() const {
        CJson o = CJson::object();
        o.set("schemaVersion", schemaVersion);
        if (!mediaType.empty()) {
            o.set("mediaType", mediaType);
        }

        CJson m = CJson::array();
        for (const SDescriptor& d : manifests) {
            m.push(d.toJson());
        }

        o.set("manifests", std::move(m));
        if (!annotations.empty()) {
            o.set("annotations", writePairs(annotations));
        }

        return o;
    }

    /* Picks the best manifest for a platform. */
    int32_t SIndex::select(const SPlatform& want) const {
        int32_t best = -ENOENT;
        int32_t bestScore = 0;
        for (size_t i = 0; i < manifests.size(); ++i) {
            const SDescriptor& d = manifests[i];
            if (!d.hasPlatform || (!d.mediaType.empty() && !IsManifestMediaType(d.mediaType) && !IsIndexMediaType(d.mediaType))) {
                continue;
            }

            // --> BuildKit attestation manifests carry "unknown/unknown".
            if (d.platform.os == "unknown" || d.annotation("vnd.docker.reference.type") == "attestation-manifest") {
                continue;
            }

            int32_t s = PlatformScore(want, d.platform);
            if (s > bestScore) {
                bestScore = s;
                best = int32_t(i);
            }
        }

        return best;
    }

    /* Classifies a manifest document. */
    EManifestKind ClassifyManifest(const CJson& json, std::string_view contentType) {
        if (!json.isObject()) {
            return EMK_INVALID;
        }

        if (json.get("schemaVersion").asInt(0) == 1) {
            return EMK_SCHEMA1;
        }

        std::string mt = str(json, "mediaType");
        if (!mt.empty()) {
            if (IsSchema1MediaType(mt)) {
                return EMK_SCHEMA1;
            }

            if (IsIndexMediaType(mt)) {
                return EMK_INDEX;
            }

            if (IsManifestMediaType(mt)) {
                return EMK_MANIFEST;
            }
        }

        // --> Untyped documents (allowed by OCI): the structure decides, then the Content-Type.
        if (json.find("manifests")) {
            return EMK_INDEX;
        }

        if (json.find("config") && json.find("layers")) {
            return EMK_MANIFEST;
        }

        size_t semi = contentType.find(';');
        std::string ct(contentType.substr(0, semi));
        while (!ct.empty() && (ct.back() == ' ' || ct.back() == '\t')) {
            ct.pop_back();
        }

        if (IsSchema1MediaType(ct)) {
            return EMK_SCHEMA1;
        }

        return EMK_INVALID;
    }

    /* Reads an image configuration. */
    int32_t SImageConfig::fromJson(const CJson& json, SImageConfig& out) {
        out = SImageConfig();
        if (!json.isObject()) {
            return -EINVAL;
        }

        out.raw = json;
        out.architecture = str(json, "architecture");
        out.os = str(json, "os");
        out.variant = str(json, "variant");
        out.created = str(json, "created");
        out.author = str(json, "author");
        const CJson* rootfs = json.find("rootfs");
        if (rootfs) {
            const CJson* ids = rootfs->find("diff_ids");
            if (ids) {
                if (!ids->isArray()) {
                    return -EINVAL;
                }

                for (size_t i = 0; i < ids->size(); ++i) {
                    if (!ids->at(i).isString() || ValidateDigest(ids->at(i).asString()) != SBOX_OK) {
                        return -EINVAL;
                    }

                    out.diffIds.push_back(ids->at(i).asString());
                }
            }
        }

        const CJson* c = json.find("config");
        if (c && c->isObject()) {
            out.user = str(*c, "User");
            out.workingDir = str(*c, "WorkingDir");
            out.stopSignal = str(*c, "StopSignal");
            out.env = c->get("Env").asStrings();
            out.entrypoint = c->get("Entrypoint").asStrings();
            out.cmd = c->get("Cmd").asStrings();
            out.exposedPorts = readKeys(c->find("ExposedPorts"));
            out.volumes = readKeys(c->find("Volumes"));
            readPairs(c->find("Labels"), out.labels);
            out.argsEscaped = c->get("ArgsEscaped").asBool(false);
        }

        return SBOX_OK;
    }

    /* Writes an image configuration. */
    CJson SImageConfig::toJson() const {
        CJson o = raw.isObject() ? raw : CJson::object();
        o.set("architecture", architecture);
        o.set("os", os);
        setOrRemove(o, "variant", variant);
        setOrRemove(o, "created", created);
        setOrRemove(o, "author", author);

        CJson c = o.get("config").isObject() ? o.get("config") : CJson::object();
        setOrRemove(c, "User", user);
        setOrRemove(c, "WorkingDir", workingDir);
        setOrRemove(c, "StopSignal", stopSignal);
        if (env.empty()) {
            c.remove("Env");
        } else {
            c.set("Env", CJson::fromStrings(env));
        }

        if (entrypoint.empty()) {
            c.remove("Entrypoint");
        } else {
            c.set("Entrypoint", CJson::fromStrings(entrypoint));
        }

        if (cmd.empty()) {
            c.remove("Cmd");
        } else {
            c.set("Cmd", CJson::fromStrings(cmd));
        }

        if (exposedPorts.empty()) {
            c.remove("ExposedPorts");
        } else {
            c.set("ExposedPorts", writeKeys(exposedPorts));
        }

        if (volumes.empty()) {
            c.remove("Volumes");
        } else {
            c.set("Volumes", writeKeys(volumes));
        }

        if (labels.empty()) {
            c.remove("Labels");
        } else {
            c.set("Labels", writePairs(labels));
        }

        if (argsEscaped) {
            c.set("ArgsEscaped", true);
        } else {
            c.remove("ArgsEscaped");
        }

        o.set("config", std::move(c));
        CJson rootfs = CJson::object();
        rootfs.set("type", "layers");
        rootfs.set("diff_ids", CJson::fromStrings(diffIds));
        o.set("rootfs", std::move(rootfs));
        return o;
    }

    /* Returns the platform recorded in the config. */
    SPlatform SImageConfig::platform() const {
        SPlatform p;
        p.os = os;
        p.architecture = architecture;
        p.variant = variant;
        return p;
    }

    /* Returns a label value. */
    std::string SImageConfig::label(std::string_view key) const {
        for (const auto& [k, v] : labels) {
            if (k == key) {
                return v;
            }
        }

        return std::string();
    }

    /* Returns the current time in RFC 3339 form. */
    std::string NowRfc3339() {
        struct timespec ts{};
        ::clock_gettime(CLOCK_REALTIME, &ts);
        struct tm tm{};
        ::gmtime_r(&ts.tv_sec, &tm);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ", tm.tm_year + 1900, tm.tm_mon + 1,
                      tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, long(ts.tv_nsec));
        return buf;
    }

}
}
