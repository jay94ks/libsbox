// sbox-image: image management for libsbox (pull, push, images, inspect, tag, rmi, save, load,
// bundle, mount/umount, commit, prune) over an OCI image layout store. `bundle` can also attach
// volumes (vol module) and a network (net module) to the container; see attach.hpp.
#include <sbox/core/eventloop.hpp>
#include <sbox/core/fd.hpp>
#include <sbox/core/file.hpp>
#include <sbox/core/json.hpp>
#include <sbox/http/proxy.hpp>
#include <sbox/image/gc.hpp>
#include <sbox/image/registry.hpp>
#include <sbox/image/runtime.hpp>
#include <sbox/image/snapshot.hpp>
#include <sbox/image/store.hpp>
#include <sbox/image/transfer.hpp>
#include <sbox/archive/stream.hpp>
#include "attach.hpp"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <string>
#include <unistd.h>
#include <vector>

using namespace sbox;
using namespace sbox::image;

namespace {

    const char* const USAGE =
        "usage: sbox-image [global options] <command> [arguments]\n"
        "\n"
        "Global options:\n"
        "  --root DIR                 store root (default: /var/lib/sbox/image, rootless: $XDG_DATA_HOME/sbox/image)\n"
        "  --json                     machine-readable output\n"
        "  --platform OS/ARCH[/VAR]   platform to pull or load (default: this machine)\n"
        "  --registry-mirror URL      mirror for Docker Hub (or DOMAIN=URL for another registry); repeatable\n"
        "  --insecure-registry HOST   HTTPS without verification, then plain HTTP; repeatable\n"
        "  --plain-http HOST          plain HTTP only; repeatable\n"
        "  --certs-dir DIR            per-registry certificates (default: /etc/docker/certs.d)\n"
        "  --docker-config FILE       credentials file (default: ~/.docker/config.json)\n"
        "  --snapshotter MODE         overlay, copy or auto (default)\n"
        "  -q, --quiet                no progress output\n"
        "\n"
        "Commands:\n"
        "  pull [--no-unpack] IMAGE\n"
        "  push [--chunk-size N] IMAGE [TARGET]\n"
        "  images|ls [-a] [--digests]\n"
        "  inspect IMAGE...\n"
        "  tag SOURCE TARGET\n"
        "  rmi [-f] IMAGE...\n"
        "  save [-o FILE] [--format docker|oci] IMAGE...\n"
        "  load [-i FILE] [--name NAME]\n"
        "  bundle [options] IMAGE DIR [-- ARGS...]\n"
        "      --user U --hostname H --entrypoint CMD --env K=V --cap-add C --cap-drop C\n"
        "      --tty --read-only --rootless --no-seccomp\n"
        "      -v, --volume [SRC:]DST[:OPTS]  named/anonymous volume or host bind (docker run -v)\n"
        "      --mount type=volume|bind|tmpfs,...  (docker run --mount)\n"
        "      --tmpfs DST[:OPTS]             private tmpfs\n"
        "      --volume-root DIR              volume store (default: /var/lib/sbox/volumes)\n"
        "      --network NAME                 connect a new network namespace to a network\n"
        "      -p, --publish [IP:]HOST:CTR[/PROTO]  port mapping (with --network; HOST 0 = ephemeral)\n"
        "      --netns PATH                   join an existing network namespace instead\n"
        "      --net-state-dir DIR            network state (default: /var/lib/sbox/net)\n"
        "      --netns-dir DIR                where the namespace is pinned (default: /var/run/netns)\n"
        "  mount [--id ID] IMAGE [TARGET]   prepare a container root and mount it\n"
        "  umount ID\n"
        "  rm [-v] ID                       unmount and delete a container root, disconnect its network,\n"
        "                                   release its volumes (-v: remove its anonymous volumes)\n"
        "  ps                               list container roots\n"
        "  commit [--author A] [--message M] ID [IMAGE]\n"
        "  prune [-a] [--dry-run]\n"
        "  tags REPOSITORY                  list the tags of a remote repository\n"
        "  snapshots                        list unpacked layers\n";

    /*
     * Global settings from the command line.
     */
    struct Globals {
        std::string root;
        bool json = false;
        bool quiet = false;
        ESnapshotMode mode = ESNAP_AUTO;
        SRegistryOptions registry;
    };

    /* Prints an error and returns the exit code. */
    int fail(const std::string& message) {
        std::fprintf(stderr, "sbox-image: %s\n", message.c_str());
        return 1;
    }

    /* Formats an errno with a message. */
    std::string why(int32_t r, const std::string& detail) {
        return detail.empty() ? std::string(std::strerror(-r)) : detail;
    }

    /* Returns the short image ID (12 hex characters). */
    std::string shortId(const std::string& digest) {
        return std::string(DigestHex(digest)).substr(0, 12);
    }

    /* Prints JSON to stdout. */
    void printJson(const CJson& j) {
        std::string s = j.dump(true);
        std::fwrite(s.data(), 1, s.size(), stdout);
        std::fputc('\n', stdout);
    }

    /* Formats a byte count like Docker ("2.81MB"). */
    std::string humanSize(uint64_t bytes) {
        const char* units[] = { "B", "kB", "MB", "GB", "TB" };
        double v = double(bytes);
        int u = 0;
        while (v >= 1000.0 && u < 4) {
            v /= 1000.0;
            ++u;
        }

        char buf[32];
        std::snprintf(buf, sizeof(buf), u == 0 ? "%.0f%s" : "%.3g%s", v, units[u]);
        return buf;
    }

    /* Prints progress like `docker pull`, one line per state change. */
    FImageProgress progressPrinter(bool quiet) {
        if (quiet) {
            return nullptr;
        }

        auto lastPhase = std::make_shared<std::map<std::string, int32_t>>();
        return [lastPhase](const SProgress& p) {
            const char* text = nullptr;
            switch (p.phase) {
            case EPP_EXISTS: text = "Already exists"; break;
            case EPP_WAITING: text = "Waiting"; break;
            case EPP_DOWNLOADING: text = "Downloading"; break;
            case EPP_RETRYING: text = "Retrying"; break;
            case EPP_VERIFIED: text = "Download complete"; break;
            case EPP_EXTRACTING: text = "Extracting"; break;
            case EPP_EXTRACTED: text = "Pull complete"; break;
            case EPP_UPLOADING: text = "Pushing"; break;
            case EPP_MOUNTED: text = "Mounted from"; break;
            case EPP_PUSHED: text = "Pushed"; break;
            default: break;
            }

            if (!text || p.digest.empty()) {
                return;
            }

            int32_t& last = (*lastPhase)[p.digest];
            if (last == int32_t(p.phase) + 1) {
                return;
            }

            last = int32_t(p.phase) + 1;
            std::string extra;
            if (p.phase == EPP_DOWNLOADING || p.phase == EPP_UPLOADING) {
                extra = " " + humanSize(p.total);
            } else if (!p.message.empty() && (p.phase == EPP_RETRYING || p.phase == EPP_MOUNTED)) {
                extra = " " + p.message;
            }

            std::fprintf(stderr, "%s: %s%s\n", shortId(p.digest).c_str(), text, extra.c_str());
        };
    }

    /* Opens the store. */
    int32_t openStore(const Globals& g, CContentStorePtr& store) {
        int32_t r = CContentStore::open(g.root, store);
        if (r != SBOX_OK) {
            fail("cannot open the image store at " + g.root + ": " + std::strerror(-r));
        }

        return r;
    }

    /* Returns the repository and tag columns of a full reference. */
    void splitName(const std::string& full, std::string& repo, std::string& tag) {
        SReference ref;
        if (SReference::parse(full, ref) != SBOX_OK) {
            repo = full;
            tag = "<none>";
            return;
        }

        repo = ref.familiarName();
        tag = ref.hasTag() ? ref.tag : "<none>";
    }

    /* Builds the `docker inspect`-like JSON of an image. */
    CJson inspectJson(const SImageInfo& i) {
        CJson j = CJson::object();
        j.set("Id", i.id);
        CJson tags = CJson::array();
        for (const std::string& t : i.repoTags) {
            SReference r;
            tags.push(SReference::parse(t, r) == SBOX_OK ? r.familiarString() : t);
        }

        CJson digests = CJson::array();
        for (const std::string& t : i.repoDigests) {
            SReference r;
            digests.push(SReference::parse(t, r) == SBOX_OK ? r.familiarString() : t);
        }

        j.set("RepoTags", std::move(tags));
        j.set("RepoDigests", std::move(digests));
        j.set("Created", i.config.created);
        j.set("Author", i.config.author);
        j.set("Architecture", i.config.architecture);
        if (!i.config.variant.empty()) {
            j.set("Variant", i.config.variant);
        }

        j.set("Os", i.config.os);
        j.set("Size", i.size);
        j.set("Config", i.config.raw.get("config"));
        CJson rootfs = CJson::object();
        rootfs.set("Type", "layers");
        rootfs.set("Layers", CJson::fromStrings(i.config.diffIds));
        j.set("RootFS", std::move(rootfs));
        CJson desc = i.manifestDescriptor.toJson();
        j.set("Descriptor", std::move(desc));
        return j;
    }

    /* Consumes "--name value" style options; returns false when `arg` is not `name`. */
    bool takeValue(const std::vector<std::string>& args, size_t& i, const char* name, std::string& out) {
        std::string a = args[i];
        std::string n = name;
        if (a == n && i + 1 < args.size()) {
            out = args[++i];
            return true;
        }

        if (a.compare(0, n.size() + 1, n + "=") == 0) {
            out = a.substr(n.size() + 1);
            return true;
        }

        return false;
    }

    /* pull */
    int cmdPull(Globals& g, const std::vector<std::string>& args) {
        std::string image;
        for (size_t i = 0; i < args.size(); ++i) {
            if (args[i] == "--no-unpack") {
                g.registry.unpack = false;
            } else if (image.empty() && args[i][0] != '-') {
                image = args[i];
            } else {
                return fail("pull: unexpected argument " + args[i]);
            }
        }

        if (image.empty()) {
            return fail("pull: an image is required");
        }

        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        g.registry.progress = progressPrinter(g.quiet || g.json);
        CRegistryClient client(g.registry);
        SPullResult res;
        CEventLoop loop;
        int32_t r = loop.run(client.pull(*store, image, res));
        if (r != SBOX_OK) {
            return fail(why(r, client.lastError()));
        }

        if (g.json) {
            CJson j = CJson::object();
            j.set("Reference", res.reference);
            j.set("Digest", res.resolvedDigest);
            j.set("Manifest", res.manifestDigest);
            j.set("Id", res.imageId);
            j.set("Downloaded", int64_t(res.downloadedBytes));
            j.set("Source", res.endpoint);
            printJson(j);
        } else {
            SReference ref;
            SReference::parse(res.reference, ref);
            std::printf("Digest: %s\n", res.resolvedDigest.c_str());
            std::printf("Status: %s for %s\n", res.downloadedBytes ? "Downloaded newer image" : "Image is up to date",
                        ref.familiarString().c_str());
            std::printf("%s\n", res.reference.c_str());
        }

        return 0;
    }

    /* push */
    int cmdPush(Globals& g, const std::vector<std::string>& args) {
        std::vector<std::string> pos;
        for (size_t i = 0; i < args.size(); ++i) {
            std::string v;
            if (takeValue(args, i, "--chunk-size", v)) {
                g.registry.uploadChunkSize = std::strtoll(v.c_str(), nullptr, 10);
            } else {
                pos.push_back(args[i]);
            }
        }

        if (pos.empty() || pos.size() > 2) {
            return fail("push: usage: push IMAGE [TARGET]");
        }

        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        g.registry.progress = progressPrinter(g.quiet || g.json);
        CRegistryClient client(g.registry);
        SPushResult res;
        CEventLoop loop;
        int32_t r = loop.run(client.push(*store, pos[0], pos.size() > 1 ? pos[1] : std::string(), res));
        if (r != SBOX_OK) {
            return fail(why(r, client.lastError()));
        }

        if (g.json) {
            CJson j = CJson::object();
            j.set("Reference", res.reference);
            j.set("Digest", res.manifestDigest);
            j.set("Uploaded", int64_t(res.uploadedBytes));
            j.set("BlobsUploaded", res.blobsUploaded);
            j.set("BlobsMounted", res.blobsMounted);
            j.set("BlobsExisting", res.blobsExisting);
            printJson(j);
        } else {
            std::printf("%s: digest: %s\n", res.reference.c_str(), res.manifestDigest.c_str());
        }

        return 0;
    }

    /* images */
    int cmdImages(Globals& g, const std::vector<std::string>& args) {
        bool digests = false;
        bool all = false;
        for (const std::string& a : args) {
            if (a == "--digests") {
                digests = true;
            } else if (a == "-a" || a == "--all") {
                all = true;
            } else {
                return fail("images: unexpected argument " + a);
            }
        }

        (void)all;
        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        std::vector<SImageInfo> images;
        int32_t r = store->listImages(images);
        if (r != SBOX_OK) {
            return fail(std::string("cannot read index.json: ") + std::strerror(-r));
        }

        if (g.json) {
            CJson arr = CJson::array();
            for (const SImageInfo& i : images) {
                arr.push(inspectJson(i));
            }

            printJson(arr);
            return 0;
        }

        std::printf("%-40s %-16s %s%-14s %-22s %s\n", "REPOSITORY", "TAG", digests ? "DIGEST                                                                   " : "",
                    "IMAGE ID", "CREATED", "SIZE");
        for (const SImageInfo& i : images) {
            std::vector<std::string> names = i.repoTags;
            if (names.empty()) {
                names.push_back(std::string());
            }

            for (const std::string& n : names) {
                std::string repo = "<none>";
                std::string tag = "<none>";
                if (!n.empty()) {
                    splitName(n, repo, tag);
                }

                std::string digest;
                if (digests) {
                    for (const std::string& d : i.repoDigests) {
                        SReference dr;
                        SReference tr;
                        if (SReference::parse(d, dr) == SBOX_OK && (n.empty() || (SReference::parse(n, tr) == SBOX_OK && tr.name() == dr.name()))) {
                            digest = dr.digest;
                        }
                    }

                    if (digest.empty()) {
                        digest = "<none>";
                    }

                    digest.resize(std::max<size_t>(digest.size(), 72), ' ');
                    digest += " ";
                }

                std::string created = i.config.created.substr(0, 19);
                std::printf("%-40s %-16s %s%-14s %-22s %s\n", repo.c_str(), tag.c_str(), digest.c_str(), shortId(i.id).c_str(),
                            created.c_str(), humanSize(uint64_t(i.size)).c_str());
            }
        }

        return 0;
    }

    /* inspect */
    int cmdInspect(Globals& g, const std::vector<std::string>& args) {
        if (args.empty()) {
            return fail("inspect: an image is required");
        }

        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        CJson arr = CJson::array();
        int rc = 0;
        for (const std::string& a : args) {
            SImageInfo info;
            int32_t r = store->resolve(a, info);
            if (r != SBOX_OK) {
                rc = fail("no such image: " + a);
                continue;
            }

            arr.push(inspectJson(info));
        }

        printJson(arr);
        return rc;
    }

    /* tag */
    int cmdTag(Globals& g, const std::vector<std::string>& args) {
        if (args.size() != 2) {
            return fail("tag: usage: tag SOURCE TARGET");
        }

        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        SImageInfo info;
        if (store->resolve(args[0], info) != SBOX_OK) {
            return fail("no such image: " + args[0]);
        }

        SReference ref;
        if (ParseDockerReference(args[1], ref) != SBOX_OK || ref.hasDigest()) {
            return fail("invalid reference format: " + args[1]);
        }

        int32_t r = store->setRecord(ref.toString(), info.manifestDescriptor);
        return r == SBOX_OK ? 0 : fail(std::string("tag: ") + std::strerror(-r));
    }

    /* rmi */
    int cmdRmi(Globals& g, const std::vector<std::string>& args) {
        bool force = false;
        std::vector<std::string> images;
        for (const std::string& a : args) {
            if (a == "-f" || a == "--force") {
                force = true;
            } else {
                images.push_back(a);
            }
        }

        if (images.empty()) {
            return fail("rmi: an image is required");
        }

        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        int rc = 0;
        CJson out = CJson::array();
        for (const std::string& img : images) {
            SRemoveResult res;
            std::string error;
            int32_t r = RemoveImage(*store, img, force, res, &error);
            if (r != SBOX_OK) {
                rc = fail(why(r, error));
                continue;
            }

            for (const std::string& u : res.untagged) {
                SReference ref;
                std::string shown = SReference::parse(u, ref) == SBOX_OK ? ref.familiarString() : u;
                if (g.json) {
                    CJson e = CJson::object();
                    e.set("Untagged", shown);
                    out.push(std::move(e));
                } else {
                    std::printf("Untagged: %s\n", shown.c_str());
                }
            }

            for (const std::string& d : res.deleted) {
                if (g.json) {
                    CJson e = CJson::object();
                    e.set("Deleted", d);
                    out.push(std::move(e));
                } else {
                    std::printf("Deleted: %s\n", d.c_str());
                }
            }
        }

        if (g.json) {
            printJson(out);
        }

        return rc;
    }

    /* save */
    int cmdSave(Globals& g, const std::vector<std::string>& args) {
        std::string output;
        std::string format = "docker";
        std::vector<std::string> images;
        for (size_t i = 0; i < args.size(); ++i) {
            std::string v;
            if (takeValue(args, i, "-o", v) || takeValue(args, i, "--output", v)) {
                output = v;
            } else if (takeValue(args, i, "--format", v)) {
                format = v;
            } else {
                images.push_back(args[i]);
            }
        }

        if (images.empty()) {
            return fail("save: an image is required");
        }

        if (format != "docker" && format != "oci") {
            return fail("save: --format must be docker or oci");
        }

        if (output.empty() && ::isatty(STDOUT_FILENO)) {
            return fail("save: refusing to write an archive to a terminal; use -o FILE or redirect stdout");
        }

        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        CFd fd(output.empty() ? ::dup(STDOUT_FILENO) : ::open(output.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
        if (!fd.isValid()) {
            return fail("cannot open " + output + ": " + std::strerror(errno));
        }

        archive::CFdSink sink(fd.get());
        std::string error;
        int32_t r = format == "oci" ? SaveOciArchive(*store, images, sink, &error) : SaveDockerArchive(*store, images, sink, &error);
        if (r != SBOX_OK) {
            if (!output.empty()) {
                ::unlink(output.c_str());
            }

            return fail(why(r, error));
        }

        return 0;
    }

    /* load */
    int cmdLoad(Globals& g, const std::vector<std::string>& args) {
        std::string input;
        SLoadOptions lo;
        lo.platform = g.registry.platform;
        for (size_t i = 0; i < args.size(); ++i) {
            std::string v;
            if (takeValue(args, i, "-i", v) || takeValue(args, i, "--input", v)) {
                input = v;
            } else if (takeValue(args, i, "--name", v)) {
                lo.name = v;
            } else {
                return fail("load: unexpected argument " + args[i]);
            }
        }

        if (input.empty() && ::isatty(STDIN_FILENO)) {
            return fail("load: requested load from stdin, but stdin is a terminal; use -i FILE");
        }

        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        CFd fd(input.empty() ? ::dup(STDIN_FILENO) : ::open(input.c_str(), O_RDONLY | O_CLOEXEC));
        if (!fd.isValid()) {
            return fail("cannot open " + input + ": " + std::strerror(errno));
        }

        archive::CFdSource src(fd.get());
        SLoadResult res;
        std::string error;
        int32_t r = LoadImageArchive(*store, src, lo, res, &error);
        if (r != SBOX_OK) {
            return fail(why(r, error));
        }

        if (g.json) {
            CJson j = CJson::object();
            j.set("Format", res.format);
            j.set("Tags", CJson::fromStrings(res.tags));
            j.set("Ids", CJson::fromStrings(res.imageIds));
            printJson(j);
            return 0;
        }

        for (const std::string& t : res.tags) {
            SReference ref;
            std::printf("Loaded image: %s\n", SReference::parse(t, ref) == SBOX_OK ? ref.familiarString().c_str() : t.c_str());
        }

        if (res.tags.empty()) {
            for (const std::string& id : res.imageIds) {
                std::printf("Loaded image ID: %s\n", id.c_str());
            }
        }

        return 0;
    }

    /* Resolves an image, unpacking it (helper for bundle/mount). */
    int32_t resolveImage(CContentStore& store, const std::string& name, SImageInfo& info) {
        int32_t r = store.resolve(name, info);
        if (r != SBOX_OK) {
            fail("no such image: " + name + " (pull it first)");
        }

        return r;
    }

    /* bundle */
    int cmdBundle(Globals& g, const std::vector<std::string>& args) {
        SBundleOptions o;
        imagecli::AttachRequest attach;
        std::vector<std::string> pos;
        size_t i = 0;
        for (; i < args.size(); ++i) {
            std::string v;
            if (args[i] == "--") {
                ++i;
                break;
            }

            std::string attachError;
            int32_t consumed = imagecli::ParseAttachOption(args, i, attach, attachError);
            if (consumed < 0) {
                return fail("bundle: " + attachError);
            }

            if (consumed > 0) {
                continue;
            }

            if (takeValue(args, i, "--user", v) || takeValue(args, i, "-u", v)) {
                o.user = v;
            } else if (takeValue(args, i, "--hostname", v)) {
                o.hostname = v;
            } else if (takeValue(args, i, "--entrypoint", v)) {
                o.hasEntrypoint = true;
                o.entrypoint = v.empty() ? std::vector<std::string>() : std::vector<std::string>{ v };
            } else if (takeValue(args, i, "--env", v) || takeValue(args, i, "-e", v)) {
                o.env.push_back(v);
            } else if (takeValue(args, i, "--cap-add", v)) {
                o.capAdd.push_back(v);
            } else if (takeValue(args, i, "--cap-drop", v)) {
                o.capDrop.push_back(v);
            } else if (takeValue(args, i, "--workdir", v) || takeValue(args, i, "-w", v)) {
                o.workingDir = v;
            } else if (args[i] == "--tty" || args[i] == "-t") {
                o.terminal = true;
            } else if (args[i] == "--read-only") {
                o.readOnlyRoot = true;
            } else if (args[i] == "--rootless") {
                o.rootless = true;
            } else if (args[i] == "--no-seccomp") {
                o.seccomp = false;
            } else if (args[i] == "--no-new-privileges") {
                o.noNewPrivileges = true;
            } else if (!args[i].empty() && args[i][0] == '-') {
                return fail("bundle: unknown option " + args[i]);
            } else {
                pos.push_back(args[i]);
            }
        }

        for (; i < args.size(); ++i) {
            o.args.push_back(args[i]);
        }

        if (pos.size() != 2) {
            return fail("bundle: usage: bundle [options] IMAGE DIR [-- ARGS...]");
        }

        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        SImageInfo info;
        if (resolveImage(*store, pos[0], info) != SBOX_OK) {
            return 1;
        }

        SSnapshotterOptions so;
        so.progress = progressPrinter(g.quiet || g.json);
        CSnapshotter snap(store, so);
        if (snap.rootless()) {
            o.rootless = true;
        }

        std::string id;
        std::string error;
        int32_t r = CreateBundle(snap, info, pos[1], o, g.mode, &id, &error);
        if (r != SBOX_OK) {
            return fail(why(r, error));
        }

        SContainerInfo c;
        snap.container(id, c);

        // --> Volumes and network after the root exists (copy-up reads the image content from
        // it); a failure removes the half-made bundle so the command can simply be retried.
        imagecli::AttachRecord record;
        if (!attach.empty()) {
            std::string attachError;
            CEventLoop loop;
            r = loop.run(imagecli::AttachContainer(attach, id, pos[1], c.rootfs, record, attachError));
            if (r == SBOX_OK && (r = imagecli::SaveAttachRecord(g.root, record)) != SBOX_OK) {
                attachError = std::string("cannot write the attachment record: ") + std::strerror(-r);
                std::string ignored;
                loop.run(imagecli::DetachContainer(record, true, ignored));
            }

            if (r != SBOX_OK) {
                snap.remove(id);
                ::unlink(CFile::join(pos[1], "config.json").c_str());
                return fail("bundle: " + attachError);
            }
        }

        if (g.json) {
            CJson j = CJson::object();
            j.set("Id", id);
            j.set("Bundle", pos[1]);
            j.set("Rootfs", c.rootfs);
            j.set("Snapshotter", SnapshotModeName(c.mode));
            if (!record.volumes.empty()) {
                j.set("Volumes", CJson::fromStrings(record.volumes));
            }

            if (!record.netns.empty() || !attach.netns.empty()) {
                j.set("Netns", record.netns.empty() ? attach.netns : record.netns);
            }

            if (!record.network.empty()) {
                CJson n = CJson::object();
                n.set("Name", record.network);
                n.set("Address", record.address);
                CJson ports = CJson::array();
                for (const net::SPortMapping& m : record.ports) {
                    ports.push(m.toJson());
                }

                n.set("Ports", std::move(ports));
                j.set("Network", std::move(n));
            }

            printJson(j);
        } else {
            std::printf("%s\n", id.c_str());
            if (!record.network.empty() && !g.quiet) {
                for (const net::SPortMapping& m : record.ports) {
                    std::fprintf(stderr, "%s: %s %u/%s -> %s:%u\n", shortId(id).c_str(), record.network.c_str(),
                                 unsigned(m.containerPort), m.protocolName().c_str(),
                                 m.hostIp.isValid() ? m.hostIp.toString().c_str() : "0.0.0.0", unsigned(m.hostPort));
                }
            }
        }

        return 0;
    }

    /* mount */
    int cmdMount(Globals& g, const std::vector<std::string>& args) {
        std::string id;
        std::vector<std::string> pos;
        for (size_t i = 0; i < args.size(); ++i) {
            std::string v;
            if (takeValue(args, i, "--id", v)) {
                id = v;
            } else {
                pos.push_back(args[i]);
            }
        }

        if (pos.empty() || pos.size() > 2) {
            return fail("mount: usage: mount [--id ID] IMAGE [TARGET]");
        }

        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        SImageInfo info;
        if (resolveImage(*store, pos[0], info) != SBOX_OK) {
            return 1;
        }

        SSnapshotterOptions so;
        so.progress = progressPrinter(g.quiet || g.json);
        CSnapshotter snap(store, so);
        SContainerInfo c;
        std::string target = pos.size() > 1 ? pos[1] : std::string();
        if (!target.empty()) {
            CFile::makeDirs(target, 0755);
        }

        int32_t r = snap.prepare(id, info, g.mode, c, true, target);
        if (r != SBOX_OK) {
            return fail(why(r, snap.lastError()));
        }

        if (g.json) {
            CJson j = CJson::object();
            j.set("Id", c.id);
            j.set("Rootfs", c.rootfs);
            j.set("Snapshotter", SnapshotModeName(c.mode));
            printJson(j);
        } else {
            std::printf("%s %s\n", c.id.c_str(), c.rootfs.c_str());
        }

        return 0;
    }

    /* umount / rm */
    int cmdUnmount(Globals& g, const std::vector<std::string>& args, bool remove) {
        bool removeVolumes = false;
        std::vector<std::string> ids;
        for (const std::string& a : args) {
            if (remove && (a == "-v" || a == "--volumes")) {
                removeVolumes = true;
            } else if (!a.empty() && a[0] == '-') {
                return fail(std::string(remove ? "rm" : "umount") + ": unknown option " + a);
            } else {
                ids.push_back(a);
            }
        }

        if (ids.empty()) {
            return fail(std::string(remove ? "rm" : "umount") + ": a container root ID is required");
        }

        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        CSnapshotter snap(store);
        int rc = 0;
        for (const std::string& id : ids) {
            // --> Network and volumes first: they reference the container, not its root.
            bool attached = false;
            if (remove) {
                imagecli::AttachRecord record;
                int32_t lr = imagecli::LoadAttachRecord(g.root, id, record);
                if (lr == SBOX_OK) {
                    attached = true;
                    std::string error;
                    CEventLoop loop;
                    int32_t dr = loop.run(imagecli::DetachContainer(record, removeVolumes, error));
                    if (dr != SBOX_OK) {
                        rc = fail(id + ": " + error);
                        continue;
                    }

                    ::unlink(imagecli::AttachRecordPath(g.root, id).c_str());
                } else if (lr != -ENOENT) {
                    rc = fail(id + ": unreadable attachment record " + imagecli::AttachRecordPath(g.root, id));
                    continue;
                }
            }

            int32_t r = remove ? snap.remove(id) : snap.unmount(id);
            if (r != SBOX_OK && !(attached && r == -ENOENT)) {
                rc = fail(id + ": " + why(r, snap.lastError()));
            }
        }

        return rc;
    }

    /* ps */
    int cmdPs(Globals& g) {
        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        CSnapshotter snap(store);
        std::vector<SContainerInfo> list;
        snap.listContainers(list);
        if (g.json) {
            CJson arr = CJson::array();
            for (const SContainerInfo& c : list) {
                CJson j = CJson::object();
                j.set("Id", c.id);
                j.set("Image", c.imageId);
                j.set("ImageName", c.imageName);
                j.set("Snapshotter", SnapshotModeName(c.mode));
                j.set("Rootfs", c.rootfs);
                j.set("Created", c.created);
                arr.push(std::move(j));
            }

            printJson(arr);
            return 0;
        }

        std::printf("%-34s %-14s %-9s %s\n", "ID", "IMAGE", "MODE", "ROOTFS");
        for (const SContainerInfo& c : list) {
            std::printf("%-34s %-14s %-9s %s\n", c.id.c_str(), shortId(c.imageId).c_str(), SnapshotModeName(c.mode), c.rootfs.c_str());
        }

        return 0;
    }

    /* commit */
    int cmdCommit(Globals& g, const std::vector<std::string>& args) {
        SCommitOptions o;
        std::vector<std::string> pos;
        for (size_t i = 0; i < args.size(); ++i) {
            std::string v;
            if (takeValue(args, i, "--author", v) || takeValue(args, i, "-a", v)) {
                o.author = v;
            } else if (takeValue(args, i, "--message", v) || takeValue(args, i, "-m", v)) {
                o.comment = v;
            } else {
                pos.push_back(args[i]);
            }
        }

        if (pos.empty() || pos.size() > 2) {
            return fail("commit: usage: commit [--author A] [--message M] ID [IMAGE]");
        }

        if (pos.size() > 1) {
            o.reference = pos[1];
        }

        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        CSnapshotter snap(store);
        SImageInfo out;
        int32_t r = snap.commit(pos[0], o, out);
        if (r != SBOX_OK) {
            return fail(why(r, snap.lastError()));
        }

        std::printf("%s\n", out.id.c_str());
        return 0;
    }

    /* prune */
    int cmdPrune(Globals& g, const std::vector<std::string>& args) {
        SGcOptions o;
        o.pruneDangling = true;
        for (const std::string& a : args) {
            if (a == "-a" || a == "--all") {
                o.pruneUnused = true;
            } else if (a == "--dry-run") {
                o.dryRun = true;
            } else {
                return fail("prune: unexpected argument " + a);
            }
        }

        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        SGcResult res;
        int32_t r = CollectGarbage(*store, o, res);
        if (r != SBOX_OK) {
            return fail(std::string("prune: ") + std::strerror(-r));
        }

        if (g.json) {
            CJson j = CJson::object();
            j.set("ImagesDeleted", CJson::fromStrings(res.removedImages));
            j.set("BlobsDeleted", CJson::fromStrings(res.removedBlobs));
            j.set("SnapshotsDeleted", CJson::fromStrings(res.removedSnapshots));
            j.set("SpaceReclaimed", int64_t(res.reclaimedBytes));
            printJson(j);
            return 0;
        }

        for (const std::string& i : res.removedImages) {
            std::printf("Deleted image: %s\n", i.c_str());
        }

        std::printf("%s %zu blobs, %zu snapshots\nTotal reclaimed space: %s\n", o.dryRun ? "Would delete" : "Deleted",
                    res.removedBlobs.size(), res.removedSnapshots.size(), humanSize(res.reclaimedBytes).c_str());
        return 0;
    }

    /* tags */
    int cmdTags(Globals& g, const std::vector<std::string>& args) {
        if (args.size() != 1) {
            return fail("tags: usage: tags REPOSITORY");
        }

        CRegistryClient client(g.registry);
        std::vector<std::string> tags;
        CEventLoop loop;
        int32_t r = loop.run(client.listTags(args[0], tags));
        if (r != SBOX_OK) {
            return fail(why(r, client.lastError()));
        }

        if (g.json) {
            printJson(CJson::fromStrings(tags));
        } else {
            for (const std::string& t : tags) {
                std::printf("%s\n", t.c_str());
            }
        }

        return 0;
    }

    /* snapshots */
    int cmdSnapshots(Globals& g) {
        CContentStorePtr store;
        if (openStore(g, store) != SBOX_OK) {
            return 1;
        }

        CSnapshotter snap(store);
        std::vector<SSnapshotInfo> list;
        snap.listSnapshots(list);
        if (g.json) {
            CJson arr = CJson::array();
            for (const SSnapshotInfo& s : list) {
                CJson j = CJson::object();
                j.set("ChainId", s.chainId);
                j.set("DiffId", s.diffId);
                j.set("Parent", s.parent);
                j.set("Path", s.path);
                j.set("Whiteouts", s.whiteouts);
                j.set("Size", int64_t(s.size));
                arr.push(std::move(j));
            }

            printJson(arr);
            return 0;
        }

        std::printf("%-14s %-14s %-10s %s\n", "CHAIN ID", "PARENT", "SIZE", "PATH");
        for (const SSnapshotInfo& s : list) {
            std::printf("%-14s %-14s %-10s %s\n", shortId(s.chainId).c_str(), s.parent.empty() ? "-" : shortId(s.parent).c_str(),
                        humanSize(s.size).c_str(), s.path.c_str());
        }

        return 0;
    }

}

int main(int argc, char** argv) {
    Globals g;
    g.root = DefaultStoreRoot();
    const char* envRoot = std::getenv("SBOX_IMAGE_ROOT");
    if (envRoot && *envRoot) {
        g.root = envRoot;
    }

    // --> Docker honours HTTPS_PROXY / NO_PROXY for registry traffic; so do we.
    g.registry.proxy = http::SProxyConfig::fromEnvironment();
    std::vector<std::string> args(argv + 1, argv + argc);
    size_t i = 0;
    for (; i < args.size(); ++i) {
        std::string v;
        const std::string& a = args[i];
        if (a == "-h" || a == "--help" || a == "help") {
            std::fputs(USAGE, stdout);
            return 0;
        } else if (takeValue(args, i, "--root", v)) {
            g.root = v;
        } else if (a == "--json") {
            g.json = true;
        } else if (a == "-q" || a == "--quiet") {
            g.quiet = true;
        } else if (takeValue(args, i, "--platform", v)) {
            if (SPlatform::parse(v, g.registry.platform) != SBOX_OK) {
                return fail("invalid platform " + v);
            }
        } else if (takeValue(args, i, "--registry-mirror", v)) {
            g.registry.mirrors.push_back(v);
        } else if (takeValue(args, i, "--insecure-registry", v)) {
            g.registry.insecureRegistries.push_back(v);
        } else if (takeValue(args, i, "--plain-http", v)) {
            g.registry.plainHttpRegistries.push_back(v);
        } else if (takeValue(args, i, "--certs-dir", v)) {
            g.registry.certsDir = v;
        } else if (takeValue(args, i, "--docker-config", v)) {
            g.registry.dockerConfig = v;
        } else if (takeValue(args, i, "--snapshotter", v)) {
            g.mode = ParseSnapshotMode(v);
            if (g.mode == ESNAP_INVALID) {
                return fail("invalid snapshotter " + v);
            }
        } else if (!a.empty() && a[0] == '-') {
            return fail("unknown option " + a + "\n" + USAGE);
        } else {
            break;
        }
    }

    if (i >= args.size()) {
        std::fputs(USAGE, stderr);
        return 2;
    }

    std::string cmd = args[i];
    std::vector<std::string> rest(args.begin() + ptrdiff_t(i) + 1, args.end());
    if (cmd == "pull") return cmdPull(g, rest);
    if (cmd == "push") return cmdPush(g, rest);
    if (cmd == "images" || cmd == "ls" || cmd == "list") return cmdImages(g, rest);
    if (cmd == "inspect") return cmdInspect(g, rest);
    if (cmd == "tag") return cmdTag(g, rest);
    if (cmd == "rmi") return cmdRmi(g, rest);
    if (cmd == "save") return cmdSave(g, rest);
    if (cmd == "load") return cmdLoad(g, rest);
    if (cmd == "bundle") return cmdBundle(g, rest);
    if (cmd == "mount") return cmdMount(g, rest);
    if (cmd == "umount" || cmd == "unmount") return cmdUnmount(g, rest, false);
    if (cmd == "rm") return cmdUnmount(g, rest, true);
    if (cmd == "ps") return cmdPs(g);
    if (cmd == "commit") return cmdCommit(g, rest);
    if (cmd == "prune") return cmdPrune(g, rest);
    if (cmd == "tags") return cmdTags(g, rest);
    if (cmd == "snapshots") return cmdSnapshots(g);
    return fail("unknown command " + cmd + " (see --help)");
}
