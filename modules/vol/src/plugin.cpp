#include <sbox/vol/plugin.hpp>

#include "util.hpp"

#include <sbox/http/server.hpp>
#include <cerrno>

namespace sbox {
namespace vol {

    namespace {

        const char* const PATHS[] = {
            "/Plugin.Activate",
            "/VolumeDriver.Create",
            "/VolumeDriver.Remove",
            "/VolumeDriver.Mount",
            "/VolumeDriver.Unmount",
            "/VolumeDriver.Path",
            "/VolumeDriver.Get",
            "/VolumeDriver.List",
            "/VolumeDriver.Capabilities",
        };

        /* Returns {"Err": message}. */
        CJson errorReply(const std::string& message) {
            CJson out = CJson::object();
            out.set("Err", CJson(message.empty() ? std::string("unknown error") : message));
            return out;
        }

        /* Returns the store's reason for a failure, or a generic one. */
        std::string reasonOf(const CVolumeStore& store, int32_t rc, const std::string& name) {
            if (!store.lastError().empty()) {
                return store.lastError();
            }

            // --> Docker recognizes missing volumes by this wording.
            if (rc == -ENOENT) {
                return "no such volume: " + name;
            }

            return ErrorText(rc);
        }

        /* Returns the "Volume" object of Get/List replies. */
        CJson volumeEntry(const SVolume& v, bool withStatus) {
            CJson out = CJson::object();
            out.set("Name", CJson(v.name));
            out.set("Mountpoint", CJson(v.mountpoint));
            out.set("CreatedAt", CJson(v.createdAt));
            if (withStatus) {
                CJson status = CJson::object();
                status.set("Mounted", CJson(v.mounted));
                status.set("RefCount", CJson(int64_t(v.users.size())));
                status.set("Options", MapToJson(v.options));
                status.set("Labels", MapToJson(v.labels));
                if (v.sizeLimit != 0) {
                    status.set("SizeLimit", CJson(v.sizeLimit));
                }

                out.set("Status", std::move(status));
            }

            return out;
        }

    }

    /* Returns the content type of plugin replies. */
    const char* CVolumePlugin::contentType() noexcept {
        return "application/vnd.docker.plugins.v1.2+json";
    }

    /* Returns true for an implemented path. */
    bool CVolumePlugin::isKnownPath(std::string_view path) noexcept {
        for (const char* p : PATHS) {
            if (path == p) {
                return true;
            }
        }

        return false;
    }

    /* Returns true when a reply carries an error. */
    bool CVolumePlugin::isError(const CJson& reply) noexcept {
        const CJson* err = reply.find("Err");
        return err != nullptr && err->isString() && !err->asString().empty();
    }

    /* Handles one plugin call. */
    TTask<CJson> CVolumePlugin::handle(std::string path, CJson body) {
        if (path == "/Plugin.Activate") {
            std::vector<std::string> implements;
            implements.push_back("VolumeDriver");
            CJson out = CJson::object();
            out.set("Implements", CJson::fromStrings(implements));
            co_return out;
        }

        if (path == "/VolumeDriver.Capabilities") {
            CJson caps = CJson::object();
            caps.set("Scope", CJson("local"));
            CJson out = CJson::object();
            out.set("Capabilities", std::move(caps));
            co_return out;
        }

        CJson ok = CJson::object();
        ok.set("Err", CJson(""));
        std::string name = body.get("Name").asString();

        if (path == "/VolumeDriver.List") {
            std::vector<SVolume> all;
            int32_t rc = _store.list(all);
            if (rc < 0) {
                co_return errorReply(ErrorText(rc));
            }

            CJson list = CJson::array();
            for (const SVolume& v : all) {
                list.push(volumeEntry(v, false));
            }

            CJson out = CJson::object();
            out.set("Volumes", std::move(list));
            out.set("Err", CJson(""));
            co_return out;
        }

        if (!isKnownPath(path)) {
            co_return errorReply("unsupported plugin call " + path);
        }

        if (name.empty()) {
            co_return errorReply("missing volume name");
        }

        if (path == "/VolumeDriver.Create") {
            SVolumeCreate req;
            req.name = name;
            req.options = MapFromJson(body.get("Opts"));
            SVolume v;
            int32_t rc = co_await _store.create(req, v);
            co_return rc < 0 ? errorReply(reasonOf(_store, rc, name)) : ok;
        }

        if (path == "/VolumeDriver.Remove") {
            int32_t rc = co_await _store.remove(name, false);
            co_return rc < 0 ? errorReply(reasonOf(_store, rc, name)) : ok;
        }

        if (path == "/VolumeDriver.Mount" || path == "/VolumeDriver.Unmount") {
            // --> Docker sends a unique ID per mount since API 1.25; older daemons send none.
            std::string id = body.get("ID").asString();
            if (id.empty()) {
                id = "docker";
            }

            if (path == "/VolumeDriver.Unmount") {
                int32_t rc = co_await _store.release(name, id);
                co_return rc < 0 ? errorReply(reasonOf(_store, rc, name)) : ok;
            }

            std::string mountpoint;
            int32_t rc = co_await _store.acquire(name, id, mountpoint);
            if (rc < 0) {
                co_return errorReply(reasonOf(_store, rc, name));
            }

            CJson out = CJson::object();
            out.set("Mountpoint", CJson(mountpoint));
            out.set("Err", CJson(""));
            co_return out;
        }

        SVolume v;
        int32_t rc = _store.inspect(name, v);
        if (rc < 0) {
            co_return errorReply(rc == -ENOENT ? "no such volume: " + name : ErrorText(rc));
        }

        if (path == "/VolumeDriver.Path") {
            CJson out = CJson::object();
            out.set("Mountpoint", CJson(v.mountpoint));
            out.set("Err", CJson(""));
            co_return out;
        }

        CJson out = CJson::object();
        out.set("Volume", volumeEntry(v, true));
        out.set("Err", CJson(""));
        co_return out;
    }

    /* Registers every endpoint on an HTTP server. */
    void CVolumePlugin::attach(http::CHttpServer& server) {
        server.options().jsonContentType = contentType();
        http::THandler handler = [this](http::SServerRequest& req, http::SServerResponse& res) -> TTask<void> {
            CJson body;
            int32_t rc = co_await req.readJson(body);
            if (rc < 0) {
                res.setJson(errorReply("invalid JSON request body"), 200);
                co_return;
            }

            CJson reply = co_await handle(req.path, std::move(body));
            res.setJson(reply, 200);
        };

        for (const char* p : PATHS) {
            server.route("POST", p, handler);
        }

        server.fallback([](http::SServerRequest& req, http::SServerResponse& res) -> TTask<void> {
            res.setJson(errorReply("unsupported plugin call " + req.path), 404);
            co_return;
        });
    }

}
}
