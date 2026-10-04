#ifndef __TESTS_VOL_PLUGINCLIENT_HPP__
#define __TESTS_VOL_PLUGINCLIENT_HPP__

// Docker plugin protocol client used by the plugin and daemon tests: POST JSON over a UNIX socket.

#include <sbox/core/json.hpp>
#include <sbox/http/client.hpp>
#include <string>

namespace testutil {

    using namespace sbox;

    /**
     * Result of one plugin call.
     */
    struct PluginReply {
        int32_t rc = -1;
        int32_t status = 0;
        std::string contentType;
        CJson body;
    };

    /**
     * POSTs `body` to `path` on the plugin socket the way dockerd does.
     */
    inline TTask<PluginReply> pluginCall(http::CHttpClient& client, std::string socket, std::string path, CJson body) {
        PluginReply out;
        http::SRequest req;
        req.method = "POST";
        req.unixSocket = socket;
        if (req.setUrl("http://plugin" + path) != SBOX_OK) {
            co_return out;
        }

        req.setJson(body, "application/vnd.docker.plugins.v1.2+json");
        req.headers.set("Accept", "application/vnd.docker.plugins.v1.2+json");
        http::SResponse res;
        std::string text;
        out.rc = co_await client.fetch(std::move(req), res, text);
        if (out.rc != SBOX_OK) {
            co_return out;
        }

        out.status = res.status;
        out.contentType = res.headers.get("Content-Type");
        if (CJson::parse(text, out.body) != SBOX_OK) {
            out.rc = -EBADMSG;
        }

        co_return out;
    }

    /**
     * Returns {"Name": name} plus an optional extra member.
     */
    inline CJson nameBody(const std::string& name, const char* key = nullptr, CJson value = CJson()) {
        CJson b = CJson::object();
        b.set("Name", CJson(name));
        if (key != nullptr) {
            b.set(key, std::move(value));
        }

        return b;
    }

}

#endif
