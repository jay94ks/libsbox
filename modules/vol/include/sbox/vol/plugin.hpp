#ifndef __INCLUDE_SBOX_VOL_PLUGIN_HPP__
#define __INCLUDE_SBOX_VOL_PLUGIN_HPP__

#include <sbox/common.hpp>
#include <sbox/core/json.hpp>
#include <sbox/core/task.hpp>
#include <sbox/vol/store.hpp>

namespace sbox {
namespace http {
    class CHttpServer;
}
}

namespace sbox {
namespace vol {

    /**
     * Docker volume plugin protocol (VolumeDriver) as a pure request handler over a store.
     *
     * Endpoints (POST, JSON bodies):
     *   /Plugin.Activate             {"Implements":["VolumeDriver"]}
     *   /VolumeDriver.Create         {"Name","Opts"}         -> {"Err":""}
     *   /VolumeDriver.Remove         {"Name"}                -> {"Err":""}
     *   /VolumeDriver.Mount          {"Name","ID"}           -> {"Mountpoint","Err":""}
     *   /VolumeDriver.Unmount        {"Name","ID"}           -> {"Err":""}
     *   /VolumeDriver.Path           {"Name"}                -> {"Mountpoint","Err":""}
     *   /VolumeDriver.Get            {"Name"}                -> {"Volume":{"Name","Mountpoint","CreatedAt","Status"},"Err":""}
     *   /VolumeDriver.List           {}                      -> {"Volumes":[{"Name","Mountpoint","CreatedAt"}],"Err":""}
     *   /VolumeDriver.Capabilities   {}                      -> {"Capabilities":{"Scope":"local"}}
     *
     * Failures are {"Err":"<message>"} answered with HTTP 200, as Docker's plugin protocol
     * expects (Docker reads Err from the body). Unknown paths are reported through isKnownPath
     * so a server can answer 404.
     */
    class SBOX_API CVolumePlugin {
    private:
        CVolumeStore& _store;

    public:
        /**
         * Creates the handler over a store.
         */
        explicit CVolumePlugin(CVolumeStore& store) noexcept : _store(store) {}

        /**
         * Returns the content type of plugin replies ("application/vnd.docker.plugins.v1.2+json").
         */
        static const char* contentType() noexcept;

        /**
         * Returns true for a path this handler implements.
         */
        static bool isKnownPath(std::string_view path) noexcept;

        /**
         * Returns true when a reply carries a non-empty "Err".
         */
        static bool isError(const CJson& reply) noexcept;

        /**
         * Handles one plugin call.
         * @param path Request path ("/VolumeDriver.Create").
         * @param body Decoded JSON body (null or {} for an empty body).
         * @return The reply object.
         */
        TTask<CJson> handle(std::string path, CJson body);

        /**
         * Registers every endpoint on an HTTP server (POST, plugin content type, HTTP 200 for
         * all replies, 404 with Err for unknown paths). Sets the server's jsonContentType.
         */
        void attach(http::CHttpServer& server);
    };

}
}

#endif
