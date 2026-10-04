#ifndef __INCLUDE_SBOX_IMAGE_REGISTRY_HPP__
#define __INCLUDE_SBOX_IMAGE_REGISTRY_HPP__

#include <sbox/core/task.hpp>
#include <sbox/http/client.hpp>
#include <sbox/http/proxy.hpp>
#include <sbox/image/snapshot.hpp>
#include <sbox/image/store.hpp>
#include <sbox/tls/trust.hpp>

namespace sbox {
namespace image {

    /**
     * Credentials for one registry.
     */
    struct SBOX_API SRegistryAuth {
        std::string username;
        std::string password;
        std::string identityToken;      // --> OAuth2 refresh token (docker login with an identity token).
        std::string registryToken;      // --> Bearer token used as is.

        /** Returns true when nothing is set (anonymous). */
        inline bool empty() const noexcept {
            return username.empty() && password.empty() && identityToken.empty() && registryToken.empty();
        }
    };

    /**
     * Returns the Docker client configuration file: $DOCKER_CONFIG/config.json or
     * ~/.docker/config.json.
     */
    SBOX_API std::string DockerConfigPath();

    /**
     * Looks up the credentials of a registry domain in a Docker config.json ("auths" entries:
     * base64 "auth" of user:password, or "username"/"password", "identitytoken",
     * "registrytoken"). Keys may be URLs ("https://index.docker.io/v1/") or host[:port].
     * Credential helpers (credsStore / credHelpers) are not run.
     * @return SBOX_OK, -ENOENT when the file or the entry is missing, -EINVAL when malformed.
     */
    SBOX_API int32_t LoadDockerCredentials(const std::string& configPath, std::string_view domain, SRegistryAuth& out);

    /**
     * Settings of a CRegistryClient.
     */
    struct SBOX_API SRegistryOptions {
        std::vector<std::string> mirrors;               // --> "https://mirror:5000" (Docker Hub, like registry-mirrors)
                                                        //     or "domain=https://mirror" for another registry.
        std::vector<std::string> insecureRegistries;    // --> host[:port]: HTTPS without verification, then plain HTTP.
        std::vector<std::string> plainHttpRegistries;   // --> host[:port]: plain HTTP only.
        std::string certsDir = "/etc/docker/certs.d";  // --> <dir>/<host[:port]>/*.crt CAs, client.cert/client.key.
        std::string dockerConfig;                       // --> config.json for credentials ("" = DockerConfigPath()).
        std::vector<std::pair<std::string, SRegistryAuth>> credentials;    // --> Per domain, before config.json.
        http::SProxyConfig proxy;                       // --> Direct by default; CLI uses SProxyConfig::fromEnvironment().
        tls::CTrustStorePtr trustStore;                 // --> Base trust anchors (null: the system store).
        SPlatform platform;                             // --> Empty: the host platform.
        int32_t maxConcurrentDownloads = 3;
        int32_t maxConcurrentUploads = 5;
        int32_t maxAttempts = 5;                        // --> Per blob, network errors resume with Range.
        int64_t retryDelayMs = 1000;                    // --> Grows linearly with the attempt.
        int64_t uploadChunkSize = 0;                    // --> > 0: chunked PATCH uploads of this size; 0: monolithic PUT.
        int64_t connectTimeoutMs = 30000;
        int64_t idleTimeoutMs = 120000;
        bool unpack = true;                             // --> Pull: unpack layers into snapshots.
        SSnapshotterOptions snapshotter;
        std::string userAgent = "sbox-image/1";
        FImageProgress progress;
    };

    /**
     * Outcome of a pull.
     */
    struct SBOX_API SPullResult {
        std::string reference;          // --> Full normalized reference that was pulled.
        std::string resolvedDigest;     // --> Digest the registry returned for the reference (index or manifest).
        std::string manifestDigest;     // --> The platform manifest that was stored.
        std::string imageId;            // --> Config digest.
        std::string endpoint;           // --> URL base the content came from (a mirror or the registry).
        uint64_t downloadedBytes = 0;
        SImageInfo image;
    };

    /**
     * Outcome of a push.
     */
    struct SBOX_API SPushResult {
        std::string reference;
        std::string manifestDigest;
        uint64_t uploadedBytes = 0;
        int32_t blobsMounted = 0;
        int32_t blobsExisting = 0;
        int32_t blobsUploaded = 0;
    };

    /**
     * Docker Registry HTTP API v2 / OCI distribution client.
     *
     * - Endpoints: mirrors first (pull only), then the registry (docker.io -> registry-1.docker.io).
     *   HTTPS by default; insecure registries (and loopback ones, as Docker does) try HTTPS
     *   without verification and fall back to plain HTTP; /etc/docker/certs.d/<host>/ CAs and
     *   client certificates are honoured.
     * - Authentication: the /v2/ ping records the challenge; Bearer tokens are fetched from the
     *   realm (anonymously, with Basic credentials, or with an identity token) and cached per
     *   scope until they expire; Basic challenges send the credentials directly.
     * - Manifests: OCI index / Docker manifest list (platform selection), OCI manifest / Docker
     *   schema 2; schema 1 is rejected with -EPROTONOSUPPORT. Digests are verified.
     * - Blobs: downloaded concurrently (maxConcurrentDownloads coroutines on the calling loop),
     *   streamed into the store's ingest while the digest is computed, resumed with Range after
     *   network errors, verified before they become visible.
     * - Push: HEAD to skip existing blobs, cross-repository mount, monolithic PUT or chunked
     *   PATCH uploads, manifest PUT.
     *
     * The coroutines run on the calling thread's CEventLoop; one client serves one loop.
     */
    class SBOX_API CRegistryClient {
    public:
        /** Private state (connection pool, token cache). */
        struct SImpl;

    private:
        std::unique_ptr<SImpl> _impl;

    public:
        /**
         * Creates a client.
         */
        explicit CRegistryClient(SRegistryOptions options = {});

        /** Destroys the client. */
        ~CRegistryClient();

        CRegistryClient(const CRegistryClient&) = delete;

        CRegistryClient& operator=(const CRegistryClient&) = delete;

        /** Returns the settings. */
        SRegistryOptions& options() noexcept;

        /**
         * Returns a description of the last failure (registry error code and message, TLS
         * reason, ...).
         */
        const std::string& lastError() const noexcept;

        /**
         * Pulls an image into a store (and unpacks it when options().unpack).
         * @param reference User string ("alpine", "ghcr.io/x/y:1", "name@sha256:...").
         * @return SBOX_OK; -ENOENT (unknown repository / tag), -EACCES (authentication),
         *         -EPROTONOSUPPORT (schema 1), -EBADMSG (digest mismatch), -ENOEXEC (no
         *         manifest for the platform), network errors.
         */
        TTask<int32_t> pull(CContentStore& store, std::string reference, SPullResult& out);

        /**
         * Pushes a local image to a registry.
         * @param source Local image (name or ID).
         * @param target Destination reference ("" pushes to `source` itself).
         */
        TTask<int32_t> push(CContentStore& store, std::string source, std::string target, SPushResult& out);

        /**
         * Fetches a manifest document (no platform resolution).
         * @param body Receives the exact bytes.
         * @param mediaType Receives the media type.
         * @param digest Receives the digest of the bytes.
         */
        TTask<int32_t> fetchManifest(std::string reference, std::string& body, std::string& mediaType, std::string& digest);

        /**
         * Lists the tags of a repository (follows Link pagination).
         */
        TTask<int32_t> listTags(std::string repository, std::vector<std::string>& out);
    };

}
}

#endif
