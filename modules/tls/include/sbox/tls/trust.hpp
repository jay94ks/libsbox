#ifndef __INCLUDE_SBOX_TLS_TRUST_HPP__
#define __INCLUDE_SBOX_TLS_TRUST_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>

namespace sbox {
namespace tls {

    class CTrustStore;

    using CTrustStorePtr = std::shared_ptr<CTrustStore>;

    /**
     * Set of trust anchors (root CA certificates) that server certificate chains are verified
     * against.
     *
     * A store is loaded once and then shared (CTrustStorePtr) by every connection that uses it;
     * parsing the system bundle costs tens of milliseconds, so do not build one per connection.
     * A store may have a parent: lookups fall through to it, which is how a per-registry CA
     * (Docker's /etc/docker/certs.d/<host>/ca.crt) is layered over the system roots without
     * copying them:
     *
     * ```cpp
     * auto store = CTrustStore::create(CTrustStore::system());
     * store->addFile("/etc/docker/certs.d/myregistry:5000/ca.crt");
     * ```
     *
     * Mutating methods are not thread-safe; finish adding anchors before sharing the store.
     * Lookups (done by the verifier) are read-only and may run concurrently.
     */
    class SBOX_API CTrustStore {
    public:
        struct SImpl;

    private:
        std::unique_ptr<SImpl> _impl;

    public:
        /**
         * Creates an empty store, optionally layered over `parent`.
         */
        explicit CTrustStore(CTrustStorePtr parent = nullptr);

        CTrustStore(const CTrustStore&) = delete;

        CTrustStore& operator=(const CTrustStore&) = delete;

        ~CTrustStore();

        /**
         * Creates an empty shared store, optionally layered over `parent`.
         */
        static CTrustStorePtr create(CTrustStorePtr parent = nullptr);

        /**
         * Returns the process-wide store of system roots, loading it on first use (see
         * loadSystem for the locations). Never null; the store is empty when no bundle exists.
         */
        static CTrustStorePtr system();

        /**
         * Loads the system roots into this store.
         *
         * Files: $SSL_CERT_FILE when set; otherwise the first existing of
         * /etc/ssl/certs/ca-certificates.crt (Debian/Ubuntu/Alpine/Arch),
         * /etc/pki/tls/certs/ca-bundle.crt (Fedora/RHEL), /etc/ssl/ca-bundle.pem (openSUSE),
         * /etc/pki/tls/cacert.pem, /etc/ssl/cert.pem.
         * Directories: every entry of $SSL_CERT_DIR (colon separated) when set; otherwise
         * /etc/ssl/certs, but only if no bundle file was found.
         * @return The number of anchors added (>= 0), or -ENOENT when nothing could be loaded.
         */
        int32_t loadSystem();

        /**
         * Adds every CERTIFICATE block of a PEM text. Blocks that fail to parse are skipped.
         * @return The number of anchors added, or -EINVAL when the text holds no usable
         *         certificate.
         */
        int32_t addPem(std::string_view pem);

        /**
         * Adds one DER-encoded certificate.
         * @return 1 when added, 0 when it was already present, -EINVAL when it does not parse.
         */
        int32_t addDer(const SReadOnlyByteSpan& der);

        /**
         * Adds the certificates of a PEM (or single DER) file.
         * @return The number of anchors added, or a negated errno (-ENOENT, -EINVAL, ...).
         */
        int32_t addFile(const std::string& path);

        /**
         * Adds every *.pem, *.crt and OpenSSL hash-named (xxxxxxxx.N) file of a directory.
         * Unreadable or unparsable entries are skipped.
         * @return The number of anchors added, or a negated errno when the directory cannot be
         *         read.
         */
        int32_t addDirectory(const std::string& path);

        /**
         * Returns the number of anchors held by this store itself (not its parent).
         */
        size_t size() const noexcept;

        /**
         * Returns the parent store (may be null).
         */
        CTrustStorePtr parent() const noexcept;

        /**
         * Returns the implementation (module-internal use by the verifier).
         */
        inline const SImpl* impl() const noexcept { return _impl.get(); }
    };

}
}

#endif
