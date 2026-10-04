#include <sbox/tls/trust.hpp>
#include <sbox/core/file.hpp>
#include "trustimpl.hpp"
#include "der.hpp"
#include <certpp/x509/chain/pem.hpp>
#include <cerrno>
#include <cstdlib>
#include <dirent.h>
#include <sys/stat.h>

namespace sbox {
namespace tls {

    namespace {

        /* Returns true for file names the directory loader picks up. */
        bool wantedName(std::string_view name) {
            auto endsWith = [&](std::string_view suffix) {
                return name.size() > suffix.size() && name.substr(name.size() - suffix.size()) == suffix;
            };

            if (endsWith(".pem") || endsWith(".crt")) {
                return true;
            }

            // --> OpenSSL c_rehash names: eight hex digits, a dot, a decimal counter.
            if (name.size() < 10 || name[8] != '.') {
                return false;
            }

            for (size_t i = 0; i < 8; ++i) {
                char c = name[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                    return false;
                }
            }

            for (size_t i = 9; i < name.size(); ++i) {
                if (name[i] < '0' || name[i] > '9') {
                    return false;
                }
            }

            return true;
        }

    }

    /* Creates an empty store. */
    CTrustStore::CTrustStore(CTrustStorePtr parent) : _impl(std::make_unique<SImpl>()) {
        _impl->parent = std::move(parent);
    }

    /* Destroys the store. */
    CTrustStore::~CTrustStore() = default;

    /* Creates a shared store. */
    CTrustStorePtr CTrustStore::create(CTrustStorePtr parent) {
        return std::make_shared<CTrustStore>(std::move(parent));
    }

    /* Process-wide system store. */
    CTrustStorePtr CTrustStore::system() {
        // --> A function-local static is initialized exactly once even with concurrent callers.
        static CTrustStorePtr store = [] {
            CTrustStorePtr s = create();
            s->loadSystem();
            return s;
        }();

        return store;
    }

    /* Loads the system roots. */
    int32_t CTrustStore::loadSystem() {
        static const char* const BUNDLES[] = {
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/pki/tls/cacert.pem",
            "/etc/ssl/cert.pem",
        };

        int32_t total = 0;
        bool haveFile = false;

        if (const char* file = std::getenv("SSL_CERT_FILE"); file && *file) {
            int32_t n = addFile(file);
            if (n >= 0) {
                total += n;
                haveFile = true;
            }
        }
        else {
            for (const char* path : BUNDLES) {
                int32_t n = addFile(path);
                if (n >= 0) {
                    total += n;
                    haveFile = true;
                    break;
                }
            }
        }

        if (const char* dirs = std::getenv("SSL_CERT_DIR"); dirs && *dirs) {
            std::string_view list(dirs);
            while (!list.empty()) {
                size_t colon = list.find(':');
                std::string_view dir = list.substr(0, colon);
                if (!dir.empty()) {
                    int32_t n = addDirectory(std::string(dir));
                    if (n > 0) {
                        total += n;
                    }
                }

                list = colon == std::string_view::npos ? std::string_view() : list.substr(colon + 1);
            }
        }
        else if (!haveFile) {
            int32_t n = addDirectory("/etc/ssl/certs");
            if (n > 0) {
                total += n;
            }
        }

        return total > 0 || haveFile ? total : -ENOENT;
    }

    /* Adds PEM certificates. */
    int32_t CTrustStore::addPem(std::string_view pem) {
        certpp::CString text(pem.data(), pem.size());
        size_t cursor = 0;
        int32_t added = 0;
        bool any = false;

        while (cursor < text.size()) {
            certpp::CString label;
            certpp::COctet der;
            size_t before = cursor;

            certpp::ERetCode rc = certpp::x509::CPemChainFormat::nextBlock(text, cursor, label, der);
            if (rc == certpp::ERET_NOTFOUND || cursor <= before) {
                break;
            }

            if (rc != certpp::ERET_OK || label.compare("CERTIFICATE") != 0) {
                continue;
            }

            int32_t r = addDer(SReadOnlyByteSpan(der.toPtr(), der.size()));
            if (r >= 0) {
                any = true;
                added += r;
            }
        }

        return any ? added : -EINVAL;
    }

    /* Adds one DER certificate. */
    int32_t CTrustStore::addDer(const SReadOnlyByteSpan& der) {
        std::string key(reinterpret_cast<const char*>(der.data), der.size);
        if (_impl->ders.count(key)) {
            return 0;
        }

        SReadOnlyByteSpan issuer, subject;
        if (!DerCertificateNames(der, issuer, subject)) {
            return -EINVAL;
        }

        auto cert = std::make_shared<certpp::x509::CCert>();
        if (cert->importDer(certpp::COctet(der.data, der.size)) != certpp::ERET_OK) {
            return -EINVAL;
        }

        // --> Builds the lazily cached public key now, so later concurrent lookups only read.
        if (!cert->publicKey()) {
            return -EINVAL;
        }

        Anchor a;
        a.cert = std::move(cert);
        a.der.assign(der.data, der.data + der.size);
        a.subject.assign(reinterpret_cast<const char*>(subject.data), subject.size);

        _impl->bySubject.emplace(a.subject, _impl->anchors.size());
        _impl->anchors.push_back(std::move(a));
        _impl->ders.insert(std::move(key));
        return 1;
    }

    /* Adds a PEM or DER file. */
    int32_t CTrustStore::addFile(const std::string& path) {
        std::string content;
        int32_t rc = CFile::readAll(path, content, size_t(16) << 20);
        if (rc != SBOX_OK) {
            return rc;
        }

        if (content.find("-----BEGIN") != std::string::npos) {
            return addPem(content);
        }

        return addDer(BytesOf(content));
    }

    /* Adds a directory of certificates. */
    int32_t CTrustStore::addDirectory(const std::string& path) {
        DIR* dir = ::opendir(path.c_str());
        if (!dir) {
            return -errno;
        }

        std::vector<std::string> names;
        while (dirent* entry = ::readdir(dir)) {
            if (wantedName(entry->d_name)) {
                names.emplace_back(entry->d_name);
            }
        }

        ::closedir(dir);

        int32_t added = 0;
        for (const std::string& name : names) {
            std::string full = CFile::join(path, name);
            struct stat st{};
            if (::stat(full.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
                continue;
            }

            int32_t n = addFile(full);
            if (n > 0) {
                added += n;
            }
        }

        return added;
    }

    /* Own anchor count. */
    size_t CTrustStore::size() const noexcept {
        return _impl->anchors.size();
    }

    /* Parent store. */
    CTrustStorePtr CTrustStore::parent() const noexcept {
        return _impl->parent;
    }

}
}
