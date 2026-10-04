#ifndef __SRC_TLS_TRUSTIMPL_HPP__
#define __SRC_TLS_TRUSTIMPL_HPP__

#include <sbox/tls/trust.hpp>
#include <certpp/x509/cert.hpp>
#include <map>
#include <set>

namespace sbox {
namespace tls {

    /**
     * One parsed trust anchor.
     */
    struct Anchor {
        std::shared_ptr<certpp::x509::CCert> cert;
        std::vector<uint8_t> der;
        std::string subject;    // --> Raw DER of the subject Name (lookup key).
    };

    /**
     * Storage behind CTrustStore.
     */
    struct CTrustStore::SImpl {
        CTrustStorePtr parent;
        std::vector<Anchor> anchors;
        std::multimap<std::string, size_t> bySubject;
        std::set<std::string> ders;     // --> Dedupe key: the whole DER.

        /**
         * Collects the anchors (here and in the parents) whose subject equals `subject`.
         */
        void find(const std::string& subject, std::vector<const Anchor*>& out) const {
            auto range = bySubject.equal_range(subject);
            for (auto it = range.first; it != range.second; ++it) {
                out.push_back(&anchors[it->second]);
            }

            if (parent) {
                parent->impl()->find(subject, out);
            }
        }

        /**
         * Returns true when a certificate with exactly these bytes is an anchor here or in a
         * parent.
         */
        bool contains(const std::string& der) const {
            return ders.count(der) != 0 || (parent && parent->impl()->contains(der));
        }
    };

}
}

#endif
