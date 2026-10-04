#ifndef __SRC_TLS_VERIFYIMPL_HPP__
#define __SRC_TLS_VERIFYIMPL_HPP__

#include <sbox/tls/verify.hpp>

namespace sbox {
namespace tls {

    /**
     * VerifyServerChain with the TLS alert that best describes a failure (bad_certificate,
     * unknown_ca, certificate_expired, unsupported_certificate, certificate_unknown).
     */
    int32_t VerifyChainWithAlert(const std::vector<std::vector<uint8_t>>& chain, const CTrustStore& trust,
                                 const STlsVerifyParams& params, std::string& reason, uint8_t& alert);

}
}

#endif
