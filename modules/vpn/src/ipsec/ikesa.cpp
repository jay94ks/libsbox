#include "ikesa.hpp"
#include "crypto.hpp"
#include "der.hpp"
#include <sbox/core/eventloop.hpp>
#include <certpp/crypto/asym.hpp>
#include <certpp/x509/cert.hpp>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>

namespace sbox {
namespace vpn {
namespace ipsec {

    using namespace certpp::crypto;

    namespace {

        const char KEY_PAD[] = "Key Pad for IKEv2";

        // --> RFC 7427 hash algorithm identifiers (IANA "Hash Algorithms").
        constexpr uint16_t HASH_SHA1 = 1;
        constexpr uint16_t HASH_SHA256 = 2;
        constexpr uint16_t HASH_SHA384 = 3;
        constexpr uint16_t HASH_SHA512 = 4;

        struct SigAlg {
            uint8_t oid[9];
            size_t oidSize;
            bool ecdsa;
            EHashers hash;
        };

        const SigAlg SIG_ALGS[] = {
            { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05 }, 9, false, EHASH_SHA1 },
            { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b }, 9, false, EHASH_SHA256 },
            { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c }, 9, false, EHASH_SHA384 },
            { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d }, 9, false, EHASH_SHA512 },
            { { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01 }, 7, true, EHASH_SHA1 },
            { { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 }, 8, true, EHASH_SHA256 },
            { { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 }, 8, true, EHASH_SHA384 },
            { { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04 }, 8, true, EHASH_SHA512 },
        };

        const uint8_t OID_RSA_PSS[9] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a };

        struct HashOid {
            uint8_t oid[9];
            size_t oidSize;
            EHashers hash;
        };

        const HashOid HASH_OIDS[] = {
            { { 0x2b, 0x0e, 0x03, 0x02, 0x1a }, 5, EHASH_SHA1 },
            { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 }, 9, EHASH_SHA256 },
            { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 }, 9, EHASH_SHA384 },
            { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 }, 9, EHASH_SHA512 },
        };

        /* Maps a hash OID. */
        EHashers hashOfOid(const SReadOnlyByteSpan& oid) {
            for (const HashOid& h : HASH_OIDS) {
                if (oid.size == h.oidSize && std::memcmp(oid.data, h.oid, h.oidSize) == 0) {
                    return h.hash;
                }
            }

            return EHASH_UNKNOWN;
        }

        /* Encodes a signature AlgorithmIdentifier (RSA PKCS#1 with NULL parameters). */
        std::vector<uint8_t> algorithmIdentifier(bool ecdsa, EHashers hash) {
            for (const SigAlg& a : SIG_ALGS) {
                if (a.ecdsa == ecdsa && a.hash == hash) {
                    std::vector<uint8_t> body;
                    DerPut(body, 0x06, SReadOnlyByteSpan(a.oid, a.oidSize));
                    if (!ecdsa) {
                        body.push_back(0x05);
                        body.push_back(0x00);
                    }

                    std::vector<uint8_t> out;
                    DerPut(out, 0x30, BytesOf(body));
                    return out;
                }
            }

            return {};
        }

        /* Curve coordinate size of an ECDSA key (0 for others). */
        size_t ecCoord(EAsymmetrics which) {
            switch (which) {
            case EASYM_P256: return 32;
            case EASYM_P384: return 48;
            case EASYM_P521: return 66;
            default: return 0;
            }
        }

        /* Byte-for-byte case-insensitive compare. */
        bool equalsNoCase(std::string_view a, std::string_view b) {
            if (a.size() != b.size()) {
                return false;
            }

            for (size_t i = 0; i < a.size(); ++i) {
                char x = a[i];
                char y = b[i];
                if (x >= 'A' && x <= 'Z') {
                    x = char(x - 'A' + 'a');
                }

                if (y >= 'A' && y <= 'Z') {
                    y = char(y - 'A' + 'a');
                }

                if (x != y) {
                    return false;
                }
            }

            return true;
        }

    }

    /* Suite from a proposal. */
    Suite Suite::from(const SIkeProposal& p) {
        Suite s;
        SIkeTransform e = p.first(EIKE_TT_ENCR);
        s.encr = e.id;
        s.keyBits = e.keyLength;
        s.integ = p.first(EIKE_TT_INTEG).id;
        s.prf = p.first(EIKE_TT_PRF).id;
        s.dh = p.first(EIKE_TT_DH).id;
        s.esn = p.first(EIKE_TT_ESN).id;
        return s;
    }

    /* Wipes IKE keys. */
    void IkeKeys::wipe() {
        for (std::vector<uint8_t>* k : { &d, &ai, &ar, &ei, &er, &pi, &pr }) {
            IkeWipe(*k);
        }
    }

    /* Wipes CHILD keys. */
    void ChildKeys::wipe() {
        for (std::vector<uint8_t>* k : { &encIr, &integIr, &encRi, &integRi }) {
            IkeWipe(*k);
        }
    }

    /* SKEYSEED. */
    int32_t ComputeSkeyseed(uint16_t prf, const SReadOnlyByteSpan& ni, const SReadOnlyByteSpan& nr, const SReadOnlyByteSpan& gir,
                            std::vector<uint8_t>& out) {
        std::vector<uint8_t> key;
        Append(key, ni);
        Append(key, nr);
        int32_t r = IkePrf(prf, BytesOf(key), gir, out);
        IkeWipe(key);
        return r;
    }

    /* Rekey SKEYSEED. */
    int32_t ComputeRekeySkeyseed(uint16_t oldPrf, const SReadOnlyByteSpan& oldSkD, const SReadOnlyByteSpan& gir,
                                 const SReadOnlyByteSpan& ni, const SReadOnlyByteSpan& nr, std::vector<uint8_t>& out) {
        std::vector<uint8_t> data;
        Append(data, gir);
        Append(data, ni);
        Append(data, nr);
        int32_t r = IkePrf(oldPrf, oldSkD, BytesOf(data), out);
        IkeWipe(data);
        return r;
    }

    /* SK_* derivation. */
    int32_t DeriveIkeKeys(const Suite& suite, const SReadOnlyByteSpan& skeyseed, const SReadOnlyByteSpan& ni,
                          const SReadOnlyByteSpan& nr, uint64_t spiI, uint64_t spiR, IkeKeys& out) {
        size_t prfLen = IkePrfSize(suite.prf);
        size_t integLen = IkeIntegKeySize(suite.integ);
        size_t encLen = IkeEncrKeyMaterial(suite.encr, suite.keyBits);
        if (!prfLen || !encLen) {
            return -ENOTSUP;
        }

        std::vector<uint8_t> seed;
        Append(seed, ni);
        Append(seed, nr);
        PutBe64(seed, spiI);
        PutBe64(seed, spiR);

        std::vector<uint8_t> km;
        int32_t r = IkePrfPlus(suite.prf, skeyseed, BytesOf(seed), prfLen * 3 + integLen * 2 + encLen * 2, km);
        if (r != SBOX_OK) {
            return r;
        }

        size_t at = 0;
        auto take = [&](size_t n) {
            std::vector<uint8_t> v(km.begin() + long(at), km.begin() + long(at + n));
            at += n;
            return v;
        };

        out.d = take(prfLen);
        out.ai = take(integLen);
        out.ar = take(integLen);
        out.ei = take(encLen);
        out.er = take(encLen);
        out.pi = take(prfLen);
        out.pr = take(prfLen);
        IkeWipe(km);
        return SBOX_OK;
    }

    /* CHILD KEYMAT. */
    int32_t DeriveChildKeys(uint16_t prf, const SReadOnlyByteSpan& skD, const SReadOnlyByteSpan& gir, const SReadOnlyByteSpan& ni,
                            const SReadOnlyByteSpan& nr, const Suite& child, ChildKeys& out) {
        size_t encLen = IkeEncrKeyMaterial(child.encr, child.keyBits);
        size_t integLen = IkeIntegKeySize(child.integ);
        if (!encLen) {
            return -ENOTSUP;
        }

        std::vector<uint8_t> seed;
        Append(seed, gir);
        Append(seed, ni);
        Append(seed, nr);

        std::vector<uint8_t> km;
        int32_t r = IkePrfPlus(prf, skD, BytesOf(seed), (encLen + integLen) * 2, km);
        IkeWipe(seed);
        if (r != SBOX_OK) {
            return r;
        }

        size_t at = 0;
        auto take = [&](size_t n) {
            std::vector<uint8_t> v(km.begin() + long(at), km.begin() + long(at + n));
            at += n;
            return v;
        };

        out.encIr = take(encLen);
        out.integIr = take(integLen);
        out.encRi = take(encLen);
        out.integRi = take(integLen);
        IkeWipe(km);
        return SBOX_OK;
    }

    /* Endpoint address. */
    net::SIpAddress AddressOf(const SEndpoint& endpoint) {
        net::SIpAddress a;
        if (endpoint.family() == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(&endpoint.storage);
            net::SIpAddress::fromBytes(reinterpret_cast<const uint8_t*>(&sin->sin_addr), 4, a);
        }
        else if (endpoint.family() == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(&endpoint.storage);
            net::SIpAddress::fromBytes(reinterpret_cast<const uint8_t*>(&sin6->sin6_addr), 16, a);
        }

        return a;
    }

    /* Endpoint from address and port. */
    SEndpoint EndpointOf(const net::SIpAddress& address, uint16_t port) {
        SEndpoint ep;
        SEndpoint::fromIp(address.toString(), port, ep);
        return ep;
    }

    /* NAT detection hash. */
    std::vector<uint8_t> NatHash(uint64_t spiI, uint64_t spiR, const SEndpoint& endpoint) {
        std::vector<uint8_t> data;
        PutBe64(data, spiI);
        PutBe64(data, spiR);
        if (endpoint.family() == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(&endpoint.storage);
            Append(data, SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(&sin->sin_addr), 4));
        }
        else if (endpoint.family() == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(&endpoint.storage);
            Append(data, SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(&sin6->sin6_addr), 16));
        }

        PutBe16(data, endpoint.port());
        return Hash(EHASH_SHA1, BytesOf(data));
    }

    /* Signed octets. */
    std::vector<uint8_t> AuthOctets(const SReadOnlyByteSpan& message, const SReadOnlyByteSpan& nonce, uint16_t prf,
                                    const SReadOnlyByteSpan& skP, const SReadOnlyByteSpan& idBody) {
        std::vector<uint8_t> mac;
        if (IkePrf(prf, skP, idBody, mac) != SBOX_OK) {
            return {};
        }

        std::vector<uint8_t> out;
        out.reserve(message.size + nonce.size + mac.size());
        Append(out, message);
        Append(out, nonce);
        Append(out, BytesOf(mac));
        return out;
    }

    /* PSK / MSK AUTH. */
    int32_t SharedKeyAuth(uint16_t prf, const SReadOnlyByteSpan& secret, const SReadOnlyByteSpan& octets, std::vector<uint8_t>& out) {
        std::vector<uint8_t> padKey;
        int32_t r = IkePrf(prf, secret, SReadOnlyByteSpan(reinterpret_cast<const uint8_t*>(KEY_PAD), sizeof(KEY_PAD) - 1), padKey);
        if (r != SBOX_OK) {
            return r;
        }

        r = IkePrf(prf, BytesOf(padKey), octets, out);
        IkeWipe(padKey);
        return r;
    }

    /* SIGNATURE_HASH_ALGORITHMS parsing. */
    std::vector<uint16_t> ParseHashAlgorithms(const SReadOnlyByteSpan& data) {
        std::vector<uint16_t> out;
        for (size_t i = 0; i + 1 < data.size; i += 2) {
            out.push_back(GetBe16(data.data + i));
        }

        return out;
    }

    /* Our hash list. */
    std::vector<uint8_t> OurHashAlgorithms() {
        std::vector<uint8_t> out;
        PutBe16(out, HASH_SHA256);
        PutBe16(out, HASH_SHA384);
        PutBe16(out, HASH_SHA512);
        return out;
    }

    /* Signs AUTH octets. */
    int32_t SignAuth(const CIkeCertificate& cert, const SReadOnlyByteSpan& octets, const std::vector<uint16_t>& peerHashes,
                     uint8_t& method, std::vector<uint8_t>& data) {
        IPublicKeyPtr pub = cert.native().publicKey();
        IPrivateKeyPtr key = cert.privateKey();
        if (!pub || !key) {
            return -ENOTSUP;
        }

        EAsymmetrics which = pub->algorithm();
        size_t coord = ecCoord(which);
        bool ecdsa = coord != 0;
        if (!ecdsa && which != EASYM_RSA) {
            return -ENOTSUP;
        }

        // --> RFC 7427 when the peer announced it, else the classic per-key methods.
        bool rfc7427 = false;
        EHashers hash = EHASH_SHA1;
        auto offers = [&](uint16_t h) {
            for (uint16_t x : peerHashes) {
                if (x == h) {
                    return true;
                }
            }

            return false;
        };

        if (!peerHashes.empty()) {
            uint16_t want = coord == 48 ? HASH_SHA384 : coord == 66 ? HASH_SHA512 : HASH_SHA256;
            const uint16_t order[] = { want, HASH_SHA256, HASH_SHA384, HASH_SHA512 };
            for (uint16_t h : order) {
                if (offers(h)) {
                    rfc7427 = true;
                    hash = h == HASH_SHA256 ? EHASH_SHA256 : h == HASH_SHA384 ? EHASH_SHA384 : EHASH_SHA512;
                    break;
                }
            }
        }

        if (!rfc7427) {
            hash = coord == 32 ? EHASH_SHA256 : coord == 48 ? EHASH_SHA384 : coord == 66 ? EHASH_SHA512 : EHASH_SHA1;
        }

        std::vector<uint8_t> digest = Hash(hash, octets);
        IAsymmetricPtr asym = IAsymmetric::builtIn(which);
        IAsymmetricContextPtr ctx = asym ? asym->createContext() : nullptr;
        if (digest.empty() || !ctx) {
            return -EIO;
        }

        ctx->keyPair(pub, key);
        std::vector<uint8_t> sig(ctx->sizeOfSign() ? ctx->sizeOfSign() : 1024);
        certpp::SByteSpan sigOut(sig.data(), sig.size());
        if (ctx->sign(certpp::SReadOnlyByteSpan(digest.data(), digest.size()), sigOut) != certpp::ERET_OK) {
            return -EIO;
        }

        sig.resize(sigOut.size);
        data.clear();

        if (rfc7427) {
            std::vector<uint8_t> algId = algorithmIdentifier(ecdsa, hash);
            method = EIKE_AUTH_DIGITAL_SIGNATURE;
            data.push_back(uint8_t(algId.size()));
            Append(data, BytesOf(algId));
            Append(data, BytesOf(sig));
            return SBOX_OK;
        }

        if (ecdsa) {
            method = coord == 32 ? EIKE_AUTH_ECDSA_256 : coord == 48 ? EIKE_AUTH_ECDSA_384 : EIKE_AUTH_ECDSA_521;
            return EcdsaDerToRaw(BytesOf(sig), coord, data) ? SBOX_OK : -EIO;
        }

        method = EIKE_AUTH_RSA_SIG;
        data = std::move(sig);
        return SBOX_OK;
    }

    /* Verifies an AUTH signature. */
    int32_t VerifyAuth(const CIkeCertificate& cert, uint8_t method, const SReadOnlyByteSpan& data, const SReadOnlyByteSpan& octets) {
        IPublicKeyPtr pub = cert.native().publicKey();
        if (!pub) {
            return -ENOTSUP;
        }

        EAsymmetrics which = pub->algorithm();
        size_t coord = ecCoord(which);
        bool ecdsaKey = coord != 0;

        EHashers hash = EHASH_UNKNOWN;
        bool pss = false;
        size_t saltLen = 0;
        std::vector<uint8_t> signature;

        switch (method) {
        case EIKE_AUTH_RSA_SIG:
            if (which != EASYM_RSA) {
                return -EKEYREJECTED;
            }

            hash = EHASH_SHA1;
            signature.assign(data.begin(), data.end());
            break;

        case EIKE_AUTH_ECDSA_256:
        case EIKE_AUTH_ECDSA_384:
        case EIKE_AUTH_ECDSA_521: {
            size_t want = method == EIKE_AUTH_ECDSA_256 ? 32 : method == EIKE_AUTH_ECDSA_384 ? 48 : 66;
            if (coord != want || data.size != want * 2 || !EcdsaRawToDer(data, signature)) {
                return -EKEYREJECTED;
            }

            hash = want == 32 ? EHASH_SHA256 : want == 48 ? EHASH_SHA384 : EHASH_SHA512;
            break;
        }

        case EIKE_AUTH_DIGITAL_SIGNATURE: {
            if (data.size < 2 || size_t(data[0]) + 1 > data.size) {
                return -EBADMSG;
            }

            SReadOnlyByteSpan algId = data.slice(1, data[0]);
            SReadOnlyByteSpan in = algId;
            DerElement seq;
            DerElement oid;
            if (!DerNext(in, seq) || seq.tag != 0x30) {
                return -EBADMSG;
            }

            SReadOnlyByteSpan fields = seq.value();
            if (!DerNext(fields, oid) || oid.tag != 0x06) {
                return -EBADMSG;
            }

            bool known = false;
            for (const SigAlg& a : SIG_ALGS) {
                if (oid.contentSize == a.oidSize && std::memcmp(oid.content, a.oid, a.oidSize) == 0) {
                    if (a.ecdsa != ecdsaKey) {
                        return -EKEYREJECTED;
                    }

                    hash = a.hash;
                    known = true;
                    break;
                }
            }

            if (!known && oid.contentSize == sizeof(OID_RSA_PSS) && std::memcmp(oid.content, OID_RSA_PSS, sizeof(OID_RSA_PSS)) == 0) {
                if (which != EASYM_RSA) {
                    return -EKEYREJECTED;
                }

                // --> RSASSA-PSS-params: [0] hash, [1] MGF (assumed MGF1 with the same hash),
                // [2] salt length; RFC 4055 defaults are SHA-1 and 20.
                pss = true;
                hash = EHASH_SHA1;
                saltLen = 20;
                DerElement params;
                if (DerNext(fields, params) && params.tag == 0x30) {
                    SReadOnlyByteSpan p = params.value();
                    DerElement item;
                    while (DerNext(p, item)) {
                        SReadOnlyByteSpan inner = item.value();
                        if (item.tag == 0xa0) {
                            DerElement algSeq;
                            DerElement hashOid;
                            if (DerNext(inner, algSeq) && algSeq.tag == 0x30) {
                                SReadOnlyByteSpan a = algSeq.value();
                                if (DerNext(a, hashOid) && hashOid.tag == 0x06) {
                                    hash = hashOfOid(hashOid.value());
                                }
                            }
                        }
                        else if (item.tag == 0xa2) {
                            DerElement salt;
                            if (DerNext(inner, salt) && salt.tag == 0x02 && salt.contentSize <= 4) {
                                saltLen = 0;
                                for (size_t i = 0; i < salt.contentSize; ++i) {
                                    saltLen = (saltLen << 8) | salt.content[i];
                                }
                            }
                        }
                    }
                }

                known = hash != EHASH_UNKNOWN;
            }

            if (!known) {
                return -ENOTSUP;
            }

            signature.assign(data.data + 1 + data[0], data.data + data.size);
            break;
        }

        default:
            return -ENOTSUP;
        }

        std::vector<uint8_t> digest = Hash(hash, octets);
        IAsymmetricContextPtr ctx = cert.native().createAsymmetricContext();
        if (digest.empty() || !ctx) {
            return -EIO;
        }

        certpp::SReadOnlyByteSpan d(digest.data(), digest.size());
        certpp::SReadOnlyByteSpan s(signature.data(), signature.size());
        certpp::ERetCode rc = pss ? ctx->verifyPss(d, hash, saltLen, s) : ctx->verify(d, s);
        return rc == certpp::ERET_OK ? SBOX_OK : -EKEYREJECTED;
    }

    /* Identity binding. */
    bool IdMatchesCertificate(const SIkeId& id, const CIkeCertificate& cert) {
        switch (id.type) {
        case EIKE_ID_DER_ASN1_DN:
            return id.data == cert.subjectDer() || DnToString(BytesOf(id.data)) == cert.subject();

        case EIKE_ID_FQDN: {
            std::string name(id.data.begin(), id.data.end());
            for (const std::string& dns : cert.dnsNames()) {
                if (equalsNoCase(dns, name)) {
                    return true;
                }
            }

            return false;
        }

        case EIKE_ID_RFC822_ADDR: {
            std::string mail(id.data.begin(), id.data.end());
            for (const std::string& e : cert.emails()) {
                if (equalsNoCase(e, mail)) {
                    return true;
                }
            }

            return false;
        }

        case EIKE_ID_IPV4_ADDR:
        case EIKE_ID_IPV6_ADDR: {
            std::string text = id.toString();
            for (const std::string& ip : cert.ipAddresses()) {
                if (ip == text) {
                    return true;
                }
            }

            return false;
        }

        default:
            return false;
        }
    }

    /* Plain message. */
    std::vector<uint8_t> EncodePlainMessage(SIkeHeader header, const std::vector<SIkePayload>& payloads) {
        std::vector<uint8_t> body;
        uint8_t first = 0;
        EncodeIkePayloads(payloads, body, first);
        header.nextPayload = first;
        header.length = uint32_t(IKE_HEADER_SIZE + body.size());

        std::vector<uint8_t> out;
        out.reserve(header.length);
        header.encode(out);
        Append(out, BytesOf(body));
        return out;
    }

    // ---------------------------------------------------------------------------------------

    IkeSa::~IkeSa() {
        keys.wipe();
    }

    /* Header flags. */
    uint8_t IkeSa::flags(bool response) const noexcept {
        return uint8_t((initiator ? EIKE_F_INITIATOR : 0) | (response ? EIKE_F_RESPONSE : 0));
    }

    /* Derives and installs keys. */
    int32_t IkeSa::installKeys(const SReadOnlyByteSpan& skeyseed) {
        int32_t r = DeriveIkeKeys(suite, skeyseed, BytesOf(ni), BytesOf(nr), spiI, spiR, keys);
        if (r != SBOX_OK) {
            return r;
        }

        CIpsecCipher fromI;
        CIpsecCipher fromR;
        r = fromI.init(suite.encr, suite.keyBits, suite.integ, BytesOf(keys.ei), BytesOf(keys.ai));
        if (r == SBOX_OK) {
            r = fromR.init(suite.encr, suite.keyBits, suite.integ, BytesOf(keys.er), BytesOf(keys.ar));
        }

        if (r != SBOX_OK) {
            return r;
        }

        if (initiator) {
            out = std::move(fromI);
            in = std::move(fromR);
        }
        else {
            out = std::move(fromR);
            in = std::move(fromI);
        }

        return SBOX_OK;
    }

    /* Builds protected datagrams. */
    int32_t IkeSa::encrypt(uint8_t exchange, bool response, uint32_t mid, const std::vector<SIkePayload>& payloads,
                           std::vector<std::vector<uint8_t>>& datagrams) {
        datagrams.clear();
        if (!out.isValid()) {
            return -EINVAL;
        }

        std::vector<uint8_t> inner;
        uint8_t firstType = 0;
        EncodeIkePayloads(payloads, inner, firstType);

        size_t block = out.blockSize();
        size_t ivSize = out.ivSize();
        size_t icvSize = out.icvSize();

        auto build = [&](const SReadOnlyByteSpan& chunk, uint8_t nextType, bool fragment, uint16_t number, uint16_t total,
                         std::vector<uint8_t>& msg) -> int32_t {
            std::vector<uint8_t> padded;
            padded.reserve(chunk.size + block + 1);
            Append(padded, chunk);
            size_t padLength = (block - (chunk.size + 1) % block) % block;
            padded.insert(padded.end(), padLength, 0);
            padded.push_back(uint8_t(padLength));

            size_t payloadLength = IKE_PAYLOAD_HEADER_SIZE + (fragment ? 4 : 0) + ivSize + padded.size() + icvSize;
            SIkeHeader h;
            h.spiI = spiI;
            h.spiR = spiR;
            h.nextPayload = fragment ? EIKE_PL_SKF : EIKE_PL_SK;
            h.exchange = exchange;
            h.flags = flags(response);
            h.messageId = mid;
            h.length = uint32_t(IKE_HEADER_SIZE + payloadLength);

            msg.clear();
            msg.reserve(h.length);
            h.encode(msg);
            msg.push_back(nextType);
            msg.push_back(0);
            PutBe16(msg, uint32_t(payloadLength));
            if (fragment) {
                PutBe16(msg, number);
                PutBe16(msg, total);
            }

            std::vector<uint8_t> aad = msg;
            int32_t r = out.seal(BytesOf(aad), BytesOf(padded), msg);
            IkeWipe(padded);
            return r;
        };

        size_t whole = IKE_HEADER_SIZE + IKE_PAYLOAD_HEADER_SIZE + ivSize + inner.size() + block + icvSize;
        if (!fragmentation || whole <= fragmentSize || exchange == EIKE_X_SA_INIT) {
            std::vector<uint8_t> msg;
            int32_t r = build(BytesOf(inner), firstType, false, 0, 0, msg);
            IkeWipe(inner);
            if (r != SBOX_OK) {
                return r;
            }

            datagrams.push_back(std::move(msg));
            return SBOX_OK;
        }

        size_t overhead = IKE_HEADER_SIZE + IKE_PAYLOAD_HEADER_SIZE + 4 + ivSize + icvSize + block;
        size_t chunk = fragmentSize > overhead + 64 ? fragmentSize - overhead : 64;
        size_t count = (inner.size() + chunk - 1) / chunk;
        if (count > 0xffff) {
            IkeWipe(inner);
            return -EMSGSIZE;
        }

        for (size_t i = 0; i < count; ++i) {
            SReadOnlyByteSpan part = BytesOf(inner).slice(i * chunk, chunk);
            std::vector<uint8_t> msg;
            int32_t r = build(part, i == 0 ? firstType : uint8_t(0), true, uint16_t(i + 1), uint16_t(count), msg);
            if (r != SBOX_OK) {
                IkeWipe(inner);
                datagrams.clear();
                return r;
            }

            datagrams.push_back(std::move(msg));
        }

        IkeWipe(inner);
        return SBOX_OK;
    }

    /* Opens a protected message. */
    int32_t IkeSa::decrypt(const SIkeHeader& header, const SReadOnlyByteSpan& message, std::vector<SIkePayload>& payloads) {
        if (!in.isValid()) {
            return -EINVAL;
        }

        // --> The peer's messages carry the opposite Initiator flag.
        if (header.fromInitiator() == initiator) {
            return -EBADMSG;
        }

        if (message.size != header.length || message.size < IKE_HEADER_SIZE + IKE_PAYLOAD_HEADER_SIZE) {
            return -EBADMSG;
        }

        const uint8_t* p = message.data + IKE_HEADER_SIZE;
        uint8_t next = p[0];
        size_t payloadLength = GetBe16(p + 2);
        if (payloadLength != message.size - IKE_HEADER_SIZE) {
            return -EBADMSG;
        }

        auto openPadded = [&](size_t aadSize, std::vector<uint8_t>& plain) -> int32_t {
            int32_t r = in.open(message.slice(0, aadSize), message.slice(aadSize), plain);
            if (r != SBOX_OK) {
                return r;
            }

            if (plain.empty() || size_t(plain.back()) + 1 > plain.size()) {
                return -EBADMSG;
            }

            plain.resize(plain.size() - 1 - plain.back());
            return SBOX_OK;
        };

        if (header.nextPayload == EIKE_PL_SK) {
            std::vector<uint8_t> plain;
            int32_t r = openPadded(IKE_HEADER_SIZE + IKE_PAYLOAD_HEADER_SIZE, plain);
            if (r != SBOX_OK) {
                return r;
            }

            r = ParseIkePayloads(next, BytesOf(plain), payloads);
            IkeWipe(plain);
            return r;
        }

        if (header.nextPayload != EIKE_PL_SKF || !fragmentation) {
            return -EBADMSG;
        }

        uint16_t number = 0;
        uint16_t total = 0;
        if (DecodeIkeFragmentHeader(message.slice(IKE_HEADER_SIZE + IKE_PAYLOAD_HEADER_SIZE), number, total) != SBOX_OK
            || total > 128 || (number == 1) != (next != 0)) {
            return -EBADMSG;
        }

        bool sameMessage = reasm.active && reasm.mid == header.messageId && reasm.response == header.isResponse();
        if (sameMessage && total < reasm.total) {
            return -EBADMSG;
        }

        std::vector<uint8_t> plain;
        int32_t r = openPadded(IKE_HEADER_SIZE + IKE_PAYLOAD_HEADER_SIZE + 4, plain);
        if (r != SBOX_OK) {
            return r;
        }

        // --> RFC 7383 2.6.2: a larger Total Fragments value means the sender re-fragmented
        // the message, so everything collected so far is dropped.
        if (!sameMessage || total > reasm.total) {
            reasm = Reassembly();
            reasm.active = true;
            reasm.mid = header.messageId;
            reasm.response = header.isResponse();
            reasm.exchange = header.exchange;
            reasm.total = total;
            reasm.started = CEventLoop::nowMs();
        }

        if (number == 1) {
            reasm.firstType = next;
        }

        reasm.parts.emplace(number, std::move(plain));
        if (reasm.parts.size() < reasm.total) {
            return -EAGAIN;
        }

        std::vector<uint8_t> whole;
        for (auto& [n, part] : reasm.parts) {
            (void)n;
            Append(whole, BytesOf(part));
            IkeWipe(part);
        }

        uint8_t first = reasm.firstType;
        reasm = Reassembly();
        r = ParseIkePayloads(first, BytesOf(whole), payloads);
        IkeWipe(whole);
        return r;
    }

}
}
}
