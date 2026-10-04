#ifndef __INCLUDE_SBOX_VPN_IPSEC_ESP_HPP__
#define __INCLUDE_SBOX_VPN_IPSEC_ESP_HPP__

#include <sbox/common.hpp>
#include <sbox/core/span.hpp>
#include <sbox/vpn/ipsec/ikecrypto.hpp>
#include <vector>

// --> User-space ESP (RFC 4303) for kernels without (usable) XFRM: one direction of an ESP SA
// with the anti-replay window, padding and the IPsec cipher shared with IKE.

namespace sbox {
namespace vpn {

    /**
     * Keys and algorithms of one ESP direction.
     */
    struct SEspKeys {
        uint16_t encr = EIKE_ENCR_AES_GCM_16;
        uint16_t keyBits = 128;
        uint16_t integ = EIKE_INTEG_NONE;
        std::vector<uint8_t> encKey;    // --> Key plus salt for AEAD transforms.
        std::vector<uint8_t> integKey;
    };

    /** IP protocol number of IPv4-in-ESP (tunnel mode). */
    constexpr uint8_t ESP_NEXT_IPV4 = 4;

    /** IP protocol number of IPv6-in-ESP (tunnel mode). */
    constexpr uint8_t ESP_NEXT_IPV6 = 41;

    /**
     * One direction of an ESP security association.
     */
    class SBOX_API CEspSa {
    private:
        uint32_t _spi;
        bool _inbound;
        CIpsecCipher _cipher;
        uint32_t _seq;                  // --> Outbound: last sent; inbound: highest received.
        uint64_t _window[2];            // --> 128-packet anti-replay bitmap (bit 0 = _seq).
        uint32_t _windowSize;
        uint64_t _bytes;
        uint64_t _packets;
        int64_t _lastUsed;

    public:
        CEspSa();

        CEspSa(CEspSa&&) noexcept = default;

        CEspSa& operator=(CEspSa&&) noexcept = default;

        /**
         * Keys the SA.
         * @param spi SPI (host order).
         * @param inbound True for the receiving direction.
         * @param replayWindow Anti-replay window in packets (0 disables, at most 128).
         */
        int32_t init(uint32_t spi, bool inbound, const SEspKeys& keys, uint32_t replayWindow = 64);

        /** Returns the SPI. */
        inline uint32_t spi() const noexcept { return _spi; }

        /** Returns the processed payload bytes. */
        inline uint64_t bytes() const noexcept { return _bytes; }

        /** Returns the processed packets. */
        inline uint64_t packets() const noexcept { return _packets; }

        /** Returns the monotonic time (ms) of the last processed packet, 0 when none. */
        inline int64_t lastUsed() const noexcept { return _lastUsed; }

        /** Returns the last sequence number sent or received. */
        inline uint32_t sequence() const noexcept { return _seq; }

        /**
         * Builds an ESP packet (SPI .. ICV) around `payload`.
         * @param nextHeader ESP_NEXT_IPV4/ESP_NEXT_IPV6 in tunnel mode, the transport protocol
         *        in transport mode.
         * @return SBOX_OK, -EOVERFLOW when the sequence number space is exhausted (rekey), -EIO.
         */
        int32_t encapsulate(const SReadOnlyByteSpan& payload, uint8_t nextHeader, std::vector<uint8_t>& out);

        /**
         * Verifies, replay-checks and decrypts an ESP packet (SPI .. ICV).
         * @return SBOX_OK, -EBADMSG (malformed/padding), -EKEYREJECTED (ICV), -EALREADY (replay).
         */
        int32_t decapsulate(const SReadOnlyByteSpan& packet, std::vector<uint8_t>& payload, uint8_t& nextHeader);

        /**
         * Reads the SPI of an ESP packet (0 when too short).
         */
        static uint32_t packetSpi(const SReadOnlyByteSpan& packet) noexcept;

    private:
        /** Returns true when `seq` would pass the replay check. */
        bool replayOk(uint32_t seq) const noexcept;

        /** Records `seq` in the window. */
        void replayUpdate(uint32_t seq) noexcept;
    };

}
}

#endif
