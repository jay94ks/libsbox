#include <sbox/vpn/ipsec/esp.hpp>
#include <sbox/core/eventloop.hpp>
#include "crypto.hpp"
#include <cerrno>
#include <cstring>

namespace sbox {
namespace vpn {

    using namespace ipsec;

    CEspSa::CEspSa()
        : _spi(0), _inbound(false), _seq(0), _window{ 0, 0 }, _windowSize(64), _bytes(0), _packets(0), _lastUsed(0) {}

    /* Keys the SA. */
    int32_t CEspSa::init(uint32_t spi, bool inbound, const SEspKeys& keys, uint32_t replayWindow) {
        if (replayWindow > 128) {
            return -EINVAL;
        }

        int32_t r = _cipher.init(keys.encr, keys.keyBits, keys.integ, BytesOf(keys.encKey), BytesOf(keys.integKey));
        if (r != SBOX_OK) {
            return r;
        }

        _spi = spi;
        _inbound = inbound;
        _seq = 0;
        _window[0] = 0;
        _window[1] = 0;
        _windowSize = replayWindow;
        _bytes = 0;
        _packets = 0;
        _lastUsed = 0;
        return SBOX_OK;
    }

    /* SPI of a packet. */
    uint32_t CEspSa::packetSpi(const SReadOnlyByteSpan& packet) noexcept {
        return packet.size >= 8 ? GetBe32(packet.data) : 0;
    }

    /* Builds an ESP packet. */
    int32_t CEspSa::encapsulate(const SReadOnlyByteSpan& payload, uint8_t nextHeader, std::vector<uint8_t>& out) {
        if (_inbound || !_cipher.isValid()) {
            return -EINVAL;
        }

        // --> Without ESN the counter must never wrap (RFC 4303 3.3.3): the SA needs a rekey.
        if (_seq == 0xffffffffu) {
            return -EOVERFLOW;
        }

        ++_seq;

        size_t align = _cipher.blockSize() < 4 ? 4 : _cipher.blockSize();
        size_t body = payload.size + 2;
        size_t padLength = (align - body % align) % align;

        std::vector<uint8_t> plain;
        plain.reserve(body + padLength);
        Append(plain, payload);
        for (size_t i = 1; i <= padLength; ++i) {
            plain.push_back(uint8_t(i));
        }

        plain.push_back(uint8_t(padLength));
        plain.push_back(nextHeader);

        out.clear();
        out.reserve(8 + _cipher.ivSize() + plain.size() + _cipher.icvSize());
        PutBe32(out, _spi);
        PutBe32(out, _seq);

        uint8_t header[8];
        std::memcpy(header, out.data(), 8);
        int32_t r = _cipher.seal(SReadOnlyByteSpan(header, 8), BytesOf(plain), out);
        if (r != SBOX_OK) {
            return r;
        }

        _bytes += payload.size;
        ++_packets;
        _lastUsed = CEventLoop::nowMs();
        return SBOX_OK;
    }

    /* Replay check. */
    bool CEspSa::replayOk(uint32_t seq) const noexcept {
        if (seq == 0) {
            return false;
        }

        if (_windowSize == 0 || seq > _seq) {
            return true;
        }

        uint32_t diff = _seq - seq;
        if (diff >= _windowSize) {
            return false;
        }

        return ((_window[diff / 64] >> (diff % 64)) & 1u) == 0;
    }

    /* Records a sequence number. */
    void CEspSa::replayUpdate(uint32_t seq) noexcept {
        if (seq > _seq) {
            uint32_t shift = seq - _seq;
            if (shift >= 128) {
                _window[0] = 0;
                _window[1] = 0;
            }
            else if (shift >= 64) {
                _window[1] = _window[0] << (shift - 64);
                _window[0] = 0;
            }
            else {
                _window[1] = (_window[1] << shift) | (shift ? (_window[0] >> (64 - shift)) : 0);
                _window[0] <<= shift;
            }

            _window[0] |= 1u;
            _seq = seq;
            return;
        }

        uint32_t diff = _seq - seq;
        if (diff < 128) {
            _window[diff / 64] |= uint64_t(1) << (diff % 64);
        }
    }

    /* Opens an ESP packet. */
    int32_t CEspSa::decapsulate(const SReadOnlyByteSpan& packet, std::vector<uint8_t>& payload, uint8_t& nextHeader) {
        if (!_inbound || !_cipher.isValid()) {
            return -EINVAL;
        }

        if (packet.size < 8 + _cipher.ivSize() + _cipher.icvSize() + 2 || GetBe32(packet.data) != _spi) {
            return -EBADMSG;
        }

        uint32_t seq = GetBe32(packet.data + 4);
        if (!replayOk(seq)) {
            return -EALREADY;
        }

        std::vector<uint8_t> plain;
        int32_t r = _cipher.open(packet.slice(0, 8), packet.slice(8), plain);
        if (r != SBOX_OK) {
            return r;
        }

        if (plain.size() < 2) {
            return -EBADMSG;
        }

        size_t padLength = plain[plain.size() - 2];
        nextHeader = plain[plain.size() - 1];
        if (padLength + 2 > plain.size()) {
            return -EBADMSG;
        }

        // --> RFC 4303 2.4: the default padding is 1, 2, 3, ... and a receiver may check it.
        size_t payloadSize = plain.size() - 2 - padLength;
        for (size_t i = 0; i < padLength; ++i) {
            if (plain[payloadSize + i] != uint8_t(i + 1)) {
                return -EBADMSG;
            }
        }

        replayUpdate(seq);
        plain.resize(payloadSize);
        payload = std::move(plain);
        _bytes += payload.size();
        ++_packets;
        _lastUsed = CEventLoop::nowMs();
        return SBOX_OK;
    }

}
}
