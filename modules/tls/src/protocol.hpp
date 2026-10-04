#ifndef __SRC_TLS_PROTOCOL_HPP__
#define __SRC_TLS_PROTOCOL_HPP__

#include <sbox/common.hpp>

// --> Wire constants of TLS 1.2 (RFC 5246) and TLS 1.3 (RFC 8446) used by the client.

namespace sbox {
namespace tls {

    // Record content types.
    constexpr uint8_t CT_CHANGE_CIPHER_SPEC = 20;
    constexpr uint8_t CT_ALERT = 21;
    constexpr uint8_t CT_HANDSHAKE = 22;
    constexpr uint8_t CT_APPLICATION_DATA = 23;

    // Handshake message types.
    constexpr uint8_t HS_HELLO_REQUEST = 0;
    constexpr uint8_t HS_CLIENT_HELLO = 1;
    constexpr uint8_t HS_SERVER_HELLO = 2;
    constexpr uint8_t HS_NEW_SESSION_TICKET = 4;
    constexpr uint8_t HS_END_OF_EARLY_DATA = 5;
    constexpr uint8_t HS_ENCRYPTED_EXTENSIONS = 8;
    constexpr uint8_t HS_CERTIFICATE = 11;
    constexpr uint8_t HS_SERVER_KEY_EXCHANGE = 12;
    constexpr uint8_t HS_CERTIFICATE_REQUEST = 13;
    constexpr uint8_t HS_SERVER_HELLO_DONE = 14;
    constexpr uint8_t HS_CERTIFICATE_VERIFY = 15;
    constexpr uint8_t HS_CLIENT_KEY_EXCHANGE = 16;
    constexpr uint8_t HS_FINISHED = 20;
    constexpr uint8_t HS_KEY_UPDATE = 24;
    constexpr uint8_t HS_MESSAGE_HASH = 254;

    // Extension types.
    constexpr uint16_t EXT_SERVER_NAME = 0;
    constexpr uint16_t EXT_MAX_FRAGMENT_LENGTH = 1;
    constexpr uint16_t EXT_STATUS_REQUEST = 5;
    constexpr uint16_t EXT_SUPPORTED_GROUPS = 10;
    constexpr uint16_t EXT_EC_POINT_FORMATS = 11;
    constexpr uint16_t EXT_SIGNATURE_ALGORITHMS = 13;
    constexpr uint16_t EXT_ALPN = 16;
    constexpr uint16_t EXT_SCT = 18;
    constexpr uint16_t EXT_EXTENDED_MASTER_SECRET = 23;
    constexpr uint16_t EXT_SESSION_TICKET = 35;
    constexpr uint16_t EXT_PRE_SHARED_KEY = 41;
    constexpr uint16_t EXT_EARLY_DATA = 42;
    constexpr uint16_t EXT_SUPPORTED_VERSIONS = 43;
    constexpr uint16_t EXT_COOKIE = 44;
    constexpr uint16_t EXT_PSK_KEY_EXCHANGE_MODES = 45;
    constexpr uint16_t EXT_CERTIFICATE_AUTHORITIES = 47;
    constexpr uint16_t EXT_SIGNATURE_ALGORITHMS_CERT = 50;
    constexpr uint16_t EXT_KEY_SHARE = 51;
    constexpr uint16_t EXT_RENEGOTIATION_INFO = 0xff01;

    // Protocol versions.
    constexpr uint16_t VER_TLS10 = 0x0301;
    constexpr uint16_t VER_TLS12 = 0x0303;
    constexpr uint16_t VER_TLS13 = 0x0304;

    // Cipher suites (TLS 1.3).
    constexpr uint16_t TLS_AES_128_GCM_SHA256 = 0x1301;
    constexpr uint16_t TLS_AES_256_GCM_SHA384 = 0x1302;
    constexpr uint16_t TLS_CHACHA20_POLY1305_SHA256 = 0x1303;

    // Cipher suites (TLS 1.2, ECDHE + AEAD only).
    constexpr uint16_t TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b;
    constexpr uint16_t TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c;
    constexpr uint16_t TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f;
    constexpr uint16_t TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030;
    constexpr uint16_t TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8;
    constexpr uint16_t TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9;

    // Named groups.
    constexpr uint16_t GROUP_SECP256R1 = 0x0017;
    constexpr uint16_t GROUP_SECP384R1 = 0x0018;
    constexpr uint16_t GROUP_X25519 = 0x001d;

    // Signature schemes.
    constexpr uint16_t SIG_RSA_PKCS1_SHA256 = 0x0401;
    constexpr uint16_t SIG_RSA_PKCS1_SHA384 = 0x0501;
    constexpr uint16_t SIG_RSA_PKCS1_SHA512 = 0x0601;
    constexpr uint16_t SIG_ECDSA_SECP256R1_SHA256 = 0x0403;
    constexpr uint16_t SIG_ECDSA_SECP384R1_SHA384 = 0x0503;
    constexpr uint16_t SIG_ECDSA_SECP521R1_SHA512 = 0x0603;
    constexpr uint16_t SIG_RSA_PSS_RSAE_SHA256 = 0x0804;
    constexpr uint16_t SIG_RSA_PSS_RSAE_SHA384 = 0x0805;
    constexpr uint16_t SIG_RSA_PSS_RSAE_SHA512 = 0x0806;
    constexpr uint16_t SIG_ED25519 = 0x0807;

    // Alert levels and descriptions.
    constexpr uint8_t ALERT_WARNING = 1;
    constexpr uint8_t ALERT_FATAL = 2;

    constexpr uint8_t AD_CLOSE_NOTIFY = 0;
    constexpr uint8_t AD_UNEXPECTED_MESSAGE = 10;
    constexpr uint8_t AD_BAD_RECORD_MAC = 20;
    constexpr uint8_t AD_RECORD_OVERFLOW = 22;
    constexpr uint8_t AD_HANDSHAKE_FAILURE = 40;
    constexpr uint8_t AD_BAD_CERTIFICATE = 42;
    constexpr uint8_t AD_UNSUPPORTED_CERTIFICATE = 43;
    constexpr uint8_t AD_CERTIFICATE_REVOKED = 44;
    constexpr uint8_t AD_CERTIFICATE_EXPIRED = 45;
    constexpr uint8_t AD_CERTIFICATE_UNKNOWN = 46;
    constexpr uint8_t AD_ILLEGAL_PARAMETER = 47;
    constexpr uint8_t AD_UNKNOWN_CA = 48;
    constexpr uint8_t AD_ACCESS_DENIED = 49;
    constexpr uint8_t AD_DECODE_ERROR = 50;
    constexpr uint8_t AD_DECRYPT_ERROR = 51;
    constexpr uint8_t AD_PROTOCOL_VERSION = 70;
    constexpr uint8_t AD_INSUFFICIENT_SECURITY = 71;
    constexpr uint8_t AD_INTERNAL_ERROR = 80;
    constexpr uint8_t AD_INAPPROPRIATE_FALLBACK = 86;
    constexpr uint8_t AD_USER_CANCELED = 90;
    constexpr uint8_t AD_NO_RENEGOTIATION = 100;
    constexpr uint8_t AD_MISSING_EXTENSION = 109;
    constexpr uint8_t AD_UNSUPPORTED_EXTENSION = 110;
    constexpr uint8_t AD_UNRECOGNIZED_NAME = 112;
    constexpr uint8_t AD_BAD_CERTIFICATE_STATUS_RESPONSE = 113;
    constexpr uint8_t AD_UNKNOWN_PSK_IDENTITY = 115;
    constexpr uint8_t AD_CERTIFICATE_REQUIRED = 116;
    constexpr uint8_t AD_NO_APPLICATION_PROTOCOL = 120;

    // Record size limits.
    constexpr size_t MAX_PLAINTEXT = 16384;                     // --> 2^14.
    constexpr size_t MAX_CIPHERTEXT_13 = MAX_PLAINTEXT + 256;   // --> RFC 8446 5.2.
    constexpr size_t MAX_CIPHERTEXT_12 = MAX_PLAINTEXT + 2048;  // --> RFC 5246 6.2.3.
    constexpr size_t MAX_HANDSHAKE_MESSAGE = 256 * 1024;        // --> Bound on one reassembled message.

}
}

#endif
