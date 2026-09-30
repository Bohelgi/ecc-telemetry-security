#pragma once
#include "telemetry/support.hpp"
#include <array>
#include <filesystem>
#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>

namespace telemetry {
class EccIdentity {
public:
    EccIdentity();
    explicit EccIdentity(const Bytes& rawPrivateKeyScalar);
    EccIdentity(EccIdentity&&) noexcept;
    EccIdentity& operator=(EccIdentity&&) noexcept;
    EccIdentity(const EccIdentity&) = delete;
    EccIdentity& operator=(const EccIdentity&) = delete;
    ~EccIdentity();

    static EccIdentity loadOrCreate(const std::filesystem::path& keyFile);

    Bytes rawPrivateKeyScalar() const;
    Bytes publicKeyUncompressed() const;

    Bytes sign(const Bytes& message) const;

    static bool verify(const Bytes& publicKeyUncompressed, const Bytes& message, const Bytes& signature);

private:
    void initFromScalar(const Bytes& rawPrivateKeyScalar);

    mbedtls_ecdsa_context ctx_{};
};

using SessionKey = std::array<uint8_t, 32>;

class EphemeralKeyPair {
public:
    EphemeralKeyPair();
    EphemeralKeyPair(EphemeralKeyPair&&) noexcept;
    EphemeralKeyPair& operator=(EphemeralKeyPair&&) noexcept;
    EphemeralKeyPair(const EphemeralKeyPair&) = delete;
    EphemeralKeyPair& operator=(const EphemeralKeyPair&) = delete;
    ~EphemeralKeyPair();

    Bytes publicKeyUncompressed() const;

    SessionKey deriveSessionKey(const Bytes& peerPublicKeyUncompressed, const Bytes& salt, const Bytes& info) const;

private:
    mbedtls_ecp_group grp_{};
    mbedtls_mpi d_{};
    mbedtls_ecp_point Q_{};
};

struct EncryptedBlob {
    Bytes nonce;
    Bytes ciphertext;
    Bytes tag;
};

class AesGcmCipher {
public:
    static EncryptedBlob encrypt(const SessionKey& key, const Bytes& plaintext, const Bytes& aad);

    static Bytes decrypt(const SessionKey& key, const EncryptedBlob& blob, const Bytes& aad);
};
}
