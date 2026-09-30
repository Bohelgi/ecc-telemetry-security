#include "telemetry/crypto_primitives.hpp"
#include <mbedtls/ecdh.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <fstream>
#include <stdexcept>

namespace telemetry {
namespace {
constexpr mbedtls_ecp_group_id kCurve = MBEDTLS_ECP_DP_SECP256R1;
constexpr size_t kScalarLen = 32;
constexpr size_t kUncompressedPointLen = 65;

void checkRc(int rc, const char* what) {
    if (rc != 0) {
        throw std::runtime_error(std::string(what) + " failed (mbedTLS code " + std::to_string(rc) + ")");
    }
}

Bytes sha256(const Bytes& message) {
    Bytes digest(32);
    checkRc(mbedtls_sha256_ret(message.data(), message.size(), digest.data(), 0), "mbedtls_sha256_ret");
    return digest;
}
}

EccIdentity::EccIdentity() {
    mbedtls_ecdsa_init(&ctx_);
    checkRc(mbedtls_ecdsa_genkey(&ctx_, kCurve, mbedtls_ctr_drbg_random, RandomSource::instance().drbgCtx()),
            "mbedtls_ecdsa_genkey");
}

EccIdentity::EccIdentity(const Bytes& rawPrivateKeyScalar) {
    mbedtls_ecdsa_init(&ctx_);
    initFromScalar(rawPrivateKeyScalar);
}

void EccIdentity::initFromScalar(const Bytes& rawPrivateKeyScalar) {
    if (rawPrivateKeyScalar.size() != kScalarLen) {
        throw std::invalid_argument("EccIdentity: private key scalar must be 32 bytes");
    }
    checkRc(mbedtls_ecp_group_load(&ctx_.grp, kCurve), "mbedtls_ecp_group_load");
    checkRc(mbedtls_mpi_read_binary(&ctx_.d, rawPrivateKeyScalar.data(), rawPrivateKeyScalar.size()),
            "mbedtls_mpi_read_binary");
    checkRc(mbedtls_ecp_mul(&ctx_.grp, &ctx_.Q, &ctx_.d, &ctx_.grp.G, mbedtls_ctr_drbg_random,
                             RandomSource::instance().drbgCtx()),
            "mbedtls_ecp_mul");
}

EccIdentity::EccIdentity(EccIdentity&& other) noexcept {
    mbedtls_ecdsa_init(&ctx_);
    std::swap(ctx_, other.ctx_);
}

EccIdentity& EccIdentity::operator=(EccIdentity&& other) noexcept {
    if (this != &other) {
        mbedtls_ecdsa_free(&ctx_);
        mbedtls_ecdsa_init(&ctx_);
        std::swap(ctx_, other.ctx_);
    }
    return *this;
}

EccIdentity::~EccIdentity() {
    mbedtls_ecdsa_free(&ctx_);
}

EccIdentity EccIdentity::loadOrCreate(const std::filesystem::path& keyFile) {
    if (std::filesystem::exists(keyFile)) {
        std::ifstream in(keyFile);
        std::string hex;
        std::getline(in, hex);
        if (hex.size() == kScalarLen * 2) {
            return EccIdentity(fromHex(hex));
        }
    }

    EccIdentity identity;
    std::ofstream out(keyFile, std::ios::trunc);
    if (!out) {
        throw std::runtime_error("EccIdentity::loadOrCreate: cannot write " + keyFile.string());
    }
    out << toHex(identity.rawPrivateKeyScalar()) << '\n';
    return identity;
}

Bytes EccIdentity::rawPrivateKeyScalar() const {
    Bytes out(kScalarLen);
    checkRc(mbedtls_mpi_write_binary(&ctx_.d, out.data(), out.size()), "mbedtls_mpi_write_binary");
    return out;
}

Bytes EccIdentity::publicKeyUncompressed() const {
    Bytes out(kUncompressedPointLen);
    size_t writtenLen = 0;
    checkRc(mbedtls_ecp_point_write_binary(&ctx_.grp, &ctx_.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &writtenLen, out.data(),
                                            out.size()),
            "mbedtls_ecp_point_write_binary");
    out.resize(writtenLen);
    return out;
}

Bytes EccIdentity::sign(const Bytes& message) const {
    Bytes digest = sha256(message);

    Bytes sig(MBEDTLS_ECDSA_MAX_LEN);
    size_t sigLen = 0;
    checkRc(mbedtls_ecdsa_write_signature(const_cast<mbedtls_ecdsa_context*>(&ctx_), MBEDTLS_MD_SHA256,
                                           digest.data(), digest.size(), sig.data(), &sigLen,
                                           mbedtls_ctr_drbg_random, RandomSource::instance().drbgCtx()),
            "mbedtls_ecdsa_write_signature");
    sig.resize(sigLen);
    return sig;
}

bool EccIdentity::verify(const Bytes& publicKeyUncompressed, const Bytes& message, const Bytes& signature) {
    if (publicKeyUncompressed.size() != kUncompressedPointLen) {
        return false;
    }

    mbedtls_ecdsa_context verifier;
    mbedtls_ecdsa_init(&verifier);
    bool ok = false;
    if (mbedtls_ecp_group_load(&verifier.grp, kCurve) == 0 &&
        mbedtls_ecp_point_read_binary(&verifier.grp, &verifier.Q, publicKeyUncompressed.data(),
                                       publicKeyUncompressed.size()) == 0) {
        Bytes digest = sha256(message);
        ok = mbedtls_ecdsa_read_signature(&verifier, digest.data(), digest.size(), signature.data(),
                                           signature.size()) == 0;
    }
    mbedtls_ecdsa_free(&verifier);
    return ok;
}

EphemeralKeyPair::EphemeralKeyPair() {
    mbedtls_ecp_group_init(&grp_);
    mbedtls_mpi_init(&d_);
    mbedtls_ecp_point_init(&Q_);

    checkRc(mbedtls_ecp_group_load(&grp_, kCurve), "mbedtls_ecp_group_load");
    checkRc(mbedtls_ecp_gen_keypair(&grp_, &d_, &Q_, mbedtls_ctr_drbg_random, RandomSource::instance().drbgCtx()),
            "mbedtls_ecp_gen_keypair");
}

EphemeralKeyPair::EphemeralKeyPair(EphemeralKeyPair&& other) noexcept {
    mbedtls_ecp_group_init(&grp_);
    mbedtls_mpi_init(&d_);
    mbedtls_ecp_point_init(&Q_);
    std::swap(grp_, other.grp_);
    std::swap(d_, other.d_);
    std::swap(Q_, other.Q_);
}

EphemeralKeyPair& EphemeralKeyPair::operator=(EphemeralKeyPair&& other) noexcept {
    if (this != &other) {
        mbedtls_ecp_group_free(&grp_);
        mbedtls_mpi_free(&d_);
        mbedtls_ecp_point_free(&Q_);
        mbedtls_ecp_group_init(&grp_);
        mbedtls_mpi_init(&d_);
        mbedtls_ecp_point_init(&Q_);
        std::swap(grp_, other.grp_);
        std::swap(d_, other.d_);
        std::swap(Q_, other.Q_);
    }
    return *this;
}

EphemeralKeyPair::~EphemeralKeyPair() {
    mbedtls_ecp_group_free(&grp_);
    mbedtls_mpi_free(&d_);
    mbedtls_ecp_point_free(&Q_);
}

Bytes EphemeralKeyPair::publicKeyUncompressed() const {
    Bytes out(kUncompressedPointLen);
    size_t writtenLen = 0;
    checkRc(mbedtls_ecp_point_write_binary(&grp_, &Q_, MBEDTLS_ECP_PF_UNCOMPRESSED, &writtenLen, out.data(),
                                            out.size()),
            "mbedtls_ecp_point_write_binary");
    out.resize(writtenLen);
    return out;
}

SessionKey EphemeralKeyPair::deriveSessionKey(const Bytes& peerPublicKeyUncompressed, const Bytes& salt,
                                               const Bytes& info) const {
    mbedtls_ecp_point peerQ;
    mbedtls_ecp_point_init(&peerQ);
    mbedtls_mpi sharedZ;
    mbedtls_mpi_init(&sharedZ);

    SessionKey key{};
    try {
        checkRc(mbedtls_ecp_point_read_binary(&grp_, &peerQ, peerPublicKeyUncompressed.data(),
                                               peerPublicKeyUncompressed.size()),
                "mbedtls_ecp_point_read_binary");
        checkRc(mbedtls_ecp_check_pubkey(&grp_, &peerQ), "mbedtls_ecp_check_pubkey");

        checkRc(mbedtls_ecdh_compute_shared(const_cast<mbedtls_ecp_group*>(&grp_), &sharedZ, &peerQ,
                                             const_cast<mbedtls_mpi*>(&d_), mbedtls_ctr_drbg_random,
                                             RandomSource::instance().drbgCtx()),
                "mbedtls_ecdh_compute_shared");

        Bytes sharedSecret(32);
        checkRc(mbedtls_mpi_write_binary(&sharedZ, sharedSecret.data(), sharedSecret.size()),
                "mbedtls_mpi_write_binary");

        const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        checkRc(mbedtls_hkdf(md, salt.data(), salt.size(), sharedSecret.data(), sharedSecret.size(), info.data(),
                              info.size(), key.data(), key.size()),
                "mbedtls_hkdf");
    } catch (...) {
        mbedtls_ecp_point_free(&peerQ);
        mbedtls_mpi_free(&sharedZ);
        throw;
    }

    mbedtls_ecp_point_free(&peerQ);
    mbedtls_mpi_free(&sharedZ);
    return key;
}

namespace {
constexpr size_t kNonceLen = 12;
constexpr size_t kTagLen = 16;

class GcmContext {
public:
    explicit GcmContext(const SessionKey& key) {
        mbedtls_gcm_init(&ctx_);
        int rc = mbedtls_gcm_setkey(&ctx_, MBEDTLS_CIPHER_ID_AES, key.data(),
                                     static_cast<unsigned int>(key.size() * 8));
        if (rc != 0) {
            mbedtls_gcm_free(&ctx_);
            throw std::runtime_error("mbedtls_gcm_setkey failed (code " + std::to_string(rc) + ")");
        }
    }
    ~GcmContext() { mbedtls_gcm_free(&ctx_); }
    mbedtls_gcm_context* get() { return &ctx_; }

private:
    mbedtls_gcm_context ctx_{};
};
}

EncryptedBlob AesGcmCipher::encrypt(const SessionKey& key, const Bytes& plaintext, const Bytes& aad) {
    GcmContext gcm(key);

    EncryptedBlob blob;
    blob.nonce = RandomSource::instance().generate(kNonceLen);
    blob.ciphertext.resize(plaintext.size());
    blob.tag.resize(kTagLen);

    int rc = mbedtls_gcm_crypt_and_tag(gcm.get(), MBEDTLS_GCM_ENCRYPT, plaintext.size(), blob.nonce.data(),
                                        blob.nonce.size(), aad.data(), aad.size(),
                                        plaintext.empty() ? nullptr : plaintext.data(),
                                        blob.ciphertext.empty() ? nullptr : blob.ciphertext.data(), blob.tag.size(),
                                        blob.tag.data());
    if (rc != 0) {
        throw std::runtime_error("mbedtls_gcm_crypt_and_tag failed (code " + std::to_string(rc) + ")");
    }
    return blob;
}

Bytes AesGcmCipher::decrypt(const SessionKey& key, const EncryptedBlob& blob, const Bytes& aad) {
    if (blob.nonce.size() != kNonceLen || blob.tag.size() != kTagLen) {
        throw SecurityException("AesGcmCipher::decrypt: malformed nonce/tag length");
    }

    GcmContext gcm(key);
    Bytes plaintext(blob.ciphertext.size());

    int rc = mbedtls_gcm_auth_decrypt(gcm.get(), blob.ciphertext.size(), blob.nonce.data(), blob.nonce.size(),
                                       aad.data(), aad.size(), blob.tag.data(), blob.tag.size(),
                                       blob.ciphertext.empty() ? nullptr : blob.ciphertext.data(),
                                       plaintext.empty() ? nullptr : plaintext.data());
    if (rc == MBEDTLS_ERR_GCM_AUTH_FAILED) {
        throw SecurityException("AES-GCM authentication tag mismatch: payload rejected as tampered");
    }
    if (rc != 0) {
        throw std::runtime_error("mbedtls_gcm_auth_decrypt failed (code " + std::to_string(rc) + ")");
    }
    return plaintext;
}
}
