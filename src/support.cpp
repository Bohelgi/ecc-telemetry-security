#include "telemetry/support.hpp"
#include <cstring>
#include <stdexcept>

namespace telemetry {
std::string toHex(const Bytes& data) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0F]);
    }
    return out;
}

namespace {
uint8_t hexNibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    throw std::invalid_argument("fromHex: not a hex digit");
}
}

Bytes fromHex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("fromHex: odd-length string");
    }
    Bytes out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>((hexNibble(hex[i]) << 4) | hexNibble(hex[i + 1])));
    }
    return out;
}

RandomSource::RandomSource() {
    mbedtls_entropy_init(&entropy_);
    mbedtls_ctr_drbg_init(&ctrDrbg_);

    static const unsigned char personalization[] = "secure-telemetry-ecc/rng";
    int rc = mbedtls_ctr_drbg_seed(&ctrDrbg_, mbedtls_entropy_func, &entropy_,
                                    personalization, sizeof(personalization) - 1);
    if (rc != 0) {
        throw std::runtime_error("RandomSource: failed to seed CTR_DRBG (code " + std::to_string(rc) + ")");
    }
}

RandomSource::~RandomSource() {
    mbedtls_ctr_drbg_free(&ctrDrbg_);
    mbedtls_entropy_free(&entropy_);
}

RandomSource& RandomSource::instance() {
    static RandomSource singleton;
    return singleton;
}

Bytes RandomSource::generate(size_t length) {
    Bytes out(length);
    if (length == 0) return out;
    int rc = mbedtls_ctr_drbg_random(&ctrDrbg_, out.data(), length);
    if (rc != 0) {
        throw std::runtime_error("RandomSource: mbedtls_ctr_drbg_random failed (code " + std::to_string(rc) + ")");
    }
    return out;
}

namespace wire {
void Writer::putU8(uint8_t v) {
    buffer_.push_back(v);
}

void Writer::putU32(uint32_t v) {
    buffer_.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>(v & 0xFF));
}

void Writer::putU64(uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        buffer_.push_back(static_cast<uint8_t>((v >> shift) & 0xFF));
    }
}

void Writer::putFloat(float v) {
    uint8_t raw[sizeof(float)];
    std::memcpy(raw, &v, sizeof(float));
    buffer_.insert(buffer_.end(), raw, raw + sizeof(float));
}

void Writer::putBytes(const Bytes& v) {
    if (v.size() > 0xFFFF) {
        throw std::length_error("wire::Writer::putBytes: payload exceeds 65535 bytes");
    }
    putU8(static_cast<uint8_t>((v.size() >> 8) & 0xFF));
    putU8(static_cast<uint8_t>(v.size() & 0xFF));
    buffer_.insert(buffer_.end(), v.begin(), v.end());
}

void Writer::putString(const std::string& v) {
    putBytes(Bytes(v.begin(), v.end()));
}

void Reader::require(size_t n) const {
    if (pos_ + n > data_.size()) {
        throw std::out_of_range("wire::Reader: truncated message");
    }
}

uint8_t Reader::getU8() {
    require(1);
    return data_[pos_++];
}

uint32_t Reader::getU32() {
    require(4);
    uint32_t v = (static_cast<uint32_t>(data_[pos_]) << 24) |
                 (static_cast<uint32_t>(data_[pos_ + 1]) << 16) |
                 (static_cast<uint32_t>(data_[pos_ + 2]) << 8) |
                 static_cast<uint32_t>(data_[pos_ + 3]);
    pos_ += 4;
    return v;
}

uint64_t Reader::getU64() {
    require(8);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | data_[pos_ + i];
    }
    pos_ += 8;
    return v;
}

float Reader::getFloat() {
    require(sizeof(float));
    float v;
    std::memcpy(&v, &data_[pos_], sizeof(float));
    pos_ += sizeof(float);
    return v;
}

Bytes Reader::getBytes() {
    uint16_t len = (static_cast<uint16_t>(getU8()) << 8) | getU8();
    require(len);
    Bytes v(data_.begin() + pos_, data_.begin() + pos_ + len);
    pos_ += len;
    return v;
}

std::string Reader::getString() {
    Bytes v = getBytes();
    return std::string(v.begin(), v.end());
}
}
}
