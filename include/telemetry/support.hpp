#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

namespace telemetry {
using Bytes = std::vector<uint8_t>;

std::string toHex(const Bytes& data);
Bytes fromHex(const std::string& hex);

class SecurityException : public std::runtime_error {
public:
    explicit SecurityException(const std::string& reason) : std::runtime_error(reason) {}
};

class RandomSource {
public:
    static RandomSource& instance();

    RandomSource(const RandomSource&) = delete;
    RandomSource& operator=(const RandomSource&) = delete;

    Bytes generate(size_t length);

    mbedtls_ctr_drbg_context* drbgCtx() { return &ctrDrbg_; }

private:
    RandomSource();
    ~RandomSource();

    mbedtls_entropy_context entropy_{};
    mbedtls_ctr_drbg_context ctrDrbg_{};
};

namespace wire {
class Writer {
public:
    void putU8(uint8_t v);
    void putU32(uint32_t v);
    void putU64(uint64_t v);
    void putFloat(float v);
    void putBytes(const Bytes& v);
    void putString(const std::string& v);

    const Bytes& data() const { return buffer_; }
    Bytes take() { return std::move(buffer_); }

private:
    Bytes buffer_;
};

class Reader {
public:
    explicit Reader(const Bytes& data) : data_(data) {}

    uint8_t getU8();
    uint32_t getU32();
    uint64_t getU64();
    float getFloat();
    Bytes getBytes();
    std::string getString();

    bool atEnd() const { return pos_ >= data_.size(); }

private:
    void require(size_t n) const;

    const Bytes& data_;
    size_t pos_ = 0;
};
}
}
