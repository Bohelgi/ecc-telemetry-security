#pragma once
#include "telemetry/crypto_primitives.hpp"
#include "telemetry/support.hpp"
#include <cstdint>
#include <string>

namespace telemetry {
struct TelemetryPacket {
    uint64_t unixTimestampMs = 0;
    float voltageV = 0.0f;
    float currentA = 0.0f;
    float powerW = 0.0f;
    float temperatureC = 0.0f;

    Bytes serialize() const;
    static TelemetryPacket deserialize(const Bytes& data);
};

struct HelloMessage {
    std::string deviceId;
    Bytes ephemeralPublicKey;

    Bytes serialize() const;
    static HelloMessage deserialize(const Bytes& data);
};

struct TelemetryEnvelope {
    std::string deviceId;
    uint32_t sequenceNumber = 0;
    Bytes nonce;
    Bytes ciphertext;
    Bytes tag;
    Bytes signature;

    Bytes signedTranscript() const;

    Bytes serialize() const;
    static TelemetryEnvelope deserialize(const Bytes& data);
};

Bytes makeTelemetryAad(const std::string& deviceId, uint32_t sequenceNumber);

Bytes handshakeTranscript(const std::string& deviceId, const Bytes& deviceEphemeralPublicKey,
                           const Bytes& gatewayEphemeralPublicKey);

const Bytes& handshakeHkdfInfo();
}
