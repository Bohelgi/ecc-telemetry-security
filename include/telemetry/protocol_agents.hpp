#pragma once
#include "telemetry/crypto_primitives.hpp"
#include "telemetry/protocol_messages.hpp"
#include <string>
#include <unordered_map>

namespace telemetry {
class DeviceAgent {
public:
    DeviceAgent(std::string deviceId, EccIdentity identity);

    HelloMessage buildHello();
    void completeHandshake(const HelloMessage& gatewayHello);

    TelemetryEnvelope protect(const TelemetryPacket& packet);

private:
    std::string deviceId_;
    EccIdentity identity_;
    EphemeralKeyPair ephemeral_;
    Bytes myEphemeralPublicKey_;
    bool handshakeComplete_ = false;
    SessionKey sessionKey_{};
    uint32_t sequenceCounter_ = 0;
};

class GatewayAgent {
public:
    void registerTrustedDevice(const std::string& deviceId, const Bytes& longTermPublicKeyUncompressed);
    bool isTrusted(const std::string& deviceId) const;

    HelloMessage acceptHello(const HelloMessage& deviceHello);
    TelemetryPacket unprotect(const TelemetryEnvelope& msg);

private:
    struct SessionState {
        SessionKey key{};
        uint32_t lastSequence = 0;
    };

    std::unordered_map<std::string, Bytes> trustedDevices_;
    std::unordered_map<std::string, SessionState> sessions_;
};
}
