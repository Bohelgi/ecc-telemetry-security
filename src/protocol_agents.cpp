#include "telemetry/protocol_agents.hpp"
#include <stdexcept>

namespace telemetry {
DeviceAgent::DeviceAgent(std::string deviceId, EccIdentity identity)
    : deviceId_(std::move(deviceId)), identity_(std::move(identity)) {}

HelloMessage DeviceAgent::buildHello() {
    myEphemeralPublicKey_ = ephemeral_.publicKeyUncompressed();
    return HelloMessage{deviceId_, myEphemeralPublicKey_};
}

void DeviceAgent::completeHandshake(const HelloMessage& gatewayHello) {
    if (myEphemeralPublicKey_.empty()) {
        throw std::logic_error("DeviceAgent::completeHandshake: call buildHello() first");
    }
    Bytes transcript = handshakeTranscript(deviceId_, myEphemeralPublicKey_, gatewayHello.ephemeralPublicKey);
    sessionKey_ = ephemeral_.deriveSessionKey(gatewayHello.ephemeralPublicKey, transcript, handshakeHkdfInfo());
    handshakeComplete_ = true;
}

TelemetryEnvelope DeviceAgent::protect(const TelemetryPacket& packet) {
    if (!handshakeComplete_) {
        throw std::logic_error("DeviceAgent::protect: handshake not completed yet");
    }

    TelemetryEnvelope msg;
    msg.deviceId = deviceId_;
    msg.sequenceNumber = ++sequenceCounter_;

    EncryptedBlob blob =
        AesGcmCipher::encrypt(sessionKey_, packet.serialize(), makeTelemetryAad(msg.deviceId, msg.sequenceNumber));
    msg.nonce = std::move(blob.nonce);
    msg.ciphertext = std::move(blob.ciphertext);
    msg.tag = std::move(blob.tag);

    msg.signature = identity_.sign(msg.signedTranscript());
    return msg;
}

void GatewayAgent::registerTrustedDevice(const std::string& deviceId, const Bytes& longTermPublicKeyUncompressed) {
    trustedDevices_[deviceId] = longTermPublicKeyUncompressed;
}

bool GatewayAgent::isTrusted(const std::string& deviceId) const {
    return trustedDevices_.find(deviceId) != trustedDevices_.end();
}

HelloMessage GatewayAgent::acceptHello(const HelloMessage& deviceHello) {
    if (!isTrusted(deviceHello.deviceId)) {
        throw SecurityException("GatewayAgent: rejected Hello from unregistered device '" + deviceHello.deviceId +
                                 "'");
    }

    EphemeralKeyPair serverEphemeral;
    Bytes serverPub = serverEphemeral.publicKeyUncompressed();

    Bytes transcript = handshakeTranscript(deviceHello.deviceId, deviceHello.ephemeralPublicKey, serverPub);
    SessionState state;
    state.key = serverEphemeral.deriveSessionKey(deviceHello.ephemeralPublicKey, transcript, handshakeHkdfInfo());
    state.lastSequence = 0;
    sessions_[deviceHello.deviceId] = state;

    return HelloMessage{std::string(), serverPub};
}

TelemetryPacket GatewayAgent::unprotect(const TelemetryEnvelope& msg) {
    auto deviceIt = trustedDevices_.find(msg.deviceId);
    if (deviceIt == trustedDevices_.end()) {
        throw SecurityException("GatewayAgent: message from unregistered device '" + msg.deviceId + "'");
    }

    if (!EccIdentity::verify(deviceIt->second, msg.signedTranscript(), msg.signature)) {
        throw SecurityException("GatewayAgent: ECDSA signature verification failed for device '" + msg.deviceId +
                                 "'");
    }

    auto sessionIt = sessions_.find(msg.deviceId);
    if (sessionIt == sessions_.end()) {
        throw SecurityException("GatewayAgent: no active session for device '" + msg.deviceId +
                                 "' (handshake required first)");
    }

    if (msg.sequenceNumber <= sessionIt->second.lastSequence) {
        throw SecurityException("GatewayAgent: sequence number " + std::to_string(msg.sequenceNumber) +
                                 " did not increase past last accepted " +
                                 std::to_string(sessionIt->second.lastSequence) + " (replay?)");
    }

    EncryptedBlob blob{msg.nonce, msg.ciphertext, msg.tag};
    Bytes plaintext =
        AesGcmCipher::decrypt(sessionIt->second.key, blob, makeTelemetryAad(msg.deviceId, msg.sequenceNumber));

    sessionIt->second.lastSequence = msg.sequenceNumber;
    return TelemetryPacket::deserialize(plaintext);
}
}
