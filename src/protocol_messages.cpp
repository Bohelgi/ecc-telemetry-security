#include "telemetry/protocol_messages.hpp"

namespace telemetry {
Bytes TelemetryPacket::serialize() const {
    wire::Writer w;
    w.putU64(unixTimestampMs);
    w.putFloat(voltageV);
    w.putFloat(currentA);
    w.putFloat(powerW);
    w.putFloat(temperatureC);
    return w.take();
}

TelemetryPacket TelemetryPacket::deserialize(const Bytes& data) {
    wire::Reader r(data);
    TelemetryPacket p;
    p.unixTimestampMs = r.getU64();
    p.voltageV = r.getFloat();
    p.currentA = r.getFloat();
    p.powerW = r.getFloat();
    p.temperatureC = r.getFloat();
    return p;
}

Bytes HelloMessage::serialize() const {
    wire::Writer w;
    w.putString(deviceId);
    w.putBytes(ephemeralPublicKey);
    return w.take();
}

HelloMessage HelloMessage::deserialize(const Bytes& data) {
    wire::Reader r(data);
    HelloMessage m;
    m.deviceId = r.getString();
    m.ephemeralPublicKey = r.getBytes();
    return m;
}

Bytes TelemetryEnvelope::signedTranscript() const {
    wire::Writer w;
    w.putString(deviceId);
    w.putU32(sequenceNumber);
    w.putBytes(nonce);
    w.putBytes(ciphertext);
    w.putBytes(tag);
    return w.take();
}

Bytes TelemetryEnvelope::serialize() const {
    wire::Writer w;
    w.putString(deviceId);
    w.putU32(sequenceNumber);
    w.putBytes(nonce);
    w.putBytes(ciphertext);
    w.putBytes(tag);
    w.putBytes(signature);
    return w.take();
}

TelemetryEnvelope TelemetryEnvelope::deserialize(const Bytes& data) {
    wire::Reader r(data);
    TelemetryEnvelope m;
    m.deviceId = r.getString();
    m.sequenceNumber = r.getU32();
    m.nonce = r.getBytes();
    m.ciphertext = r.getBytes();
    m.tag = r.getBytes();
    m.signature = r.getBytes();
    return m;
}

Bytes makeTelemetryAad(const std::string& deviceId, uint32_t sequenceNumber) {
    wire::Writer w;
    w.putString(deviceId);
    w.putU32(sequenceNumber);
    return w.take();
}

Bytes handshakeTranscript(const std::string& deviceId, const Bytes& deviceEphemeralPublicKey,
                           const Bytes& gatewayEphemeralPublicKey) {
    wire::Writer w;
    w.putString(deviceId);
    w.putBytes(deviceEphemeralPublicKey);
    w.putBytes(gatewayEphemeralPublicKey);
    return w.take();
}

const Bytes& handshakeHkdfInfo() {
    static const Bytes info = {'s', 'e', 'c', 'u', 'r', 'e', '-', 't', 'e', 'l',
                                'e', 'm', 'e', 't', 'r', 'y', '-', 'v', '1'};
    return info;
}
}
