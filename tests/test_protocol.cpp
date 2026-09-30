#include "telemetry/console_colors.hpp"
#include "telemetry/protocol_agents.hpp"
#include <cmath>
#include <iostream>
#include <string>

using namespace telemetry;

namespace {
int g_failures = 0;

void check(bool condition, const std::string& testName, const std::string& detail = "") {
    if (condition) {
        std::cout << ansi::green << "[PASS] " << testName << ansi::reset << "\n";
    } else {
        std::cout << ansi::red << "[FAIL] " << testName;
        if (!detail.empty()) std::cout << " -- " << detail;
        std::cout << ansi::reset << "\n";
        ++g_failures;
    }
}

template <typename Fn>
bool throwsSecurityException(Fn&& fn) {
    try {
        fn();
    } catch (const SecurityException&) {
        return true;
    } catch (const std::exception&) {
        return false;
    }
    return false;
}

bool nearlyEqual(float a, float b) { return std::fabs(a - b) < 1e-3f; }

struct HandshakedPair {
    DeviceAgent device;
    GatewayAgent gateway;
};

HandshakedPair freshHandshakedPair(const std::string& deviceId = "test-device") {
    EccIdentity identity;
    Bytes pubKey = identity.publicKeyUncompressed();

    DeviceAgent device(deviceId, std::move(identity));
    GatewayAgent gateway;
    gateway.registerTrustedDevice(deviceId, pubKey);

    HelloMessage deviceHello = device.buildHello();
    HelloMessage gatewayHello = gateway.acceptHello(deviceHello);
    device.completeHandshake(gatewayHello);

    return HandshakedPair{std::move(device), std::move(gateway)};
}

TelemetryPacket samplePacket() {
    TelemetryPacket p;
    p.unixTimestampMs = 1'726'000'000'000ULL;
    p.voltageV = 231.4f;
    p.currentA = 2.87f;
    p.powerW = 664.1f;
    p.temperatureC = 33.2f;
    return p;
}

// Базовий сценарій: зашифрували, передали, розшифрували - числа збіглись.
void testRoundTrip() {
    auto pair = freshHandshakedPair();
    TelemetryPacket original = samplePacket();

    TelemetryEnvelope protectedMsg = pair.device.protect(original);
    TelemetryPacket recovered = pair.gateway.unprotect(protectedMsg);

    check(nearlyEqual(recovered.voltageV, original.voltageV) && nearlyEqual(recovered.currentA, original.currentA) &&
              nearlyEqual(recovered.powerW, original.powerW) &&
              nearlyEqual(recovered.temperatureC, original.temperatureC) &&
              recovered.unixTimestampMs == original.unixTimestampMs,
          "happy path: decrypted telemetry matches the original sample");
}

// Кілька повідомлень поспіль - номери мають зростати без пропусків.
void testSequenceAdvances() {
    auto pair = freshHandshakedPair();
    for (int i = 0; i < 5; ++i) {
        TelemetryEnvelope msg = pair.device.protect(samplePacket());
        check(msg.sequenceNumber == static_cast<uint32_t>(i + 1), "sequence numbers increase monotonically");
        pair.gateway.unprotect(msg);
    }
}

// Підміна шифротексту в польоті (MITM) - шлюз має це виявити.
void testTamperRejected() {
    auto pair = freshHandshakedPair();
    TelemetryEnvelope msg = pair.device.protect(samplePacket());
    msg.ciphertext[0] ^= 0xFF;

    check(throwsSecurityException([&] { pair.gateway.unprotect(msg); }),
          "tampered ciphertext is rejected (ECDSA signature covers ciphertext, checked before AES-GCM)");
}

// Повторне надсилання того самого пакета (replay) - шлюз має відхилити.
void testReplayRejected() {
    auto pair = freshHandshakedPair();
    TelemetryEnvelope msg = pair.device.protect(samplePacket());

    pair.gateway.unprotect(msg);
    check(throwsSecurityException([&] { pair.gateway.unprotect(msg); }),
          "replaying an already-accepted message is rejected (sequence number check)");
}

// Підпис чужим ключем - ECDSA-перевірка має провалитись.
void testForgedSigRejected() {
    auto pair = freshHandshakedPair("victim-device");
    TelemetryEnvelope msg = pair.device.protect(samplePacket());

    EccIdentity attacker;
    msg.signature = attacker.sign(msg.signedTranscript());

    check(throwsSecurityException([&] { pair.gateway.unprotect(msg); }),
          "a message signed by the wrong identity is rejected (ECDSA verification)");
}

// Hello від незареєстрованого пристрою - відхиляється до обміну ключами.
void testUnknownDevice() {
    GatewayAgent gateway;
    EccIdentity identity;
    DeviceAgent impostor("nobody-registered-me", std::move(identity));

    HelloMessage hello = impostor.buildHello();
    check(throwsSecurityException([&] { gateway.acceptHello(hello); }),
          "Hello from an unregistered device id is rejected before any key exchange");
}

// Серіалізація/десеріалізація пакетів без втрати даних.
void testWireFormat() {
    TelemetryPacket p = samplePacket();
    TelemetryPacket p2 = TelemetryPacket::deserialize(p.serialize());
    check(nearlyEqual(p.voltageV, p2.voltageV) && p.unixTimestampMs == p2.unixTimestampMs,
          "TelemetryPacket::serialize/deserialize round-trips");

    HelloMessage h{"dev-x", Bytes{1, 2, 3, 4, 5}};
    HelloMessage h2 = HelloMessage::deserialize(h.serialize());
    check(h.deviceId == h2.deviceId && h.ephemeralPublicKey == h2.ephemeralPublicKey,
          "HelloMessage::serialize/deserialize round-trips");
}
}

int main() {
    ansi::enable();
    testRoundTrip();
    testSequenceAdvances();
    testTamperRejected();
    testReplayRejected();
    testForgedSigRejected();
    testUnknownDevice();
    testWireFormat();

    std::cout << "\n" << (g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << " (" << g_failures
              << " failures)\n";
    return g_failures == 0 ? 0 : 1;
}
