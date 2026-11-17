#include "telemetry/console_colors.hpp"
#include "telemetry/profiles.hpp"
#include "telemetry/protocol_agents.hpp"
#include <cmath>
#include <filesystem>
#include <fstream>
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

void testSequenceAdvances() {
    auto pair = freshHandshakedPair();
    for (int i = 0; i < 5; ++i) {
        TelemetryEnvelope msg = pair.device.protect(samplePacket());
        check(msg.sequenceNumber == static_cast<uint32_t>(i + 1), "sequence numbers increase monotonically");
        pair.gateway.unprotect(msg);
    }
}

void testTamperRejected() {
    auto pair = freshHandshakedPair();
    TelemetryEnvelope msg = pair.device.protect(samplePacket());
    msg.ciphertext[0] ^= 0xFF;

    check(throwsSecurityException([&] { pair.gateway.unprotect(msg); }),
          "tampered ciphertext is rejected (ECDSA signature covers ciphertext, checked before AES-GCM)");
}

void testReplayRejected() {
    auto pair = freshHandshakedPair();
    TelemetryEnvelope msg = pair.device.protect(samplePacket());

    pair.gateway.unprotect(msg);
    check(throwsSecurityException([&] { pair.gateway.unprotect(msg); }),
          "replaying an already-accepted message is rejected (sequence number check)");
}

void testForgedSigRejected() {
    auto pair = freshHandshakedPair("victim-device");
    TelemetryEnvelope msg = pair.device.protect(samplePacket());

    EccIdentity attacker;
    msg.signature = attacker.sign(msg.signedTranscript());

    check(throwsSecurityException([&] { pair.gateway.unprotect(msg); }),
          "a message signed by the wrong identity is rejected (ECDSA verification)");
}

void testUnknownDevice() {
    GatewayAgent gateway;
    EccIdentity identity;
    DeviceAgent impostor("nobody-registered-me", std::move(identity));

    HelloMessage hello = impostor.buildHello();
    check(throwsSecurityException([&] { gateway.acceptHello(hello); }),
          "Hello from an unregistered device id is rejected before any key exchange");
}

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

Reading sampleLampReading() {
    Reading r;
    r.unixTimestampMs = 1'726'000'000'000ULL;
    r.profileId = "smart-lamp";
    r.values = {1.0f, 80.0f, 8.0f};
    return r;
}

void testReadingRoundTrip() {
    auto pair = freshHandshakedPair("lamp-01");
    Reading original = sampleLampReading();

    Reading recovered = pair.gateway.unprotectReading(pair.device.protect(original));

    check(recovered.profileId == original.profileId && recovered.unixTimestampMs == original.unixTimestampMs &&
              recovered.values == original.values,
          "generic reading of another device profile survives encrypt/decrypt");
}

void testReadingTamperRejected() {
    auto pair = freshHandshakedPair("lamp-01");
    TelemetryEnvelope msg = pair.device.protect(sampleLampReading());
    msg.ciphertext[0] ^= 0x01;

    check(throwsSecurityException([&] { pair.gateway.unprotectReading(msg); }),
          "tampered generic reading is rejected the same way as a power-meter packet");
}

void testProfileValidation() {
    ProfileRegistry registry = ProfileRegistry::withBuiltins();
    Reading good = sampleLampReading();
    check(registry.validate(good, "smart-lamp").empty(), "valid lamp reading passes profile validation");

    Reading outOfRange = good;
    outOfRange.values[1] = 250.0f;
    check(!registry.validate(outOfRange, "smart-lamp").empty(), "value outside the profile range is rejected");

    Reading notANumber = good;
    notANumber.values[2] = std::nanf("");
    check(!registry.validate(notANumber, "smart-lamp").empty(), "NaN value is rejected");

    check(!registry.validate(good, "power-meter").empty(),
          "device registered as power-meter cannot send smart-lamp readings");

    Reading shortReading = good;
    shortReading.values.pop_back();
    check(!registry.validate(shortReading, "smart-lamp").empty(), "wrong number of values is rejected");
}

void testBuiltinProfilesAreConsistent() {
    ProfileRegistry registry = ProfileRegistry::withBuiltins();
    bool ok = registry.all().size() >= 5;
    for (const DeviceProfile& p : registry.all()) {
        for (const FieldSpec& f : p.fields) {
            ok = ok && f.min < f.max && !f.name.empty();
        }
    }
    check(ok, "built-in device profiles have unique ids and valid field ranges");

    bool duplicateRejected = false;
    try {
        registry.add(*registry.find("smart-lamp"));
    } catch (const std::invalid_argument&) {
        duplicateRejected = true;
    }
    check(duplicateRejected, "registering a duplicate profile id is refused");
}

void testProfileFileLoading() {
    std::filesystem::path path = std::filesystem::temp_directory_path() / "telemetry_test_profiles.txt";
    {
        std::ofstream out(path);
        out << "# custom\n"
            << "profile water-meter Лічильник_води\n"
            << "field flow Витрата л/хв 0 200\n"
            << "field leak Витік =Немає/Є 0 1\n";
    }

    ProfileRegistry registry = ProfileRegistry::withBuiltins();
    size_t added = registry.loadFile(path);
    std::filesystem::remove(path);

    const DeviceProfile* p = registry.find("water-meter");
    bool shapeOk = p != nullptr && p->fields.size() == 2 && p->title == "Лічильник води" && p->fields[1].isState &&
                   p->fields[1].onLabel == "Є";
    check(added == 1 && shapeOk, "custom device profile is loaded from a text file without code changes");

    Reading r;
    r.profileId = "water-meter";
    r.values = {42.5f, 0.0f};
    check(registry.validate(r, "water-meter").empty(), "reading of a file-defined profile passes validation");
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
    testReadingRoundTrip();
    testReadingTamperRejected();
    testProfileValidation();
    testBuiltinProfilesAreConsistent();
    testProfileFileLoading();

    std::cout << "\n" << (g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << " (" << g_failures
              << " failures)\n";
    return g_failures == 0 ? 0 : 1;
}
