#include "telemetry/console_colors.hpp"
#include "telemetry/profiles.hpp"
#include "telemetry/protocol_agents.hpp"
#include "telemetry/tcp_socket.hpp"
#include <httplib.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace telemetry;

namespace {
struct Args {
    std::string deviceId = "esp32-node-01";
    std::string host = "127.0.0.1";
    uint16_t port = 9443;
    std::string transport = "tcp";
    std::string profile = "power-meter";
    std::string source = "sim";
    std::filesystem::path profilesFile;
    int intervalMs = 2000;
    int count = 0;
    std::filesystem::path keyFile = "device_identity.hex";
    std::filesystem::path exportIdentityTo;
    std::string attack = "none";
};

Args parseArgs(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&](const char* flag) -> std::string {
            if (i + 1 >= argc) throw std::runtime_error(std::string("missing value for ") + flag);
            return argv[++i];
        };
        if (arg == "--id") a.deviceId = next("--id");
        else if (arg == "--host") a.host = next("--host");
        else if (arg == "--port") a.port = static_cast<uint16_t>(std::stoi(next("--port")));
        else if (arg == "--transport") a.transport = next("--transport");
        else if (arg == "--profile") a.profile = next("--profile");
        else if (arg == "--source") a.source = next("--source");
        else if (arg == "--profiles") a.profilesFile = next("--profiles");
        else if (arg == "--interval") a.intervalMs = std::stoi(next("--interval"));
        else if (arg == "--count") a.count = std::stoi(next("--count"));
        else if (arg == "--key-file") a.keyFile = next("--key-file");
        else if (arg == "--export-identity") a.exportIdentityTo = next("--export-identity");
        else if (arg == "--attack") a.attack = next("--attack");
        else throw std::runtime_error("unknown argument: " + arg);
    }
    if (a.attack != "none" && a.attack != "tamper" && a.attack != "replay" && a.attack != "both" &&
        a.attack != "forge" && a.attack != "unknown") {
        throw std::runtime_error("unknown --attack '" + a.attack +
                                  "' (expected none|tamper|replay|both|forge|unknown)");
    }
    if (a.source != "sim" && a.source != "stdin") {
        throw std::runtime_error("unknown --source '" + a.source + "' (expected 'sim' or 'stdin')");
    }
    return a;
}

class ITransport {
public:
    virtual ~ITransport() = default;
    virtual HelloMessage exchangeHello(const HelloMessage& mine) = 0;
    virtual void sendTelemetry(const TelemetryEnvelope& msg) = 0;
};

class TcpTransport : public ITransport {
public:
    TcpTransport(const std::string& host, uint16_t port) : socket_(TcpSocket::connectTo(host, port)) {}

    HelloMessage exchangeHello(const HelloMessage& mine) override {
        socket_.sendFramed(mine.serialize());
        return HelloMessage::deserialize(socket_.receiveFramed());
    }

    void sendTelemetry(const TelemetryEnvelope& msg) override { socket_.sendFramed(msg.serialize()); }

private:
    TcpSocket socket_;
};

class HttpTransport : public ITransport {
public:
    HttpTransport(const std::string& host, uint16_t port) : client_(host, port) {
        client_.set_connection_timeout(5);
        client_.set_read_timeout(5);
    }

    HelloMessage exchangeHello(const HelloMessage& mine) override {
        Bytes payload = mine.serialize();
        auto res = client_.Post("/api/handshake/hello", std::string(payload.begin(), payload.end()),
                                 "application/octet-stream");
        if (!res) {
            throw std::runtime_error("HTTP handshake: no response from gateway (" +
                                      httplib::to_string(res.error()) + ")");
        }
        if (res->status != 200) {
            throw std::runtime_error("HTTP handshake rejected (status " + std::to_string(res->status) +
                                      "): " + res->body);
        }
        Bytes body(res->body.begin(), res->body.end());
        return HelloMessage::deserialize(body);
    }

    void sendTelemetry(const TelemetryEnvelope& msg) override {
        Bytes payload = msg.serialize();
        auto res = client_.Post("/api/telemetry", std::string(payload.begin(), payload.end()),
                                 "application/octet-stream");
        if (!res) {
            throw std::runtime_error("HTTP telemetry: no response from gateway (" + httplib::to_string(res.error()) +
                                      ")");
        }
        if (res->status != 200) {
            std::cout << "[device] gateway rejected #" << msg.sequenceNumber << " over HTTP: " << res->body << "\n";
        }
    }

private:
    httplib::Client client_;
};

class IReadingSource {
public:
    virtual ~IReadingSource() = default;
    virtual bool poll(std::vector<float>& values) = 0;
    virtual bool exhausted() const { return false; }
};

class SimulatedSource : public IReadingSource {
protected:
    float walk(float value, float step, float lo, float hi) {
        return std::clamp(value + noise_(rng_) * step, lo, hi);
    }

    bool chance(float probability) { return uniform_(rng_) < probability; }

private:
    std::mt19937 rng_{std::random_device{}()};
    std::normal_distribution<float> noise_{0.0f, 1.0f};
    std::uniform_real_distribution<float> uniform_{0.0f, 1.0f};
};

class PowerMeterSource : public SimulatedSource {
public:
    bool poll(std::vector<float>& values) override {
        voltage_ = walk(voltage_, 0.5f, 215.0f, 245.0f);
        current_ = walk(current_, 0.05f, 0.5f, 8.0f);
        temperature_ = walk(temperature_, 0.1f, 18.0f, 45.0f);
        values = {voltage_, current_, voltage_ * current_, temperature_};
        return true;
    }

private:
    float voltage_ = 230.0f;
    float current_ = 3.0f;
    float temperature_ = 28.0f;
};

class SmartPlugSource : public SimulatedSource {
public:
    explicit SmartPlugSource(int intervalMs) : intervalMs_(intervalMs) {}

    bool poll(std::vector<float>& values) override {
        if (chance(0.04f)) on_ = !on_;
        power_ = walk(power_, 15.0f, 40.0f, 1800.0f);
        float reported = on_ ? power_ : 0.0f;
        energyKwh_ += static_cast<double>(reported) * intervalMs_ / 3.6e9;
        values = {reported, static_cast<float>(energyKwh_), on_ ? 1.0f : 0.0f};
        return true;
    }

private:
    int intervalMs_;
    bool on_ = true;
    float power_ = 120.0f;
    double energyKwh_ = 12.4;
};

class ClimateSource : public SimulatedSource {
public:
    bool poll(std::vector<float>& values) override {
        temperature_ = walk(temperature_, 0.08f, 18.0f, 28.0f);
        humidity_ = walk(humidity_, 0.4f, 30.0f, 70.0f);
        values = {temperature_, humidity_};
        return true;
    }

private:
    float temperature_ = 22.5f;
    float humidity_ = 45.0f;
};

class LampSource : public SimulatedSource {
public:
    bool poll(std::vector<float>& values) override {
        if (chance(0.06f)) on_ = !on_;
        if (on_ && chance(0.15f)) brightness_ = std::round(walk(brightness_, 12.0f, 10.0f, 100.0f));
        float reported = on_ ? brightness_ : 0.0f;
        values = {on_ ? 1.0f : 0.0f, reported, reported * 0.1f};
        return true;
    }

private:
    bool on_ = false;
    float brightness_ = 60.0f;
};

class DoorSource : public SimulatedSource {
public:
    bool poll(std::vector<float>& values) override {
        ++ticks_;
        bool changed = chance(0.12f);
        if (changed) open_ = !open_;
        if (!changed && ticks_ % 15 != 0) return false;
        values = {open_ ? 1.0f : 0.0f};
        return true;
    }

private:
    bool open_ = false;
    int ticks_ = 0;
};

class StdinSource : public IReadingSource {
public:
    explicit StdinSource(size_t fieldCount) : fieldCount_(fieldCount) {}

    bool poll(std::vector<float>& values) override {
        std::string line;
        if (!std::getline(std::cin, line)) {
            done_ = true;
            return false;
        }
        std::istringstream ls(line);
        std::vector<float> parsed;
        float v;
        while (ls >> v) parsed.push_back(v);
        if (parsed.size() != fieldCount_) {
            std::cout << ansi::yellow << "[device] skipped input line: expected " << fieldCount_ << " values, got "
                      << parsed.size() << ansi::reset << "\n";
            return false;
        }
        values = std::move(parsed);
        return true;
    }

    bool exhausted() const override { return done_; }

private:
    size_t fieldCount_;
    bool done_ = false;
};

std::unique_ptr<IReadingSource> makeSource(const Args& args, const DeviceProfile& profile) {
    if (args.source == "stdin") return std::make_unique<StdinSource>(profile.fields.size());
    if (profile.id == "power-meter") return std::make_unique<PowerMeterSource>();
    if (profile.id == "smart-plug") return std::make_unique<SmartPlugSource>(args.intervalMs);
    if (profile.id == "climate-sensor") return std::make_unique<ClimateSource>();
    if (profile.id == "smart-lamp") return std::make_unique<LampSource>();
    if (profile.id == "door-sensor") return std::make_unique<DoorSource>();
    throw std::runtime_error("no built-in simulator for profile '" + profile.id + "', use --source stdin");
}

uint64_t nowMs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}
}

int main(int argc, char** argv) {
    std::cout << std::unitbuf;
    ansi::enable();
    try {
        Args args = parseArgs(argc, argv);

        ProfileRegistry profiles = ProfileRegistry::withBuiltins();
        if (!args.profilesFile.empty()) profiles.loadFile(args.profilesFile);
        const DeviceProfile* profile = profiles.find(args.profile);
        if (profile == nullptr) {
            throw std::runtime_error("unknown --profile '" + args.profile + "'");
        }

        bool attackUnknown = (args.attack == "unknown");
        EccIdentity identity = attackUnknown ? EccIdentity() : EccIdentity::loadOrCreate(args.keyFile);
        if (attackUnknown) {
            args.deviceId += "-unregistered-demo";
        }

        if (!args.exportIdentityTo.empty()) {
            std::ofstream out(args.exportIdentityTo, std::ios::app);
            out << args.deviceId << ' ' << toHex(identity.publicKeyUncompressed()) << ' ' << profile->id << '\n';
            std::cout << "Provisioned " << args.deviceId << " (" << profile->id
                      << "): " << toHex(identity.publicKeyUncompressed()) << "\n"
                      << "Add this line to the gateway's trust store (--trust-store) and rerun the device without "
                         "--export-identity.\n";
            return 0;
        }

        std::cout << "[device " << args.deviceId << "] profile: " << profile->id << ", long-term public key (ECDSA): "
                  << toHex(identity.publicKeyUncompressed()) << "\n";

        DeviceAgent agent(args.deviceId, std::move(identity));

        std::unique_ptr<ITransport> transport;
        if (args.transport == "tcp") {
            std::cout << "[device] connecting to " << args.host << ":" << args.port << " (TCP) ...\n";
            transport = std::make_unique<TcpTransport>(args.host, args.port);
        } else if (args.transport == "http") {
            std::cout << "[device] connecting to " << args.host << ":" << args.port << " (HTTP) ...\n";
            transport = std::make_unique<HttpTransport>(args.host, args.port);
        } else {
            throw std::runtime_error("unknown --transport '" + args.transport + "' (expected 'tcp' or 'http')");
        }

        if (args.attack != "none") {
            std::cout << ansi::yellow << "[device] ATTACK DEMO active: --attack " << args.attack << ansi::reset
                      << "\n\n";
        }

        HelloMessage myHello = agent.buildHello();
        std::cout << "[device] -> Hello, ephemeral ECDH public key: " << toHex(myHello.ephemeralPublicKey) << "\n";

        if (attackUnknown) {
            try {
                transport->exchangeHello(myHello);
                std::cout << ansi::red
                          << "[device] (demo) WARNING: gateway accepted an unregistered device - this should NOT "
                             "happen!"
                          << ansi::reset << "\n";
                return 1;
            } catch (const std::exception& e) {
                std::cout << ansi::green << "[device] (demo) gateway correctly rejected unregistered device '"
                          << args.deviceId << "': " << e.what() << ansi::reset << "\n";
                return 0;
            }
        }

        HelloMessage gatewayHello = transport->exchangeHello(myHello);
        std::cout << "[device] <- Hello from gateway, ephemeral public key: "
                  << toHex(gatewayHello.ephemeralPublicKey) << "\n";
        agent.completeHandshake(gatewayHello);
        std::cout << "[device] AES-256-GCM session key agreed via ECDH.\n\n";

        bool doTamper = (args.attack == "tamper" || args.attack == "both");
        bool doReplay = (args.attack == "replay" || args.attack == "both");
        bool doForge = (args.attack == "forge");
        EccIdentity attackerIdentity;

        std::unique_ptr<IReadingSource> source = makeSource(args, *profile);
        bool paced = (args.source == "sim");

        int sent = 0;
        while (args.count == 0 || sent < args.count) {
            std::vector<float> values;
            if (!source->poll(values)) {
                if (source->exhausted()) break;
                if (paced) std::this_thread::sleep_for(std::chrono::milliseconds(args.intervalMs));
                continue;
            }

            Reading reading;
            reading.unixTimestampMs = nowMs();
            reading.profileId = profile->id;
            reading.values = std::move(values);
            TelemetryEnvelope msg = agent.protect(reading);
            ++sent;

            if (doTamper && msg.sequenceNumber % 3 == 0) {
                msg.ciphertext[0] ^= 0xFF;
                std::cout << ansi::yellow << "[device] (demo) tampering with ciphertext of #" << msg.sequenceNumber
                           << ansi::reset << "\n";
            }
            if (doForge && msg.sequenceNumber % 3 == 0) {
                msg.signature = attackerIdentity.sign(msg.signedTranscript());
                std::cout << ansi::yellow << "[device] (demo) forging signature of #" << msg.sequenceNumber
                           << " with a foreign key" << ansi::reset << "\n";
            }
            if (doReplay && msg.sequenceNumber == 4) {
                std::cout << ansi::yellow << "[device] (demo) replaying #" << msg.sequenceNumber << " a second time"
                           << ansi::reset << "\n";
                transport->sendTelemetry(msg);
            }

            std::cout << "[device] telemetry #" << msg.sequenceNumber << ": "
                      << describeValues(*profile, reading.values) << "\n"
                      << "         nonce=" << toHex(msg.nonce) << " tag=" << toHex(msg.tag) << "\n"
                      << "         ciphertext=" << toHex(msg.ciphertext) << "\n"
                      << "         ECDSA signature (" << msg.signature.size() << " bytes)=" << toHex(msg.signature)
                      << "\n";

            transport->sendTelemetry(msg);
            if (paced) std::this_thread::sleep_for(std::chrono::milliseconds(args.intervalMs));
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[device] error: " << e.what() << "\n";
        return 1;
    }
}
