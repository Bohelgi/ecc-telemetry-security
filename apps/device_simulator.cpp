#include "telemetry/console_colors.hpp"
#include "telemetry/protocol_agents.hpp"
#include "telemetry/tcp_socket.hpp"
#include <httplib.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <thread>

using namespace telemetry;

namespace {
struct Args {
    std::string deviceId = "esp32-node-01";
    std::string host = "127.0.0.1";
    uint16_t port = 9443;
    std::string transport = "tcp";
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

class SensorSimulator {
public:
    TelemetryPacket next() {
        voltage_ += noise_(rng_) * 0.5f;
        voltage_ = std::clamp(voltage_, 215.0f, 245.0f);
        current_ += noise_(rng_) * 0.05f;
        current_ = std::clamp(current_, 0.5f, 8.0f);
        temperature_ += noise_(rng_) * 0.1f;
        temperature_ = std::clamp(temperature_, 18.0f, 45.0f);

        TelemetryPacket p;
        p.unixTimestampMs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        p.voltageV = voltage_;
        p.currentA = current_;
        p.powerW = voltage_ * current_;
        p.temperatureC = temperature_;
        return p;
    }

private:
    std::mt19937 rng_{std::random_device{}()};
    std::normal_distribution<float> noise_{0.0f, 1.0f};
    float voltage_ = 230.0f;
    float current_ = 3.0f;
    float temperature_ = 28.0f;
};
}

int main(int argc, char** argv) {
    std::cout << std::unitbuf;
    ansi::enable();
    try {
        Args args = parseArgs(argc, argv);
        bool attackUnknown = (args.attack == "unknown");
        EccIdentity identity = attackUnknown ? EccIdentity() : EccIdentity::loadOrCreate(args.keyFile);
        if (attackUnknown) {
            args.deviceId += "-unregistered-demo";
        }

        if (!args.exportIdentityTo.empty()) {
            std::ofstream out(args.exportIdentityTo, std::ios::app);
            out << args.deviceId << ' ' << toHex(identity.publicKeyUncompressed()) << '\n';
            std::cout << "Provisioned " << args.deviceId << ": " << toHex(identity.publicKeyUncompressed()) << "\n"
                      << "Add this line to the gateway's trust store (--trust-store) and rerun the device without "
                         "--export-identity.\n";
            return 0;
        }

        std::cout << "[device " << args.deviceId << "] long-term public key (ECDSA): "
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

        SensorSimulator sensor;
        for (int i = 0; args.count == 0 || i < args.count; ++i) {
            TelemetryPacket packet = sensor.next();
            TelemetryEnvelope msg = agent.protect(packet);

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

            std::cout << "[device] telemetry #" << msg.sequenceNumber << ": U=" << packet.voltageV
                      << "V I=" << packet.currentA << "A P=" << packet.powerW << "W T=" << packet.temperatureC
                      << "C\n"
                      << "         nonce=" << toHex(msg.nonce) << " tag=" << toHex(msg.tag) << "\n"
                      << "         ciphertext=" << toHex(msg.ciphertext) << "\n"
                      << "         ECDSA signature (" << msg.signature.size() << " bytes)=" << toHex(msg.signature)
                      << "\n";

            transport->sendTelemetry(msg);
            std::this_thread::sleep_for(std::chrono::milliseconds(args.intervalMs));
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[device] error: " << e.what() << "\n";
        return 1;
    }
}
