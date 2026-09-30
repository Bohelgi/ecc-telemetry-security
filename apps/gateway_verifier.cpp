#include "dashboard_state.hpp"
#include "telemetry/console_colors.hpp"
#include "telemetry/protocol_agents.hpp"
#include "telemetry/tcp_socket.hpp"
#include <httplib.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

using namespace telemetry;

namespace {
struct Args {
    uint16_t port = 9443;
    uint16_t httpPort = 8090;
    std::filesystem::path trustStore = "trust_store.txt";
};

Args parseArgs(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&](const char* flag) -> std::string {
            if (i + 1 >= argc) throw std::runtime_error(std::string("missing value for ") + flag);
            return argv[++i];
        };
        if (arg == "--port") a.port = static_cast<uint16_t>(std::stoi(next("--port")));
        else if (arg == "--http-port") a.httpPort = static_cast<uint16_t>(std::stoi(next("--http-port")));
        else if (arg == "--trust-store") a.trustStore = next("--trust-store");
        else throw std::runtime_error("unknown argument: " + arg);
    }
    return a;
}

size_t loadTrustStore(const std::filesystem::path& path, GatewayAgent& gateway) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("cannot open trust store: " + path.string());
    }
    size_t loaded = 0;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ls(line);
        std::string deviceId, pubKeyHex;
        if (!(ls >> deviceId >> pubKeyHex)) continue;
        gateway.registerTrustedDevice(deviceId, fromHex(pubKeyHex));
        ++loaded;
    }
    return loaded;
}

void recordAccepted(DashboardState& dashboard, const std::string& deviceId, uint32_t sequenceNumber,
                     const TelemetryPacket& packet) {
    TelemetryPoint point;
    point.timestampMs = packet.unixTimestampMs;
    point.deviceId = deviceId;
    point.sequenceNumber = sequenceNumber;
    point.voltageV = packet.voltageV;
    point.currentA = packet.currentA;
    point.powerW = packet.powerW;
    point.temperatureC = packet.temperatureC;
    dashboard.recordAccepted(point);
}

void runHttpServer(uint16_t httpPort, GatewayAgent& gateway, std::mutex& gatewayMutex, DashboardState& dashboard) {
    httplib::Server server;
    server.set_mount_point("/", DASHBOARD_WEB_DIR);
    // Дашборд команди звертається з іншого походження (localhost:5173 /
    // 77.47.192.6:5173) - без цього заголовка браузер блокує fetch() до /api/*.
    server.set_default_headers({{"Access-Control-Allow-Origin", "*"}});

    server.Get("/api/status", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(dashboard.statusJson(), "application/json");
    });
    server.Get("/api/telemetry", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(dashboard.telemetryJson(), "application/json");
    });
    server.Get("/api/events", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(dashboard.eventsJson(), "application/json");
    });

    server.Post("/api/handshake/hello", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            Bytes body(req.body.begin(), req.body.end());
            HelloMessage deviceHello = HelloMessage::deserialize(body);
            std::cout << "[gateway/http] <- Hello from '" << deviceHello.deviceId << "'\n";

            HelloMessage myHello = [&] {
                std::lock_guard<std::mutex> lock(gatewayMutex);
                return gateway.acceptHello(deviceHello);
            }();
            dashboard.recordHandshake(deviceHello.deviceId);

            Bytes out = myHello.serialize();
            res.set_content(std::string(out.begin(), out.end()), "application/octet-stream");
        } catch (const SecurityException& e) {
            std::cout << "[gateway/http] handshake rejected: " << e.what() << "\n";
            res.status = 403;
            res.set_content(e.what(), "text/plain");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(e.what(), "text/plain");
        }
    });

    server.Post("/api/telemetry", [&](const httplib::Request& req, httplib::Response& res) {
        TelemetryEnvelope msg;
        try {
            Bytes body(req.body.begin(), req.body.end());
            msg = TelemetryEnvelope::deserialize(body);

            TelemetryPacket packet = [&] {
                std::lock_guard<std::mutex> lock(gatewayMutex);
                return gateway.unprotect(msg);
            }();

            std::cout << ansi::green << "[gateway/http] ACCEPTED #" << msg.sequenceNumber << " from '"
                      << msg.deviceId << "': U=" << packet.voltageV << "V I=" << packet.currentA
                      << "A P=" << packet.powerW << "W T=" << packet.temperatureC << "C" << ansi::reset << "\n";
            recordAccepted(dashboard, msg.deviceId, msg.sequenceNumber, packet);
            res.status = 200;
        } catch (const SecurityException& e) {
            std::cout << ansi::red << "[gateway/http] REJECTED #" << msg.sequenceNumber << " from '"
                      << msg.deviceId << "': " << e.what() << ansi::reset << "\n";
            dashboard.recordRejected(msg.deviceId, msg.sequenceNumber, e.what());
            res.status = 403;
            res.set_content(e.what(), "text/plain");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(e.what(), "text/plain");
        }
    });

    std::cout << "[gateway] dashboard + HTTP ingest: http://localhost:" << httpPort << "\n";
    server.listen("0.0.0.0", httpPort);
}

void handleSession(TcpSocket socket, GatewayAgent& gateway, std::mutex& gatewayMutex, DashboardState& dashboard) {
    HelloMessage deviceHello = HelloMessage::deserialize(socket.receiveFramed());
    std::cout << "[gateway] <- Hello from '" << deviceHello.deviceId
              << "', ephemeral public key: " << toHex(deviceHello.ephemeralPublicKey) << "\n";

    HelloMessage myHello = [&] {
        std::lock_guard<std::mutex> lock(gatewayMutex);
        return gateway.acceptHello(deviceHello);
    }();
    std::cout << "[gateway] -> Hello, ephemeral public key: " << toHex(myHello.ephemeralPublicKey) << "\n";
    socket.sendFramed(myHello.serialize());
    std::cout << "[gateway] AES-256-GCM session key agreed for '" << deviceHello.deviceId << "'.\n\n";
    dashboard.recordHandshake(deviceHello.deviceId);

    while (true) {
        Bytes frame;
        try {
            frame = socket.receiveFramed();
        } catch (const std::exception&) {
            std::cout << "[gateway] connection with '" << deviceHello.deviceId << "' closed.\n";
            dashboard.recordConnectionClosed(deviceHello.deviceId);
            return;
        }

        TelemetryEnvelope msg = TelemetryEnvelope::deserialize(frame);
        try {
            TelemetryPacket packet = [&] {
                std::lock_guard<std::mutex> lock(gatewayMutex);
                return gateway.unprotect(msg);
            }();
            std::cout << ansi::green << "[gateway] ACCEPTED #" << msg.sequenceNumber << " from '" << msg.deviceId
                      << "': U=" << packet.voltageV << "V I=" << packet.currentA << "A P=" << packet.powerW
                      << "W T=" << packet.temperatureC << "C" << ansi::reset << "\n";
            recordAccepted(dashboard, msg.deviceId, msg.sequenceNumber, packet);
        } catch (const SecurityException& e) {
            std::cout << ansi::red << "[gateway] REJECTED #" << msg.sequenceNumber << " from '" << msg.deviceId
                      << "': " << e.what() << ansi::reset << "\n";
            dashboard.recordRejected(msg.deviceId, msg.sequenceNumber, e.what());
        }
    }
}
}

int main(int argc, char** argv) {
    std::cout << std::unitbuf;
    ansi::enable();
    try {
        Args args = parseArgs(argc, argv);
        GatewayAgent gateway;
        std::mutex gatewayMutex;
        size_t loaded = loadTrustStore(args.trustStore, gateway);
        std::cout << "[gateway] trusted devices loaded: " << loaded << "\n";
        std::cout << "[gateway] TCP listener on port " << args.port << " ...\n";

        DashboardState dashboard;
        std::thread httpThread(runHttpServer, args.httpPort, std::ref(gateway), std::ref(gatewayMutex),
                                std::ref(dashboard));
        httpThread.detach();

        std::cout << "\n";
        while (true) {
            TcpSocket socket = TcpSocket::listenAndAcceptOnce(args.port);
            std::cout << "[gateway] new TCP connection accepted.\n";
            try {
                handleSession(std::move(socket), gateway, gatewayMutex, dashboard);
            } catch (const SecurityException& e) {
                std::cout << "[gateway] session rejected: " << e.what() << "\n";
            } catch (const std::exception& e) {
                std::cout << "[gateway] session error: " << e.what() << "\n";
            }
            std::cout << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[gateway] fatal error: " << e.what() << "\n";
        return 1;
    }
}
