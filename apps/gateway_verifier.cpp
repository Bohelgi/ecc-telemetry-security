#include "dashboard_state.hpp"
#include "telemetry/console_colors.hpp"
#include "telemetry/profiles.hpp"
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
    std::filesystem::path profilesFile;
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
        else if (arg == "--profiles") a.profilesFile = next("--profiles");
        else throw std::runtime_error("unknown argument: " + arg);
    }
    return a;
}

struct Context {
    GatewayAgent& gateway;
    std::mutex& gatewayMutex;
    DashboardState& dashboard;
    const ProfileRegistry& profiles;
};

size_t loadTrustStore(const std::filesystem::path& path, Context& ctx) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("cannot open trust store: " + path.string());
    }
    size_t loaded = 0;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ls(line);
        std::string deviceId, pubKeyHex, profileId;
        if (!(ls >> deviceId >> pubKeyHex)) continue;
        if (!(ls >> profileId)) profileId = "power-meter";
        if (ctx.profiles.find(profileId) == nullptr) {
            throw std::runtime_error("trust store: unknown profile '" + profileId + "' for device '" + deviceId +
                                      "'");
        }
        ctx.gateway.registerTrustedDevice(deviceId, fromHex(pubKeyHex));
        ctx.dashboard.registerDevice(deviceId, profileId);
        ++loaded;
    }
    return loaded;
}

std::string process(Context& ctx, const TelemetryEnvelope& msg, const char* channel) {
    try {
        Reading reading;
        {
            std::lock_guard<std::mutex> lock(ctx.gatewayMutex);
            reading = ctx.gateway.unprotectReading(msg);
        }

        std::string problem = ctx.profiles.validate(reading, ctx.dashboard.profileOf(msg.deviceId));
        if (!problem.empty()) {
            throw SecurityException(problem);
        }
        const DeviceProfile* profile = ctx.profiles.find(reading.profileId);

        TelemetryPoint point;
        point.timestampMs = reading.unixTimestampMs;
        point.deviceId = msg.deviceId;
        point.profileId = reading.profileId;
        point.sequenceNumber = msg.sequenceNumber;
        for (size_t i = 0; i < profile->fields.size(); ++i) {
            point.values.emplace_back(profile->fields[i].name, reading.values[i]);
        }
        ctx.dashboard.recordAccepted(point);

        std::cout << ansi::green << "[" << channel << "] ACCEPTED #" << msg.sequenceNumber << " from '"
                  << msg.deviceId << "' (" << profile->id << "): " << describeValues(*profile, reading.values)
                  << ansi::reset << "\n";
        return std::string();
    } catch (const SecurityException& e) {
        std::cout << ansi::red << "[" << channel << "] REJECTED #" << msg.sequenceNumber << " from '" << msg.deviceId
                  << "': " << e.what() << ansi::reset << "\n";
        ctx.dashboard.recordRejected(msg.deviceId, msg.sequenceNumber, e.what());
        return e.what();
    }
}

void runHttpServer(uint16_t httpPort, Context& ctx) {
    httplib::Server server;
    server.set_mount_point("/", DASHBOARD_WEB_DIR);
    server.set_default_headers({{"Access-Control-Allow-Origin", "*"},
                                 {"Access-Control-Allow-Methods", "GET, POST, OPTIONS"},
                                 {"Access-Control-Allow-Headers", "Content-Type"}});
    server.Options(".*", [](const httplib::Request&, httplib::Response& res) { res.status = 204; });

    server.Get("/api/status", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(ctx.dashboard.statusJson(), "application/json");
    });
    server.Post("/api/reset", [&](const httplib::Request&, httplib::Response& res) {
        ctx.dashboard.reset();
        res.set_content("{\"ok\":true}", "application/json");
    });
    server.Get("/api/telemetry", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(ctx.dashboard.telemetryJson(), "application/json");
    });
    server.Get("/api/readings", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(ctx.dashboard.readingsJson(), "application/json");
    });
    server.Get("/api/devices", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(ctx.dashboard.devicesJson(), "application/json");
    });
    server.Get("/api/profiles", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(ctx.profiles.toJson(), "application/json");
    });
    server.Get("/api/events", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(ctx.dashboard.eventsJson(), "application/json");
    });

    server.Post("/api/handshake/hello", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            Bytes body(req.body.begin(), req.body.end());
            HelloMessage deviceHello = HelloMessage::deserialize(body);
            std::cout << "[gateway/http] <- Hello from '" << deviceHello.deviceId << "'\n";

            HelloMessage myHello = [&] {
                std::lock_guard<std::mutex> lock(ctx.gatewayMutex);
                return ctx.gateway.acceptHello(deviceHello);
            }();
            ctx.dashboard.recordHandshake(deviceHello.deviceId);

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
        try {
            Bytes body(req.body.begin(), req.body.end());
            TelemetryEnvelope msg = TelemetryEnvelope::deserialize(body);
            std::string reason = process(ctx, msg, "gateway/http");
            if (reason.empty()) {
                res.status = 200;
            } else {
                res.status = 403;
                res.set_content(reason, "text/plain");
            }
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(e.what(), "text/plain");
        }
    });

    std::cout << "[gateway] dashboard + HTTP ingest: http://localhost:" << httpPort << "\n";
    server.listen("0.0.0.0", httpPort);
}

void handleSession(TcpSocket socket, Context& ctx) {
    HelloMessage deviceHello = HelloMessage::deserialize(socket.receiveFramed());
    std::cout << "[gateway] <- Hello from '" << deviceHello.deviceId
              << "', ephemeral public key: " << toHex(deviceHello.ephemeralPublicKey) << "\n";

    HelloMessage myHello = [&] {
        std::lock_guard<std::mutex> lock(ctx.gatewayMutex);
        return ctx.gateway.acceptHello(deviceHello);
    }();
    std::cout << "[gateway] -> Hello, ephemeral public key: " << toHex(myHello.ephemeralPublicKey) << "\n";
    socket.sendFramed(myHello.serialize());
    std::cout << "[gateway] AES-256-GCM session key agreed for '" << deviceHello.deviceId << "'.\n\n";
    ctx.dashboard.recordHandshake(deviceHello.deviceId);

    while (true) {
        Bytes frame;
        try {
            frame = socket.receiveFramed();
        } catch (const std::exception&) {
            std::cout << "[gateway] connection with '" << deviceHello.deviceId << "' closed.\n";
            ctx.dashboard.recordConnectionClosed(deviceHello.deviceId);
            return;
        }

        TelemetryEnvelope msg = TelemetryEnvelope::deserialize(frame);
        process(ctx, msg, "gateway");
    }
}
}

int main(int argc, char** argv) {
    std::cout << std::unitbuf;
    ansi::enable();
    try {
        Args args = parseArgs(argc, argv);

        ProfileRegistry profiles = ProfileRegistry::withBuiltins();
        if (!args.profilesFile.empty()) {
            size_t added = profiles.loadFile(args.profilesFile);
            std::cout << "[gateway] custom profiles loaded: " << added << "\n";
        }

        GatewayAgent gateway;
        std::mutex gatewayMutex;
        DashboardState dashboard;
        Context ctx{gateway, gatewayMutex, dashboard, profiles};

        size_t loaded = loadTrustStore(args.trustStore, ctx);
        std::cout << "[gateway] device profiles available: " << profiles.all().size() << "\n";
        std::cout << "[gateway] trusted devices loaded: " << loaded << "\n";
        std::cout << "[gateway] TCP listener on port " << args.port << " ...\n";

        std::thread httpThread(runHttpServer, args.httpPort, std::ref(ctx));
        httpThread.detach();

        std::cout << "\n";
        while (true) {
            TcpSocket socket = TcpSocket::listenAndAcceptOnce(args.port);
            std::cout << "[gateway] new TCP connection accepted.\n";
            try {
                handleSession(std::move(socket), ctx);
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
