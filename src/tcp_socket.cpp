#include "telemetry/tcp_socket.hpp"
#include <stdexcept>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
static constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t kInvalidSocket = -1;
#endif

namespace telemetry {
namespace {
constexpr size_t kMaxFrameLen = 1u << 20;

#ifdef _WIN32
struct WinsockGuard {
    WinsockGuard() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("TcpSocket: WSAStartup failed");
        }
    }
    ~WinsockGuard() { WSACleanup(); }
};
void ensureNetworkInitialized() {
    static WinsockGuard guard;
    (void)guard;
}
inline void closeSocket(socket_t s) { closesocket(s); }
#else
void ensureNetworkInitialized() {}
inline void closeSocket(socket_t s) { close(s); }
#endif

inline socket_t toNative(std::intptr_t h) { return static_cast<socket_t>(h); }

void sendAll(socket_t s, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int chunk = send(s, reinterpret_cast<const char*>(data + sent), static_cast<int>(len - sent), 0);
        if (chunk <= 0) {
            throw std::runtime_error("TcpSocket: send() failed or peer closed the connection");
        }
        sent += static_cast<size_t>(chunk);
    }
}

void receiveAll(socket_t s, uint8_t* data, size_t len) {
    size_t received = 0;
    while (received < len) {
        int chunk = recv(s, reinterpret_cast<char*>(data + received), static_cast<int>(len - received), 0);
        if (chunk <= 0) {
            throw std::runtime_error("TcpSocket: recv() failed or peer closed the connection");
        }
        received += static_cast<size_t>(chunk);
    }
}
}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept : handle_(other.handle_) {
    other.handle_ = -1;
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
    if (this != &other) {
        if (handle_ != -1) closeSocket(toNative(handle_));
        handle_ = other.handle_;
        other.handle_ = -1;
    }
    return *this;
}

TcpSocket::~TcpSocket() {
    if (handle_ != -1) {
        closeSocket(toNative(handle_));
    }
}

TcpSocket TcpSocket::connectTo(const std::string& host, uint16_t port) {
    ensureNetworkInitialized();

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) != 0 || result == nullptr) {
        throw std::runtime_error("TcpSocket::connectTo: cannot resolve " + host);
    }

    socket_t s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (s == kInvalidSocket) {
        freeaddrinfo(result);
        throw std::runtime_error("TcpSocket::connectTo: socket() failed");
    }
    if (connect(s, result->ai_addr, static_cast<int>(result->ai_addrlen)) != 0) {
        freeaddrinfo(result);
        closeSocket(s);
        throw std::runtime_error("TcpSocket::connectTo: connect() to " + host + ":" + std::to_string(port) +
                                  " failed");
    }
    freeaddrinfo(result);
    return TcpSocket(static_cast<std::intptr_t>(s));
}

TcpSocket TcpSocket::listenAndAcceptOnce(uint16_t port) {
    ensureNetworkInitialized();

    socket_t listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == kInvalidSocket) {
        throw std::runtime_error("TcpSocket::listenAndAcceptOnce: socket() failed");
    }

    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closeSocket(listener);
        throw std::runtime_error("TcpSocket::listenAndAcceptOnce: bind() on port " + std::to_string(port) +
                                  " failed (already in use?)");
    }
    if (listen(listener, 1) != 0) {
        closeSocket(listener);
        throw std::runtime_error("TcpSocket::listenAndAcceptOnce: listen() failed");
    }

    socket_t client = accept(listener, nullptr, nullptr);
    closeSocket(listener);
    if (client == kInvalidSocket) {
        throw std::runtime_error("TcpSocket::listenAndAcceptOnce: accept() failed");
    }
    return TcpSocket(static_cast<std::intptr_t>(client));
}

void TcpSocket::sendFramed(const Bytes& payload) const {
    uint8_t header[4] = {
        static_cast<uint8_t>((payload.size() >> 24) & 0xFF),
        static_cast<uint8_t>((payload.size() >> 16) & 0xFF),
        static_cast<uint8_t>((payload.size() >> 8) & 0xFF),
        static_cast<uint8_t>(payload.size() & 0xFF),
    };
    socket_t s = toNative(handle_);
    sendAll(s, header, sizeof(header));
    if (!payload.empty()) {
        sendAll(s, payload.data(), payload.size());
    }
}

Bytes TcpSocket::receiveFramed() const {
    socket_t s = toNative(handle_);
    uint8_t header[4];
    receiveAll(s, header, sizeof(header));
    uint32_t len = (static_cast<uint32_t>(header[0]) << 24) | (static_cast<uint32_t>(header[1]) << 16) |
                   (static_cast<uint32_t>(header[2]) << 8) | static_cast<uint32_t>(header[3]);
    if (len > kMaxFrameLen) {
        throw std::runtime_error("TcpSocket::receiveFramed: frame length " + std::to_string(len) +
                                  " exceeds sanity limit");
    }

    Bytes payload(len);
    if (len > 0) {
        receiveAll(s, payload.data(), len);
    }
    return payload;
}
}
