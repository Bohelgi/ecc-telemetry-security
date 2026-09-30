#pragma once
#include "telemetry/support.hpp"
#include <cstdint>
#include <string>

namespace telemetry {
class TcpSocket {
public:
    TcpSocket(TcpSocket&& other) noexcept;
    TcpSocket& operator=(TcpSocket&& other) noexcept;
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;
    ~TcpSocket();

    static TcpSocket connectTo(const std::string& host, uint16_t port);
    static TcpSocket listenAndAcceptOnce(uint16_t port);

    void sendFramed(const Bytes& payload) const;
    Bytes receiveFramed() const;

private:
    explicit TcpSocket(std::intptr_t nativeHandle) : handle_(nativeHandle) {}

    std::intptr_t handle_;
};
}
