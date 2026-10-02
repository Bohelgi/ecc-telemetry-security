#pragma once
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

struct TelemetryPoint {
    uint64_t timestampMs = 0;
    std::string deviceId;
    uint32_t sequenceNumber = 0;
    float voltageV = 0.0f;
    float currentA = 0.0f;
    float powerW = 0.0f;
    float temperatureC = 0.0f;
};

struct ProtocolEvent {
    uint64_t timestampMs = 0;
    std::string deviceId;
    uint32_t sequenceNumber = 0;
    bool accepted = false;
    std::string detail;
};

class DashboardState {
public:
    void recordHandshake(const std::string& deviceId);
    void recordConnectionClosed(const std::string& deviceId);
    void recordAccepted(const TelemetryPoint& point);
    void recordRejected(const std::string& deviceId, uint32_t sequenceNumber, const std::string& reason);
    void reset();

    std::string statusJson() const;
    std::string telemetryJson() const;
    std::string eventsJson() const;

private:
    static constexpr size_t kMaxHistory = 200;

    mutable std::mutex mutex_;
    std::deque<TelemetryPoint> telemetry_;
    std::deque<ProtocolEvent> events_;
    std::vector<std::string> connectedDevices_;
    uint64_t totalAccepted_ = 0;
    uint64_t totalRejected_ = 0;
};
