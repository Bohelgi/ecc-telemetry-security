#pragma once
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

struct TelemetryPoint {
    uint64_t timestampMs = 0;
    std::string deviceId;
    std::string profileId;
    uint32_t sequenceNumber = 0;
    std::vector<std::pair<std::string, float>> values;
};

struct ProtocolEvent {
    uint64_t timestampMs = 0;
    std::string deviceId;
    uint32_t sequenceNumber = 0;
    bool accepted = false;
    std::string detail;
};

struct DeviceInfo {
    std::string id;
    std::string profileId;
    uint64_t accepted = 0;
    uint64_t rejected = 0;
    uint64_t lastSeenMs = 0;
};

class DashboardState {
public:
    void registerDevice(const std::string& deviceId, const std::string& profileId);
    std::string profileOf(const std::string& deviceId) const;

    void recordHandshake(const std::string& deviceId);
    void recordConnectionClosed(const std::string& deviceId);
    void recordAccepted(const TelemetryPoint& point);
    void recordRejected(const std::string& deviceId, uint32_t sequenceNumber, const std::string& reason);
    void reset();

    std::string statusJson() const;
    std::string telemetryJson() const;
    std::string readingsJson() const;
    std::string devicesJson() const;
    std::string eventsJson() const;

private:
    static constexpr size_t kMaxTelemetry = 600;
    static constexpr size_t kMaxEvents = 200;

    DeviceInfo* findDevice(const std::string& deviceId);

    mutable std::mutex mutex_;
    std::deque<TelemetryPoint> telemetry_;
    std::deque<ProtocolEvent> events_;
    std::vector<std::string> connectedDevices_;
    std::vector<DeviceInfo> devices_;
    uint64_t totalAccepted_ = 0;
    uint64_t totalRejected_ = 0;
};
