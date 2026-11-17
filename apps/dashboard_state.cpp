#include "dashboard_state.hpp"
#include "telemetry/support.hpp"
#include <algorithm>
#include <chrono>
#include <sstream>

using telemetry::jsonEscape;

namespace {
uint64_t nowMs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}

float valueOf(const TelemetryPoint& point, const std::string& name) {
    for (const auto& kv : point.values) {
        if (kv.first == name) return kv.second;
    }
    return 0.0f;
}
}

DeviceInfo* DashboardState::findDevice(const std::string& deviceId) {
    for (DeviceInfo& d : devices_) {
        if (d.id == deviceId) return &d;
    }
    return nullptr;
}

void DashboardState::registerDevice(const std::string& deviceId, const std::string& profileId) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (DeviceInfo* existing = findDevice(deviceId)) {
        existing->profileId = profileId;
        return;
    }
    DeviceInfo info;
    info.id = deviceId;
    info.profileId = profileId;
    devices_.push_back(std::move(info));
}

std::string DashboardState::profileOf(const std::string& deviceId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const DeviceInfo& d : devices_) {
        if (d.id == deviceId) return d.profileId;
    }
    return std::string();
}

void DashboardState::recordHandshake(const std::string& deviceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (std::find(connectedDevices_.begin(), connectedDevices_.end(), deviceId) == connectedDevices_.end()) {
        connectedDevices_.push_back(deviceId);
    }
    if (DeviceInfo* d = findDevice(deviceId)) d->lastSeenMs = nowMs();
}

void DashboardState::recordConnectionClosed(const std::string& deviceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    connectedDevices_.erase(std::remove(connectedDevices_.begin(), connectedDevices_.end(), deviceId),
                             connectedDevices_.end());
}

void DashboardState::recordAccepted(const TelemetryPoint& point) {
    std::lock_guard<std::mutex> lock(mutex_);
    telemetry_.push_back(point);
    if (telemetry_.size() > kMaxTelemetry) telemetry_.pop_front();

    events_.push_back(ProtocolEvent{point.timestampMs, point.deviceId, point.sequenceNumber, true, ""});
    if (events_.size() > kMaxEvents) events_.pop_front();

    if (DeviceInfo* d = findDevice(point.deviceId)) {
        ++d->accepted;
        d->lastSeenMs = nowMs();
    }
    ++totalAccepted_;
}

void DashboardState::recordRejected(const std::string& deviceId, uint32_t sequenceNumber, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back(ProtocolEvent{nowMs(), deviceId, sequenceNumber, false, reason});
    if (events_.size() > kMaxEvents) events_.pop_front();

    if (DeviceInfo* d = findDevice(deviceId)) {
        ++d->rejected;
        d->lastSeenMs = nowMs();
    }
    ++totalRejected_;
}

void DashboardState::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    telemetry_.clear();
    events_.clear();
    connectedDevices_.clear();
    for (DeviceInfo& d : devices_) {
        d.accepted = 0;
        d.rejected = 0;
        d.lastSeenMs = 0;
    }
    totalAccepted_ = 0;
    totalRejected_ = 0;
}

std::string DashboardState::statusJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream os;
    os << "{\"connectedDevices\":[";
    for (size_t i = 0; i < connectedDevices_.size(); ++i) {
        if (i) os << ",";
        os << "\"" << jsonEscape(connectedDevices_[i]) << "\"";
    }
    os << "],\"registeredDevices\":" << devices_.size() << ",\"totalAccepted\":" << totalAccepted_
       << ",\"totalRejected\":" << totalRejected_ << "}";
    return os.str();
}

std::string DashboardState::telemetryJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream os;
    os << "[";
    bool first = true;
    for (const TelemetryPoint& p : telemetry_) {
        if (p.profileId != "power-meter") continue;
        if (!first) os << ",";
        first = false;
        os << "{\"t\":" << p.timestampMs << ",\"device\":\"" << jsonEscape(p.deviceId) << "\",\"seq\":"
           << p.sequenceNumber << ",\"U\":" << valueOf(p, "voltage") << ",\"I\":" << valueOf(p, "current")
           << ",\"P\":" << valueOf(p, "power") << ",\"T\":" << valueOf(p, "temperature") << "}";
    }
    os << "]";
    return os.str();
}

std::string DashboardState::readingsJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream os;
    os << "[";
    for (size_t i = 0; i < telemetry_.size(); ++i) {
        const TelemetryPoint& p = telemetry_[i];
        if (i) os << ",";
        os << "{\"t\":" << p.timestampMs << ",\"device\":\"" << jsonEscape(p.deviceId) << "\",\"profile\":\""
           << jsonEscape(p.profileId) << "\",\"seq\":" << p.sequenceNumber << ",\"values\":{";
        for (size_t j = 0; j < p.values.size(); ++j) {
            if (j) os << ",";
            os << "\"" << jsonEscape(p.values[j].first) << "\":" << p.values[j].second;
        }
        os << "}}";
    }
    os << "]";
    return os.str();
}

std::string DashboardState::devicesJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream os;
    os << "[";
    for (size_t i = 0; i < devices_.size(); ++i) {
        const DeviceInfo& d = devices_[i];
        bool connected =
            std::find(connectedDevices_.begin(), connectedDevices_.end(), d.id) != connectedDevices_.end();
        if (i) os << ",";
        os << "{\"id\":\"" << jsonEscape(d.id) << "\",\"profile\":\"" << jsonEscape(d.profileId)
           << "\",\"connected\":" << (connected ? "true" : "false") << ",\"accepted\":" << d.accepted
           << ",\"rejected\":" << d.rejected << ",\"lastSeen\":" << d.lastSeenMs << "}";
    }
    os << "]";
    return os.str();
}

std::string DashboardState::eventsJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream os;
    os << "[";
    for (size_t i = 0; i < events_.size(); ++i) {
        const ProtocolEvent& e = events_[i];
        if (i) os << ",";
        os << "{\"t\":" << e.timestampMs << ",\"device\":\"" << jsonEscape(e.deviceId)
           << "\",\"seq\":" << e.sequenceNumber << ",\"status\":\"" << (e.accepted ? "accepted" : "rejected")
           << "\",\"detail\":\"" << jsonEscape(e.detail) << "\"}";
    }
    os << "]";
    return os.str();
}
