#include "dashboard_state.hpp"
#include <algorithm>
#include <chrono>
#include <sstream>

namespace {
uint64_t nowMs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            default: out += c;
        }
    }
    return out;
}
}

void DashboardState::recordHandshake(const std::string& deviceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (std::find(connectedDevices_.begin(), connectedDevices_.end(), deviceId) == connectedDevices_.end()) {
        connectedDevices_.push_back(deviceId);
    }
}

void DashboardState::recordConnectionClosed(const std::string& deviceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    connectedDevices_.erase(std::remove(connectedDevices_.begin(), connectedDevices_.end(), deviceId),
                             connectedDevices_.end());
}

void DashboardState::recordAccepted(const TelemetryPoint& point) {
    std::lock_guard<std::mutex> lock(mutex_);
    telemetry_.push_back(point);
    if (telemetry_.size() > kMaxHistory) telemetry_.pop_front();

    events_.push_back(ProtocolEvent{point.timestampMs, point.deviceId, point.sequenceNumber, true, ""});
    if (events_.size() > kMaxHistory) events_.pop_front();

    ++totalAccepted_;
}

void DashboardState::recordRejected(const std::string& deviceId, uint32_t sequenceNumber, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back(ProtocolEvent{nowMs(), deviceId, sequenceNumber, false, reason});
    if (events_.size() > kMaxHistory) events_.pop_front();

    ++totalRejected_;
}

void DashboardState::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    telemetry_.clear();
    events_.clear();
    connectedDevices_.clear();
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
    os << "],\"totalAccepted\":" << totalAccepted_ << ",\"totalRejected\":" << totalRejected_ << "}";
    return os.str();
}

std::string DashboardState::telemetryJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream os;
    os << "[";
    for (size_t i = 0; i < telemetry_.size(); ++i) {
        const TelemetryPoint& p = telemetry_[i];
        if (i) os << ",";
        os << "{\"t\":" << p.timestampMs << ",\"device\":\"" << jsonEscape(p.deviceId) << "\",\"seq\":"
           << p.sequenceNumber << ",\"U\":" << p.voltageV << ",\"I\":" << p.currentA << ",\"P\":" << p.powerW
           << ",\"T\":" << p.temperatureC << "}";
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
