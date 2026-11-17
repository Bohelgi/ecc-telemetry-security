#pragma once
#include "telemetry/protocol_messages.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace telemetry {
struct FieldSpec {
    std::string name;
    std::string label;
    std::string unit;
    float min = 0.0f;
    float max = 1.0f;
    bool isState = false;
    std::string offLabel;
    std::string onLabel;
};

struct DeviceProfile {
    std::string id;
    std::string title;
    std::vector<FieldSpec> fields;
};

class ProfileRegistry {
public:
    static ProfileRegistry withBuiltins();

    void add(DeviceProfile profile);
    size_t loadFile(const std::filesystem::path& path);
    const DeviceProfile* find(const std::string& id) const;
    const std::vector<DeviceProfile>& all() const { return profiles_; }

    std::string validate(const Reading& reading, const std::string& expectedProfileId) const;
    std::string toJson() const;

private:
    std::vector<DeviceProfile> profiles_;
};

std::string describeValues(const DeviceProfile& profile, const std::vector<float>& values);
}
