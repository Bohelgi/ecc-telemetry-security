#include "telemetry/profiles.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace telemetry {
namespace {
FieldSpec number(std::string name, std::string label, std::string unit, float min, float max) {
    FieldSpec f;
    f.name = std::move(name);
    f.label = std::move(label);
    f.unit = std::move(unit);
    f.min = min;
    f.max = max;
    return f;
}

FieldSpec state(std::string name, std::string label, std::string offLabel, std::string onLabel) {
    FieldSpec f;
    f.name = std::move(name);
    f.label = std::move(label);
    f.min = 0.0f;
    f.max = 1.0f;
    f.isState = true;
    f.offLabel = std::move(offLabel);
    f.onLabel = std::move(onLabel);
    return f;
}

std::string spaced(std::string s) {
    std::replace(s.begin(), s.end(), '_', ' ');
    return s;
}
}

ProfileRegistry ProfileRegistry::withBuiltins() {
    ProfileRegistry r;
    r.add({"power-meter",
           "Лічильник електроенергії",
           {number("voltage", "Напруга", "В", 150.0f, 300.0f), number("current", "Струм", "А", 0.0f, 40.0f),
            number("power", "Потужність", "Вт", 0.0f, 12000.0f),
            number("temperature", "Температура", "°C", -40.0f, 125.0f)}});
    r.add({"smart-plug",
           "Розумна розетка",
           {number("power", "Потужність", "Вт", 0.0f, 3600.0f),
            number("energy", "Спожита енергія", "кВт·год", 0.0f, 100000.0f),
            state("state", "Стан", "Вимкнено", "Увімкнено")}});
    r.add({"climate-sensor",
           "Датчик клімату",
           {number("temperature", "Температура", "°C", -40.0f, 85.0f),
            number("humidity", "Вологість", "%", 0.0f, 100.0f)}});
    r.add({"smart-lamp",
           "Розумна лампа",
           {state("state", "Стан", "Вимкнено", "Увімкнено"), number("brightness", "Яскравість", "%", 0.0f, 100.0f),
            number("power", "Потужність", "Вт", 0.0f, 100.0f)}});
    r.add({"door-sensor", "Датчик дверей", {state("open", "Двері", "Зачинено", "Відчинено")}});
    return r;
}

void ProfileRegistry::add(DeviceProfile profile) {
    if (profile.id.empty() || profile.fields.empty() || profile.fields.size() > 255) {
        throw std::invalid_argument("invalid device profile '" + profile.id + "'");
    }
    if (find(profile.id) != nullptr) {
        throw std::invalid_argument("duplicate device profile '" + profile.id + "'");
    }
    for (const FieldSpec& f : profile.fields) {
        if (f.name.empty() || !(f.min < f.max)) {
            throw std::invalid_argument("invalid field '" + f.name + "' in profile '" + profile.id + "'");
        }
    }
    profiles_.push_back(std::move(profile));
}

size_t ProfileRegistry::loadFile(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("cannot open profiles file: " + path.string());
    }

    std::vector<DeviceProfile> parsed;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;

        std::istringstream ls(line);
        std::string directive;
        ls >> directive;

        if (directive == "profile") {
            DeviceProfile p;
            std::string title;
            if (!(ls >> p.id >> title)) {
                throw std::runtime_error("bad profile line: " + line);
            }
            p.title = spaced(title);
            parsed.push_back(std::move(p));
        } else if (directive == "field") {
            if (parsed.empty()) {
                throw std::runtime_error("field before any profile: " + line);
            }
            FieldSpec f;
            std::string label, unit;
            if (!(ls >> f.name >> label >> unit >> f.min >> f.max)) {
                throw std::runtime_error("bad field line: " + line);
            }
            f.label = spaced(label);
            if (unit[0] == '=') {
                std::string states = unit.substr(1);
                size_t slash = states.find('/');
                if (slash == std::string::npos) {
                    throw std::runtime_error("state field needs =off/on labels: " + line);
                }
                f.isState = true;
                f.offLabel = spaced(states.substr(0, slash));
                f.onLabel = spaced(states.substr(slash + 1));
            } else if (unit != "-") {
                f.unit = spaced(unit);
            }
            parsed.back().fields.push_back(std::move(f));
        } else {
            throw std::runtime_error("unknown directive '" + directive + "' in profiles file");
        }
    }

    size_t count = parsed.size();
    for (DeviceProfile& p : parsed) {
        add(std::move(p));
    }
    return count;
}

const DeviceProfile* ProfileRegistry::find(const std::string& id) const {
    for (const DeviceProfile& p : profiles_) {
        if (p.id == id) return &p;
    }
    return nullptr;
}

std::string ProfileRegistry::validate(const Reading& reading, const std::string& expectedProfileId) const {
    if (reading.profileId != expectedProfileId) {
        return "profile mismatch: device is registered as '" + expectedProfileId + "' but sent '" +
               reading.profileId + "'";
    }
    const DeviceProfile* profile = find(reading.profileId);
    if (profile == nullptr) {
        return "unknown profile '" + reading.profileId + "'";
    }
    if (reading.values.size() != profile->fields.size()) {
        return "field count mismatch: profile '" + profile->id + "' expects " +
               std::to_string(profile->fields.size()) + " values, got " + std::to_string(reading.values.size());
    }
    for (size_t i = 0; i < profile->fields.size(); ++i) {
        float v = reading.values[i];
        const FieldSpec& f = profile->fields[i];
        if (!(v >= f.min && v <= f.max)) {
            std::ostringstream os;
            os << "value out of range: " << f.name << "=" << v << " not in [" << f.min << ", " << f.max << "]";
            return os.str();
        }
    }
    return std::string();
}

std::string ProfileRegistry::toJson() const {
    std::ostringstream os;
    os << "[";
    for (size_t i = 0; i < profiles_.size(); ++i) {
        const DeviceProfile& p = profiles_[i];
        if (i) os << ",";
        os << "{\"id\":\"" << jsonEscape(p.id) << "\",\"title\":\"" << jsonEscape(p.title) << "\",\"fields\":[";
        for (size_t j = 0; j < p.fields.size(); ++j) {
            const FieldSpec& f = p.fields[j];
            if (j) os << ",";
            os << "{\"name\":\"" << jsonEscape(f.name) << "\",\"label\":\"" << jsonEscape(f.label)
               << "\",\"unit\":\"" << jsonEscape(f.unit) << "\",\"min\":" << f.min << ",\"max\":" << f.max
               << ",\"state\":" << (f.isState ? "true" : "false") << ",\"off\":\"" << jsonEscape(f.offLabel)
               << "\",\"on\":\"" << jsonEscape(f.onLabel) << "\"}";
        }
        os << "]}";
    }
    os << "]";
    return os.str();
}

std::string describeValues(const DeviceProfile& profile, const std::vector<float>& values) {
    std::ostringstream os;
    for (size_t i = 0; i < profile.fields.size() && i < values.size(); ++i) {
        if (i) os << " ";
        os << profile.fields[i].name << "=" << values[i];
    }
    return os.str();
}
}
