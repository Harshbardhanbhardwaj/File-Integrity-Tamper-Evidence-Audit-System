// types.hpp - shared basic types.
#pragma once
#include <array>
#include <cstdint>
#include <string>

namespace fia {

using Digest = std::array<std::uint8_t, 32>;

// Numeric values match enum fia_event_type in driver/fiaudit_ioctl.h
enum class EventType : std::uint32_t {
    Heartbeat = 0,
    Create    = 1,
    Modify    = 2,
    Delete    = 3,
    Attrib    = 4,
    Move      = 5,
    Scan      = 6,
    Tamper    = 7,
};

const char* to_string(EventType t) noexcept;
bool event_type_from_string(const std::string& s, EventType& out) noexcept;

constexpr const char* kVersion = "1.0.0";
constexpr const char* kDefaultDevice = "/dev/fiaudit";

} // namespace fia
