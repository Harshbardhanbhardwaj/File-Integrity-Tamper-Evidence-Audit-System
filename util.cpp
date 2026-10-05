#include "fiaudit/util.hpp"

#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <mutex>

namespace fia {

const char* to_string(EventType t) noexcept {
    switch (t) {
        case EventType::Heartbeat: return "HEARTBEAT";
        case EventType::Create:    return "CREATE";
        case EventType::Modify:    return "MODIFY";
        case EventType::Delete:    return "DELETE";
        case EventType::Attrib:    return "ATTRIB";
        case EventType::Move:      return "MOVE";
        case EventType::Scan:      return "SCAN";
        case EventType::Tamper:    return "TAMPER";
    }
    return "UNKNOWN";
}

bool event_type_from_string(const std::string& s, EventType& out) noexcept {
    for (std::uint32_t i = 0; i <= 7; ++i) {
        if (s == to_string(static_cast<EventType>(i))) {
            out = static_cast<EventType>(i);
            return true;
        }
    }
    return false;
}

SysError::SysError(const std::string& what, int err)
    : std::runtime_error(what + ": " + std::strerror(err)), code_(err) {}

void Fd::reset(int fd) noexcept {
    if (fd_ >= 0) ::close(fd_);
    fd_ = fd;
}

std::string to_hex(const std::uint8_t* data, std::size_t len) {
    static const char* k = "0123456789abcdef";
    std::string s(len * 2, '0');
    for (std::size_t i = 0; i < len; ++i) {
        s[2 * i]     = k[data[i] >> 4];
        s[2 * i + 1] = k[data[i] & 0xF];
    }
    return s;
}
std::string to_hex(const Digest& d) { return to_hex(d.data(), d.size()); }

static int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool from_hex(const std::string& hex, std::uint8_t* out, std::size_t len) {
    if (hex.size() != len * 2) return false;
    for (std::size_t i = 0; i < len; ++i) {
        int hi = nibble(hex[2 * i]), lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

std::uint64_t now_real_ns() {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count());
}

std::string iso_time(std::uint64_t ns) {
    std::time_t sec = static_cast<std::time_t>(ns / 1000000000ULL);
    unsigned ms = static_cast<unsigned>((ns / 1000000ULL) % 1000);
    std::tm tm{};
    gmtime_r(&sec, &tm);
    char buf[96];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03uZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
    return buf;
}

std::string pct_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (c == '%' || c == '\t' || c == '\n' || c == '\r') {
            char b[4];
            std::snprintf(b, sizeof b, "%%%02X", c);
            out += b;
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

std::string pct_unescape(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() && nibble(s[i + 1]) >= 0 && nibble(s[i + 2]) >= 0) {
            out += static_cast<char>((nibble(s[i + 1]) << 4) | nibble(s[i + 2]));
            i += 2;
        } else {
            out += s[i];
        }
    }
    return out;
}

std::vector<std::string> split(std::string_view s, char sep) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (;;) {
        std::size_t p = s.find(sep, start);
        if (p == std::string_view::npos) {
            out.emplace_back(s.substr(start));
            return out;
        }
        out.emplace_back(s.substr(start, p - start));
        start = p + 1;
    }
}

bool glob_match(std::string_view p, std::string_view t) {
    // iterative matcher with backtracking on the last '*'
    std::size_t pi = 0, ti = 0, star = std::string_view::npos, mark = 0;
    while (ti < t.size()) {
        if (pi < p.size() && (p[pi] == '?' || p[pi] == t[ti])) { ++pi; ++ti; }
        else if (pi < p.size() && p[pi] == '*') { star = pi++; mark = ti; }
        else if (star != std::string_view::npos) { pi = star + 1; ti = ++mark; }
        else return false;
    }
    while (pi < p.size() && p[pi] == '*') ++pi;
    return pi == p.size();
}

bool ExcludeSet::excluded(const std::string& path) const {
    for (const auto& pat : pats_) {
        if (pat.empty()) continue;
        if (pat.find('/') != std::string::npos) {
            std::string base = pat;
            while (base.size() > 1 && base.back() == '/') base.pop_back();
            if (path == base) return true;
            if (path.size() > base.size() && path.compare(0, base.size(), base) == 0 &&
                path[base.size()] == '/') return true;
            if (glob_match(pat, path)) return true;
        } else {
            std::string_view rel = path;
            if (!root_.empty() && path.size() >= root_.size() &&
                path.compare(0, root_.size(), root_) == 0)
                rel = std::string_view(path).substr(root_.size());
            for (const auto& comp : split(rel, '/'))
                if (!comp.empty() && glob_match(pat, comp)) return true;
        }
    }
    return false;
}

// ---- logging -------------------------------------------------------------
static std::mutex g_log_mu;
static bool g_verbose = false;

void set_verbose(bool v) { g_verbose = v; }

static void emit(const char* level, const std::string& msg) {
    std::lock_guard<std::mutex> lk(g_log_mu);
    std::cerr << iso_time(now_real_ns()) << " [" << level << "] " << msg << "\n";
}
void log_info(const std::string& m)  { emit("INFO ", m); }
void log_warn(const std::string& m)  { emit("WARN ", m); }
void log_error(const std::string& m) { emit("ERROR", m); }
void log_debug(const std::string& m) { if (g_verbose) emit("DEBUG", m); }

} // namespace fia
