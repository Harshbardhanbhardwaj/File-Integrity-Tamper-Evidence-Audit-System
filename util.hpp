// util.hpp - small system-programming helpers (RAII fd, errors, escaping...).
#pragma once
#include <cerrno>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "fiaudit/types.hpp"

namespace fia {

// Exception carrying errno.
class SysError : public std::runtime_error {
public:
    explicit SysError(const std::string& what, int err = errno);
    int code() const noexcept { return code_; }
private:
    int code_;
};

// Move-only RAII wrapper for a POSIX file descriptor.
class Fd {
public:
    Fd() noexcept = default;
    explicit Fd(int fd) noexcept : fd_(fd) {}
    ~Fd() { reset(); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& o) noexcept : fd_(o.release()) {}
    Fd& operator=(Fd&& o) noexcept { if (this != &o) reset(o.release()); return *this; }

    int  get() const noexcept { return fd_; }
    bool valid() const noexcept { return fd_ >= 0; }
    int  release() noexcept { int f = fd_; fd_ = -1; return f; }
    void reset(int fd = -1) noexcept;
private:
    int fd_ = -1;
};

std::string to_hex(const std::uint8_t* data, std::size_t len);
std::string to_hex(const Digest& d);
bool        from_hex(const std::string& hex, std::uint8_t* out, std::size_t len);

std::uint64_t now_real_ns();
std::string   iso_time(std::uint64_t ns);

// Percent-escape '%', TAB, CR, LF so a value is safe in a TAB-separated line.
std::string pct_escape(std::string_view s);
std::string pct_unescape(std::string_view s);

std::vector<std::string> split(std::string_view s, char sep);

// Shell-style glob: '*' (any run, including '/'), '?' (one char).
bool glob_match(std::string_view pattern, std::string_view text);

// Exclusion rules:
//  - pattern without '/'  : matched against every path component (e.g. "*.tmp", ".git")
//  - pattern with    '/'  : absolute path prefix or glob over the whole path
class ExcludeSet {
public:
    ExcludeSet() = default;
    explicit ExcludeSet(std::vector<std::string> patterns, std::string root = "")
        : pats_(std::move(patterns)), root_(std::move(root)) {}
    void add(std::string p) { pats_.push_back(std::move(p)); }
    // Component patterns are matched on the path RELATIVE to this root.
    void set_root(std::string r) { root_ = std::move(r); }
    bool excluded(const std::string& path) const;
    const std::vector<std::string>& patterns() const { return pats_; }
private:
    std::vector<std::string> pats_;
    std::string              root_;
};

// Thread-safe stderr logging.
void set_verbose(bool v);
void log_info(const std::string& msg);
void log_warn(const std::string& msg);
void log_error(const std::string& msg);
void log_debug(const std::string& msg);

} // namespace fia
