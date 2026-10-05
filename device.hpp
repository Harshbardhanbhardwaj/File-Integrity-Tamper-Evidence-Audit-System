// device.hpp - abstraction over the kernel audit device (and a software model).
#pragma once
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "fiaudit/types.hpp"
#include "fiaudit/util.hpp"

namespace fia {

struct SubmitResult {
    bool          ok = false;
    std::uint64_t seq = 0;
    std::string   chain_hex = "-";
};

struct SinkStats {
    std::uint64_t total = 0;
    std::uint64_t oldest = 0;
    std::uint32_t capacity = 0;
    std::string   head_hex;
};

enum class VerifyStatus { Match, Mismatch, NotRetained, Unavailable };
const char* to_string(VerifyStatus s) noexcept;

// Interface (polymorphism): kernel driver, software model, or no-op.
class IAuditSink {
public:
    virtual ~IAuditSink() = default;
    virtual std::string               name() const = 0;
    virtual bool                      available() const = 0;
    virtual SubmitResult              submit(EventType type, const std::string& path) = 0;
    virtual std::optional<SinkStats>  stats() = 0;
    virtual VerifyStatus              verify(std::uint64_t seq, const std::string& chain_hex) = 0;
};

// Used when the driver is not loaded: events are logged in user space only.
class NullSink final : public IAuditSink {
public:
    std::string name() const override { return "none"; }
    bool available() const override { return false; }
    SubmitResult submit(EventType, const std::string&) override { return {}; }
    std::optional<SinkStats> stats() override { return std::nullopt; }
    VerifyStatus verify(std::uint64_t, const std::string&) override { return VerifyStatus::Unavailable; }
};

// Talks to /dev/fiaudit through open/ioctl.
class KernelSink final : public IAuditSink {
public:
    explicit KernelSink(const std::string& dev_path);   // throws SysError
    std::string name() const override { return "kernel:" + path_; }
    bool available() const override { return true; }
    SubmitResult submit(EventType type, const std::string& path) override;
    std::optional<SinkStats> stats() override;
    VerifyStatus verify(std::uint64_t seq, const std::string& chain_hex) override;
    // Read up to 'max' retained events with read(2).
    struct Event { std::uint64_t seq, ts_ns; std::uint32_t type, pid; std::string path, chain_hex; };
    std::vector<Event> read_events(std::size_t max);
private:
    std::string path_;
    Fd          fd_;
    std::mutex  mu_;
};

// Pure user-space model of the driver (same chain algorithm). Used by unit tests
// and by `--sim-device` so the full system can be demonstrated without root/kernel.
class MemorySink final : public IAuditSink {
public:
    explicit MemorySink(std::uint32_t capacity = 1024);
    std::string name() const override { return "memory-model"; }
    bool available() const override { return true; }
    SubmitResult submit(EventType type, const std::string& path) override;
    std::optional<SinkStats> stats() override;
    VerifyStatus verify(std::uint64_t seq, const std::string& chain_hex) override;
    void corrupt(std::uint64_t seq);   // test hook: flips a bit of a stored chain value
private:
    struct Slot { std::uint64_t seq = 0; std::string chain; };
    std::mutex        mu_;
    std::uint32_t     cap_;
    std::vector<Slot> ring_;
    std::uint64_t     next_seq_ = 1;
    Digest            head_{};
};

// Opens the kernel device if possible, else returns a NullSink (or throws if required).
std::unique_ptr<IAuditSink> open_sink(const std::string& dev_path, bool required);

} // namespace fia
