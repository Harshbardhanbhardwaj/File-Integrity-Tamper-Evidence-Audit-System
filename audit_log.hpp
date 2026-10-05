// audit_log.hpp - append-only, hash-chained audit log + Auditor facade.
#pragma once
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "fiaudit/device.hpp"
#include "fiaudit/types.hpp"

namespace fia {

constexpr const char* kGenesisHash =
    "0000000000000000000000000000000000000000000000000000000000000000";

struct LogRecord {
    std::uint64_t seq = 0;
    std::uint64_t ts_ns = 0;
    std::string   type;       // EventType name
    std::string   path;
    std::string   detail;
    std::uint64_t kseq = 0;   // sequence number assigned by the kernel driver (0 = none)
    std::string   khash = "-";// kernel chain value (hex) or "-"
    std::string   prev;       // previous record hash
    std::string   hash;       // SHA256(prev "|" payload)

    std::string payload() const;           // the fields covered by the hash
    std::string compute_hash() const;
    std::string to_line() const;           // without trailing '\n'
    static bool parse(const std::string& line, LogRecord& out);
};

struct VerifyResult {
    bool          ok = true;
    std::size_t   records = 0;
    std::size_t   bad_line = 0;     // 1-based, 0 = none
    std::string   message = "ok";
    std::uint64_t last_kseq = 0;
    std::string   last_khash = "-";
    std::string   last_hash = kGenesisHash;
};

class AuditLog {
public:
    explicit AuditLog(std::string path);       // opens/creates, loads chain tail
    ~AuditLog();
    AuditLog(const AuditLog&) = delete;
    AuditLog& operator=(const AuditLog&) = delete;

    LogRecord append(EventType type, const std::string& path, const std::string& detail,
                     std::uint64_t kseq = 0, const std::string& khash = "-");

    const std::string& path() const { return path_; }
    std::uint64_t      last_seq() const;

    static VerifyResult           verify(const std::string& path);
    static std::vector<LogRecord> read_all(const std::string& path);

private:
    void reload_tail_locked();

    std::string           path_;
    int                   fd_ = -1;
    mutable std::mutex    mu_;
    std::uint64_t         seq_ = 0;
    std::string           last_hash_ = kGenesisHash;
    off_t                 known_size_ = 0;
};

// Combines the user-space log with the kernel sink. Thread-safe; guarantees the
// kernel sequence order == log order.
class Auditor {
public:
    Auditor(AuditLog& log, IAuditSink& sink) : log_(log), sink_(sink) {}
    LogRecord record(EventType type, const std::string& path, const std::string& detail);
    std::uint64_t count() const { std::lock_guard<std::mutex> lk(mu_); return count_; }
private:
    AuditLog&          log_;
    IAuditSink&        sink_;
    mutable std::mutex mu_;
    std::uint64_t      count_ = 0;
};

} // namespace fia
