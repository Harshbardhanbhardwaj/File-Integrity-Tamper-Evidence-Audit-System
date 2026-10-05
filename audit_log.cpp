#include "fiaudit/audit_log.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "fiaudit/sha256.hpp"
#include "fiaudit/util.hpp"

namespace fia {

// ------------------------------------------------------------------ LogRecord
std::string LogRecord::payload() const {
    std::ostringstream o;
    o << seq << '\t' << ts_ns << '\t' << type << '\t' << pct_escape(path) << '\t'
      << pct_escape(detail) << '\t' << kseq << '\t' << khash;
    return o.str();
}

std::string LogRecord::compute_hash() const { return Sha256::hash_hex(prev + "|" + payload()); }

std::string LogRecord::to_line() const { return payload() + "\t" + prev + "\t" + hash; }

static bool is_hex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

static bool parse_u64(const std::string& s, std::uint64_t& out) {
    if (s.empty() || s.size() > 20) return false;
    for (char c : s) if (c < '0' || c > '9') return false;
    out = std::strtoull(s.c_str(), nullptr, 10);
    return true;
}

bool LogRecord::parse(const std::string& line, LogRecord& out) {
    auto f = split(line, '\t');
    if (f.size() != 9) return false;
    LogRecord r;
    if (!parse_u64(f[0], r.seq) || !parse_u64(f[1], r.ts_ns) || !parse_u64(f[5], r.kseq)) return false;
    r.type   = f[2];
    r.path   = pct_unescape(f[3]);
    r.detail = pct_unescape(f[4]);
    r.khash  = f[6];
    r.prev   = f[7];
    r.hash   = f[8];
    if (!is_hex64(r.prev) || !is_hex64(r.hash)) return false;
    out = std::move(r);
    return true;
}

// ------------------------------------------------------------------ AuditLog
static std::string slurp_fd(int fd, off_t size) {
    std::string data(static_cast<std::size_t>(size), '\0');
    off_t off = 0;
    while (off < size) {
        ssize_t n = ::pread(fd, &data[static_cast<std::size_t>(off)],
                            static_cast<std::size_t>(size - off), off);
        if (n < 0) { if (errno == EINTR) continue; throw SysError("read log"); }
        if (n == 0) break;
        off += n;
    }
    data.resize(static_cast<std::size_t>(off));
    return data;
}

AuditLog::AuditLog(std::string path) : path_(std::move(path)) {
    fd_ = ::open(path_.c_str(), O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC, 0640);
    if (fd_ < 0) throw SysError("open log " + path_);
    std::lock_guard<std::mutex> lk(mu_);
    if (::flock(fd_, LOCK_EX) != 0) throw SysError("flock " + path_);
    try { reload_tail_locked(); } catch (...) { ::flock(fd_, LOCK_UN); ::close(fd_); fd_ = -1; throw; }
    ::flock(fd_, LOCK_UN);
}

AuditLog::~AuditLog() { if (fd_ >= 0) ::close(fd_); }

void AuditLog::reload_tail_locked() {
    struct stat st;
    if (::fstat(fd_, &st) != 0) throw SysError("fstat " + path_);
    known_size_ = st.st_size;
    seq_ = 0;
    last_hash_ = kGenesisHash;
    if (st.st_size == 0) return;

    std::string data = slurp_fd(fd_, st.st_size);
    if (data.back() != '\n')
        throw std::runtime_error("audit log " + path_ + ": unterminated last record (truncated?)");
    std::size_t end = data.size() - 1;
    std::size_t start = data.rfind('\n', end - 1);
    start = (start == std::string::npos) ? 0 : start + 1;
    LogRecord r;
    if (!LogRecord::parse(data.substr(start, end - start), r))
        throw std::runtime_error("audit log " + path_ + ": last record is malformed");
    seq_ = r.seq;
    last_hash_ = r.hash;
}

std::uint64_t AuditLog::last_seq() const {
    std::lock_guard<std::mutex> lk(mu_);
    return seq_;
}

LogRecord AuditLog::append(EventType type, const std::string& path, const std::string& detail,
                           std::uint64_t kseq, const std::string& khash) {
    std::lock_guard<std::mutex> lk(mu_);
    if (::flock(fd_, LOCK_EX) != 0) throw SysError("flock " + path_);
    struct Unlock { int fd; ~Unlock() { ::flock(fd, LOCK_UN); } } unlock{fd_};

    struct stat st;
    if (::fstat(fd_, &st) != 0) throw SysError("fstat " + path_);
    if (st.st_size != known_size_) reload_tail_locked();   // another writer (or tamper)

    LogRecord r;
    r.seq    = seq_ + 1;
    r.ts_ns  = now_real_ns();
    r.type   = to_string(type);
    r.path   = path;
    r.detail = detail;
    r.kseq   = kseq;
    r.khash  = khash.empty() ? "-" : khash;
    r.prev   = last_hash_;
    r.hash   = r.compute_hash();

    std::string line = r.to_line() + "\n";
    const char* p = line.data();
    std::size_t left = line.size();
    while (left > 0) {
        ssize_t n = ::write(fd_, p, left);
        if (n < 0) { if (errno == EINTR) continue; throw SysError("write log " + path_); }
        p += n;
        left -= static_cast<std::size_t>(n);
    }
    if (::fsync(fd_) != 0) throw SysError("fsync " + path_);

    seq_ = r.seq;
    last_hash_ = r.hash;
    known_size_ += static_cast<off_t>(line.size());
    return r;
}

static std::string read_text(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw SysError("open log " + path, ENOENT);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

VerifyResult AuditLog::verify(const std::string& path) {
    VerifyResult v;
    std::string text;
    try { text = read_text(path); }
    catch (const std::exception& e) { v.ok = false; v.message = e.what(); return v; }

    std::string prev = kGenesisHash;
    std::uint64_t expect_seq = 1;
    std::size_t line_no = 0, pos = 0;
    while (pos < text.size()) {
        std::size_t nl = text.find('\n', pos);
        ++line_no;
        auto fail = [&](const std::string& why) {
            v.ok = false; v.bad_line = line_no; v.message = why; return v;
        };
        if (nl == std::string::npos) return fail("unterminated final record (truncated write?)");
        std::string line = text.substr(pos, nl - pos);
        pos = nl + 1;

        LogRecord r;
        if (!LogRecord::parse(line, r)) return fail("malformed record");
        if (r.seq != expect_seq)
            return fail("sequence gap: expected " + std::to_string(expect_seq) + ", found " +
                        std::to_string(r.seq) + " (record deleted or reordered)");
        if (r.prev != prev) return fail("broken chain: prev-hash does not match previous record");
        if (r.compute_hash() != r.hash) return fail("record content modified (hash mismatch)");

        prev = r.hash;
        ++expect_seq;
        ++v.records;
        v.last_kseq = r.kseq;
        v.last_khash = r.khash;
        v.last_hash = r.hash;
    }
    return v;
}

std::vector<LogRecord> AuditLog::read_all(const std::string& path) {
    std::string text = read_text(path);
    std::vector<LogRecord> out;
    for (const auto& line : split(text, '\n')) {
        if (line.empty()) continue;
        LogRecord r;
        if (!LogRecord::parse(line, r)) throw std::runtime_error("malformed record in " + path);
        out.push_back(std::move(r));
    }
    return out;
}

// ------------------------------------------------------------------ Auditor
LogRecord Auditor::record(EventType type, const std::string& path, const std::string& detail) {
    std::lock_guard<std::mutex> lk(mu_);
    std::uint64_t kseq = 0;
    std::string khash = "-";
    if (sink_.available()) {
        SubmitResult r = sink_.submit(type, path);
        if (r.ok) { kseq = r.seq; khash = r.chain_hex; }
        else log_warn("kernel sink rejected event; logged in user space only");
    }
    LogRecord rec = log_.append(type, path, detail, kseq, khash);
    ++count_;
    return rec;
}

} // namespace fia
