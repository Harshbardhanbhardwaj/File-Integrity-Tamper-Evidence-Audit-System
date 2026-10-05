#include "fiaudit/device.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cstring>

#include "fiaudit/sha256.hpp"
#include "fiaudit_ioctl.h"      // shared with the kernel driver

static_assert(sizeof(fia_event) == 312, "ABI: struct fia_event must be 312 bytes");

namespace fia {

const char* to_string(VerifyStatus s) noexcept {
    switch (s) {
        case VerifyStatus::Match:       return "match";
        case VerifyStatus::Mismatch:    return "MISMATCH";
        case VerifyStatus::NotRetained: return "not-retained";
        case VerifyStatus::Unavailable: return "unavailable";
    }
    return "?";
}

// ------------------------------------------------------------------ KernelSink
KernelSink::KernelSink(const std::string& dev_path) : path_(dev_path) {
    fd_.reset(::open(dev_path.c_str(), O_RDWR | O_CLOEXEC));
    if (!fd_.valid()) throw SysError("open " + dev_path);
}

SubmitResult KernelSink::submit(EventType type, const std::string& path) {
    fia_event ev;
    std::memset(&ev, 0, sizeof ev);
    ev.type = static_cast<__u32>(type);
    std::strncpy(ev.path, path.c_str(), FIA_PATH_MAX - 1);

    std::lock_guard<std::mutex> lk(mu_);
    if (::ioctl(fd_.get(), FIA_IOC_SUBMIT, &ev) != 0) {
        log_warn(std::string("FIA_IOC_SUBMIT failed: ") + std::strerror(errno));
        return {};
    }
    SubmitResult r;
    r.ok = true;
    r.seq = ev.seq;
    r.chain_hex = to_hex(ev.chain, FIA_HASH_LEN);
    return r;
}

std::optional<SinkStats> KernelSink::stats() {
    fia_stats st;
    std::memset(&st, 0, sizeof st);
    std::lock_guard<std::mutex> lk(mu_);
    if (::ioctl(fd_.get(), FIA_IOC_GET_STATS, &st) != 0) return std::nullopt;
    SinkStats s;
    s.total = st.total;
    s.oldest = st.oldest_seq;
    s.capacity = st.capacity;
    s.head_hex = to_hex(st.head, FIA_HASH_LEN);
    return s;
}

VerifyStatus KernelSink::verify(std::uint64_t seq, const std::string& chain_hex) {
    fia_verify v;
    std::memset(&v, 0, sizeof v);
    v.seq = seq;
    if (!from_hex(chain_hex, v.chain, FIA_HASH_LEN)) return VerifyStatus::Mismatch;
    std::lock_guard<std::mutex> lk(mu_);
    if (::ioctl(fd_.get(), FIA_IOC_VERIFY, &v) == 0) return VerifyStatus::Match;
    if (errno == ENOENT) return VerifyStatus::NotRetained;
    if (errno == EBADMSG) return VerifyStatus::Mismatch;
    return VerifyStatus::Unavailable;
}

std::vector<KernelSink::Event> KernelSink::read_events(std::size_t max) {
    std::vector<Event> out;
    std::lock_guard<std::mutex> lk(mu_);
    pollfd p{fd_.get(), POLLIN, 0};
    if (::poll(&p, 1, 0) <= 0 || !(p.revents & POLLIN)) return out;
    std::vector<fia_event> buf(max);
    ssize_t n = ::read(fd_.get(), buf.data(), buf.size() * sizeof(fia_event));
    if (n <= 0) return out;
    for (std::size_t i = 0; i < static_cast<std::size_t>(n) / sizeof(fia_event); ++i) {
        const fia_event& e = buf[i];
        out.push_back({e.seq, e.ts_ns, e.type, e.pid,
                       std::string(e.path, strnlen(e.path, FIA_PATH_MAX)),
                       to_hex(e.chain, FIA_HASH_LEN)});
    }
    return out;
}

// ------------------------------------------------------------------ MemorySink
MemorySink::MemorySink(std::uint32_t capacity) : cap_(capacity ? capacity : 16), ring_(cap_) {
    head_.fill(0);
}

SubmitResult MemorySink::submit(EventType type, const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    std::uint64_t seq = next_seq_;
    std::uint64_t ts = now_real_ns();
    std::uint32_t t = static_cast<std::uint32_t>(type);
    std::uint32_t pid = static_cast<std::uint32_t>(::getpid());
    char pbuf[FIA_PATH_MAX];
    std::memset(pbuf, 0, sizeof pbuf);
    std::strncpy(pbuf, path.c_str(), FIA_PATH_MAX - 1);

    Sha256 h;                                   // identical layout to the kernel driver
    h.update(head_.data(), head_.size());
    h.update(&seq, sizeof seq);
    h.update(&ts, sizeof ts);
    h.update(&t, sizeof t);
    h.update(&pid, sizeof pid);
    h.update(pbuf, sizeof pbuf);
    head_ = h.final();

    Slot& s = ring_[seq % cap_];
    s.seq = seq;
    s.chain = to_hex(head_);
    ++next_seq_;
    return {true, seq, s.chain};
}

std::optional<SinkStats> MemorySink::stats() {
    std::lock_guard<std::mutex> lk(mu_);
    SinkStats s;
    s.total = next_seq_ - 1;
    s.oldest = s.total > cap_ ? s.total - cap_ + 1 : 1;
    s.capacity = cap_;
    s.head_hex = to_hex(head_);
    return s;
}

VerifyStatus MemorySink::verify(std::uint64_t seq, const std::string& chain_hex) {
    std::lock_guard<std::mutex> lk(mu_);
    std::uint64_t total = next_seq_ - 1;
    std::uint64_t oldest = total > cap_ ? total - cap_ + 1 : 1;
    if (seq == 0 || seq > total || seq < oldest) return VerifyStatus::NotRetained;
    return ring_[seq % cap_].chain == chain_hex ? VerifyStatus::Match : VerifyStatus::Mismatch;
}

void MemorySink::corrupt(std::uint64_t seq) {
    std::lock_guard<std::mutex> lk(mu_);
    Slot& s = ring_[seq % cap_];
    if (s.seq == seq && !s.chain.empty()) s.chain[0] = (s.chain[0] == '0') ? '1' : '0';
}

// ------------------------------------------------------------------ factory
std::unique_ptr<IAuditSink> open_sink(const std::string& dev_path, bool required) {
    if (dev_path == "sim") return std::make_unique<MemorySink>();
    if (dev_path == "none") return std::make_unique<NullSink>();
    try {
        return std::make_unique<KernelSink>(dev_path);
    } catch (const SysError& e) {
        if (required) throw;
        log_warn(std::string("kernel device unavailable (") + e.what() +
                 "); continuing with user-space log only");
        return std::make_unique<NullSink>();
    }
}

} // namespace fia
