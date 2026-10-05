#include "fiaudit/watcher.hpp"

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <filesystem>

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

namespace fia {

namespace {
constexpr std::uint32_t kWatchMask =
    IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM |
    IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR | IN_EXCL_UNLINK;
}

Watcher::Watcher(WatchConfig cfg, Auditor& auditor)
    : cfg_(std::move(cfg)), auditor_(auditor), pool_(cfg_.threads ? cfg_.threads : 1) {
    if (!cfg_.baseline) throw std::invalid_argument("Watcher: baseline required");
    bl_ = cfg_.baseline;
    root_ = bl_->root;

    std::vector<std::string> pats = bl_->excludes;
    pats.insert(pats.end(), cfg_.extra_excludes.begin(), cfg_.extra_excludes.end());
    excl_ = ExcludeSet(pats, root_);

    ifd_.reset(::inotify_init1(IN_CLOEXEC | IN_NONBLOCK));
    if (!ifd_.valid()) throw SysError("inotify_init1");
    efd_.reset(::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    if (!efd_.valid()) throw SysError("eventfd");
    epfd_.reset(::epoll_create1(EPOLL_CLOEXEC));
    if (!epfd_.valid()) throw SysError("epoll_create1");

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = ifd_.get();
    if (::epoll_ctl(epfd_.get(), EPOLL_CTL_ADD, ifd_.get(), &ev) != 0) throw SysError("epoll_ctl inotify");
    ev.data.fd = efd_.get();
    if (::epoll_ctl(epfd_.get(), EPOLL_CTL_ADD, efd_.get(), &ev) != 0) throw SysError("epoll_ctl eventfd");
}

Watcher::~Watcher() { pool_.wait_idle(); }

std::shared_ptr<const Baseline> Watcher::baseline() const {
    std::lock_guard<std::mutex> lk(bl_mu_);
    return bl_;
}

WatchStats Watcher::stats() const {
    std::lock_guard<std::mutex> lk(st_mu_);
    return stats_;
}

void Watcher::request_stop() noexcept {
    stop_.store(true);
    std::uint64_t one = 1;
    ssize_t r = ::write(efd_.get(), &one, sizeof one);   // wakes epoll_wait
    (void)r;
}

void Watcher::request_reload() noexcept {
    reload_.store(true);
    std::uint64_t one = 1;
    ssize_t r = ::write(efd_.get(), &one, sizeof one);
    (void)r;
}

// ---------------------------------------------------------------- watches
void Watcher::add_tree(const std::string& dir, bool enqueue_files) {
    if (excl_.excluded(dir)) return;
    int wd = ::inotify_add_watch(ifd_.get(), dir.c_str(), kWatchMask);
    if (wd < 0) {
        if (errno == ENOSPC)
            log_error("inotify watch limit reached - raise fs.inotify.max_user_watches");
        else
            log_warn("cannot watch " + dir + ": " + std::strerror(errno));
        return;
    }
    wd_to_dir_[wd] = dir;

    std::error_code ec;
    for (fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
         !ec && it != end; it.increment(ec)) {
        std::string p = it->path().string();
        std::error_code e2;
        auto st = it->symlink_status(e2);
        if (e2 || excl_.excluded(p)) continue;
        if (fs::is_directory(st)) add_tree(p, enqueue_files);
        else if (enqueue_files) schedule(p, "", std::chrono::milliseconds(0));
    }
}

void Watcher::schedule(const std::string& path, const std::string& hint,
                       std::chrono::milliseconds delay) {
    auto& p = pending_[path];
    p.due = Clock::now() + delay;
    if (!hint.empty()) p.hint = hint;
}

void Watcher::flush_due(bool everything) {
    auto now = Clock::now();
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (everything || it->second.due <= now) {
            std::string path = it->first, hint = it->second.hint;
            it = pending_.erase(it);
            pool_.submit([this, path, hint] {
                try { process_path(path, hint); }
                catch (const std::exception& e) { log_error("process " + path + ": " + e.what()); }
            });
        } else {
            ++it;
        }
    }
}

void Watcher::drain_inotify() {
    alignas(inotify_event) char buf[64 * 1024];
    for (;;) {
        ssize_t n = ::read(ifd_.get(), buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) return;
            throw SysError("read inotify");
        }
        if (n == 0) return;
        for (char* p = buf; p < buf + n;) {
            auto* ev = reinterpret_cast<inotify_event*>(p);
            p += sizeof(inotify_event) + ev->len;
            { std::lock_guard<std::mutex> lk(st_mu_); ++stats_.inotify_events; }

            if (ev->mask & IN_Q_OVERFLOW) {
                { std::lock_guard<std::mutex> lk(st_mu_); ++stats_.overflows; }
                log_warn("inotify queue overflow - scheduling full rescan");
                pool_.submit([this] {
                    try { full_rescan("inotify queue overflow"); }
                    catch (const std::exception& e) { log_error(e.what()); }
                });
                continue;
            }
            if (ev->mask & IN_IGNORED) { wd_to_dir_.erase(ev->wd); continue; }

            auto d = wd_to_dir_.find(ev->wd);
            if (d == wd_to_dir_.end()) continue;
            const std::string& dir = d->second;

            if (ev->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
                if (dir == root_) {
                    auditor_.record(EventType::Tamper, root_, "watched root removed or moved");
                    std::lock_guard<std::mutex> lk(st_mu_); ++stats_.alerts;
                }
                continue;
            }
            if (ev->len == 0) continue;
            std::string path = dir + "/" + ev->name;
            if (excl_.excluded(path)) continue;

            bool isdir = ev->mask & IN_ISDIR;
            if (isdir && (ev->mask & (IN_CREATE | IN_MOVED_TO))) {
                add_tree(path, true);                  // new subtree: watch it + scan files in it
            } else if (isdir && (ev->mask & (IN_DELETE | IN_MOVED_FROM))) {
                pool_.submit([this, path] {
                    try { process_removed_dir(path); }
                    catch (const std::exception& e) { log_error(e.what()); }
                });
            } else if (!isdir) {
                std::string hint;
                if (ev->mask & IN_MOVED_FROM) hint = "moved_from";
                else if (ev->mask & IN_MOVED_TO) hint = "moved_to";
                schedule(path, hint, cfg_.debounce);
            }
        }
    }
}

// ---------------------------------------------------------------- analysis
std::string Watcher::state_key(const FileRecord* r) const {
    if (!r) return "ABSENT";
    return std::string(1, r->kind) + ":" + r->sha256 + ":" + std::to_string(r->mode) + ":" +
           std::to_string(r->uid) + ":" + std::to_string(r->gid);
}

void Watcher::alert(const Change& c, const std::string& extra) {
    EventType t = event_type_for(c.kind);
    std::string detail = c.detail;
    if (!c.old_hash.empty()) detail += "; old=" + c.old_hash.substr(0, 16);
    if (!c.new_hash.empty()) detail += "; new=" + c.new_hash.substr(0, 16);
    if (!extra.empty()) detail += "; " + extra;
    if (!extra.empty() && c.kind == ChangeKind::Added && extra.rfind("moved", 0) == 0) t = EventType::Move;
    if (!extra.empty() && c.kind == ChangeKind::Deleted && extra.rfind("moved", 0) == 0) t = EventType::Move;
    auditor_.record(t, c.path, detail);
    std::lock_guard<std::mutex> lk(st_mu_);
    ++stats_.alerts;
}

void Watcher::process_path(const std::string& path, const std::string& hint) {
    if (excl_.excluded(path)) return;
    { std::lock_guard<std::mutex> lk(st_mu_); ++stats_.paths_processed; }

    auto bl = baseline();
    const FileRecord* old = bl->find(path);

    std::optional<FileRecord> now;
    try {
        now = make_record(path, true);
    } catch (const SysError& e) {
        if (e.code() != ENOENT && e.code() != ENOTDIR) {
            auditor_.record(EventType::Scan, path, std::string("unreadable: ") + e.what());
            return;
        }
        now.reset();                                // vanished
    }
    if (!now) {
        struct stat st;
        if (::lstat(path.c_str(), &st) == 0) return;   // directory/special file: ignore
    }

    std::string key = state_key(now ? &*now : nullptr);
    auto change = classify(old, now ? &*now : nullptr);

    std::lock_guard<std::mutex> lk(rep_mu_);
    auto rep = reported_.find(path);
    if (!change) {
        if (rep != reported_.end()) {               // was reported, now back to baseline
            reported_.erase(rep);
            auditor_.record(EventType::Scan, path, "restored to baseline state");
        }
        return;
    }
    if (rep != reported_.end() && rep->second == key) return;   // already reported this state
    reported_[path] = key;
    std::string extra;
    if (hint == "moved_from") extra = "moved away";
    else if (hint == "moved_to") extra = "moved in";
    alert(*change, extra);
}

void Watcher::process_removed_dir(const std::string& dir) {
    auto bl = baseline();
    std::string prefix = dir + "/";
    std::vector<std::string> victims;
    for (auto it = bl->files.lower_bound(prefix); it != bl->files.end(); ++it) {
        if (it->first.compare(0, prefix.size(), prefix) != 0) break;
        victims.push_back(it->first);
    }
    for (const auto& v : victims) process_path(v, "");
}

void Watcher::full_rescan(const std::string& reason) {
    auto bl = baseline();
    ScanOptions opt;
    opt.excludes = cfg_.extra_excludes;
    opt.threads = cfg_.threads;
    CompareResult res = compare_with_baseline(*bl, opt);
    auditor_.record(EventType::Scan, root_,
                    reason + ": scanned=" + std::to_string(res.scanned) +
                    " changes=" + std::to_string(res.changes.size()));
    std::lock_guard<std::mutex> lk(rep_mu_);
    for (const auto& c : res.changes) {
        std::optional<FileRecord> now;
        try { now = make_record(c.path, true); } catch (...) {}
        std::string key = state_key(now ? &*now : nullptr);
        auto rep = reported_.find(c.path);
        if (rep != reported_.end() && rep->second == key) continue;
        reported_[c.path] = key;
        alert(c);
    }
}

void Watcher::do_reload() {
    try {
        auto fresh = std::make_shared<Baseline>(Baseline::load(cfg_.baseline_path));
        {
            std::lock_guard<std::mutex> lk(bl_mu_);
            bl_ = fresh;
        }
        { std::lock_guard<std::mutex> lk(rep_mu_); reported_.clear(); }
        log_info("baseline reloaded (" + std::to_string(fresh->files.size()) + " files)");
        auditor_.record(EventType::Scan, cfg_.baseline_path, "baseline reloaded on SIGHUP");
        full_rescan("rescan after reload");
    } catch (const std::exception& e) {
        auditor_.record(EventType::Tamper, cfg_.baseline_path,
                        std::string("baseline reload failed: ") + e.what());
        log_error(std::string("baseline reload failed: ") + e.what());
    }
}

// ---------------------------------------------------------------- main loop
void Watcher::run() {
    add_tree(root_, false);
    log_info("watching " + root_ + " (" + std::to_string(wd_to_dir_.size()) + " directories)");
    auditor_.record(EventType::Scan, root_,
                    "watch started: dirs=" + std::to_string(wd_to_dir_.size()));
    if (cfg_.initial_scan) full_rescan("initial scan");

    auto next_hb = Clock::now() + std::chrono::seconds(cfg_.heartbeat_sec);

    while (!stop_.load()) {
        int timeout_ms = -1;
        auto now = Clock::now();
        for (const auto& kv : pending_) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(kv.second.due - now).count();
            if (ms < 0) ms = 0;
            if (timeout_ms < 0 || ms < timeout_ms) timeout_ms = static_cast<int>(ms) + 1;
        }
        if (cfg_.heartbeat_sec) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(next_hb - now).count();
            if (ms < 0) ms = 0;
            if (timeout_ms < 0 || ms < timeout_ms) timeout_ms = static_cast<int>(ms) + 1;
        }

        epoll_event evs[8];
        int n = ::epoll_wait(epfd_.get(), evs, 8, timeout_ms);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw SysError("epoll_wait");
        }
        for (int i = 0; i < n; ++i) {
            if (evs[i].data.fd == efd_.get()) {
                std::uint64_t v;
                ssize_t r = ::read(efd_.get(), &v, sizeof v);
                (void)r;
                if (reload_.exchange(false)) do_reload();
            } else if (evs[i].data.fd == ifd_.get()) {
                drain_inotify();
            }
        }
        flush_due(false);
        if (cfg_.heartbeat_sec && Clock::now() >= next_hb) {
            auditor_.record(EventType::Heartbeat, root_, "alive");
            next_hb = Clock::now() + std::chrono::seconds(cfg_.heartbeat_sec);
        }
    }

    flush_due(true);
    pool_.wait_idle();
    auditor_.record(EventType::Scan, root_, "watch stopped");
}

} // namespace fia
