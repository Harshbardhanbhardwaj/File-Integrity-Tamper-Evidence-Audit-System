// watcher.hpp - real-time monitor: inotify + epoll + eventfd + worker pool.
#pragma once
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "fiaudit/audit_log.hpp"
#include "fiaudit/baseline.hpp"
#include "fiaudit/scanner.hpp"
#include "fiaudit/thread_pool.hpp"
#include "fiaudit/util.hpp"

namespace fia {

struct WatchConfig {
    std::string                  baseline_path;      // reloaded on SIGHUP
    std::shared_ptr<const Baseline> baseline;
    std::vector<std::string>     extra_excludes;     // e.g. the log & baseline files themselves
    std::chrono::milliseconds    debounce{300};
    unsigned                     threads = 2;
    unsigned                     heartbeat_sec = 0;  // user-space heartbeat records (0 = off)
    bool                         initial_scan = true;
};

struct WatchStats {
    std::uint64_t inotify_events = 0;
    std::uint64_t paths_processed = 0;
    std::uint64_t alerts = 0;
    std::uint64_t overflows = 0;
};

class Watcher {
public:
    Watcher(WatchConfig cfg, Auditor& auditor);
    ~Watcher();
    Watcher(const Watcher&) = delete;
    Watcher& operator=(const Watcher&) = delete;

    void run();                              // blocks until request_stop()
    void request_stop() noexcept;            // async-signal-safe
    void request_reload() noexcept;          // async-signal-safe
    std::size_t  watch_count() const { return wd_to_dir_.size(); }
    WatchStats   stats() const;

private:
    struct Pending { std::chrono::steady_clock::time_point due; std::string hint; };

    void add_tree(const std::string& dir, bool enqueue_files);
    void drain_inotify();
    void schedule(const std::string& path, const std::string& hint,
                  std::chrono::milliseconds delay);
    void flush_due(bool everything);
    void process_path(const std::string& path, const std::string& hint);
    void process_removed_dir(const std::string& dir);
    void full_rescan(const std::string& reason);
    void do_reload();
    void alert(const Change& c, const std::string& extra = "");
    std::shared_ptr<const Baseline> baseline() const;
    std::string state_key(const FileRecord* r) const;

    WatchConfig                         cfg_;
    Auditor&                            auditor_;
    ExcludeSet                          excl_;
    std::string                         root_;

    Fd                                  ifd_, efd_, epfd_;
    std::unordered_map<int, std::string> wd_to_dir_;          // watcher thread only
    std::unordered_map<std::string, Pending> pending_;        // watcher thread only

    mutable std::mutex                  bl_mu_;
    std::shared_ptr<const Baseline>     bl_;
    std::mutex                          rep_mu_;
    std::unordered_map<std::string, std::string> reported_;   // path -> last reported state

    std::atomic<bool>                   stop_{false}, reload_{false};
    mutable std::mutex                  st_mu_;
    WatchStats                          stats_;
    ThreadPool                          pool_;      // declared last: joined first
};

} // namespace fia
