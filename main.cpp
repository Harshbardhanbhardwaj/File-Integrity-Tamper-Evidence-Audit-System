// main.cpp - fiaudit command line interface.
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <iostream>
#include <map>
#include <set>
#include <sstream>

#include "fiaudit/audit_log.hpp"
#include "fiaudit/baseline.hpp"
#include "fiaudit/device.hpp"
#include "fiaudit/scanner.hpp"
#include "fiaudit/types.hpp"
#include "fiaudit/util.hpp"
#include "fiaudit/watcher.hpp"

using namespace fia;

namespace {

enum Exit { kOk = 0, kChanges = 1, kError = 2, kUsage = 64 };


void usage() {
    std::cout << "fiaudit - File Integrity & Tamper-Evidence Audit System v" << kVersion << R"(

USAGE: fiaudit <command> [options]

COMMANDS
  init <dir>        Scan <dir> and write a trusted baseline
  check             Compare the tree with the baseline (one-shot audit)
  watch             Real-time monitoring (inotify) until SIGINT/SIGTERM
  verify-log        Verify the hash chain of the audit log (+ kernel cross-check)
  show-log          Print audit log records
  device-stats      Show kernel driver statistics
  help              This text

COMMON OPTIONS
  --baseline FILE   Baseline file            (default: ./fiaudit.baseline)
  --log FILE        Audit log file           (default: ./fiaudit.log)
  --device PATH     Kernel device, or 'sim' (in-memory model) or 'none'
                    (default: /dev/fiaudit, silently skipped if absent)
  --require-device  Fail if the device cannot be opened
  --exclude PAT     Exclude pattern (repeatable; init only, stored in baseline)
  --threads N       Worker threads for hashing
  --verbose         Debug logging

check:      --quick (trust size+mtime)  --json  (writes to log only if --log given)
watch:      --debounce MS (300)  --heartbeat SEC  --no-initial-scan  --force
show-log:   --tail N (default 20)

EXIT CODES: 0 clean/ok, 1 changes or tampering detected, 2 error, 64 usage
)";
}

struct Opts {
    std::vector<std::string>                     pos;
    std::map<std::string, std::vector<std::string>> kv;
    std::set<std::string>                        flags;
    bool has(const std::string& k) const { return kv.count(k) || flags.count(k); }
    std::string get(const std::string& k, const std::string& def) const {
        auto it = kv.find(k);
        return it == kv.end() || it->second.empty() ? def : it->second.back();
    }
};

bool parse_args(int argc, char** argv, int start, Opts& o, std::string& err) {
    static const std::set<std::string> valued = {"baseline", "log", "device", "exclude",
                                                 "threads", "tail", "debounce", "heartbeat"};
    static const std::set<std::string> boolean = {"quick", "json", "force", "no-initial-scan",
                                                  "verbose", "require-device", "help"};
    for (int i = start; i < argc; ++i) {
        std::string a = argv[i];
        if (a.rfind("--", 0) != 0) { o.pos.push_back(a); continue; }
        std::string key = a.substr(2), val;
        auto eq = key.find('=');
        bool has_val = false;
        if (eq != std::string::npos) { val = key.substr(eq + 1); key = key.substr(0, eq); has_val = true; }
        if (valued.count(key)) {
            if (!has_val) {
                if (i + 1 >= argc) { err = "option --" + key + " needs a value"; return false; }
                val = argv[++i];
            }
            o.kv[key].push_back(val);
        } else if (boolean.count(key)) {
            o.flags.insert(key);
        } else {
            err = "unknown option --" + key;
            return false;
        }
    }
    return true;
}

unsigned num_opt(const Opts& o, const std::string& k, unsigned def) {
    if (!o.has(k)) return def;
    return static_cast<unsigned>(std::strtoul(o.get(k, "0").c_str(), nullptr, 10));
}

struct AuditCtx {
    std::unique_ptr<IAuditSink> sink;
    std::unique_ptr<AuditLog>   log;
    std::unique_ptr<Auditor>    auditor;
};

AuditCtx open_ctx(const Opts& o) {
    AuditCtx c;
    c.sink = open_sink(o.get("device", kDefaultDevice), o.has("require-device"));
    c.log = std::make_unique<AuditLog>(o.get("log", "fiaudit.log"));
    c.auditor = std::make_unique<Auditor>(*c.log, *c.sink);
    return c;
}

std::string json_escape(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); o += b; }
                else o += static_cast<char>(c);
        }
    }
    return o;
}

// -------------------------------------------------------------------- init
int cmd_init(const Opts& o) {
    if (o.pos.size() != 1) { std::cerr << "init: expected exactly one directory\n"; return kUsage; }
    std::string bl_path = o.get("baseline", "fiaudit.baseline");

    ScanOptions so;
    so.excludes = o.kv.count("exclude") ? o.kv.at("exclude") : std::vector<std::string>{};
    so.threads = num_opt(o, "threads", 0);
    // never track our own state files if they live inside the tree
    so.excludes.push_back(normalise_path(bl_path));
    so.excludes.push_back(normalise_path(o.get("log", "fiaudit.log")));

    Baseline bl = build_baseline(o.pos[0], so);
    bl.save(bl_path);
    std::cout << "baseline written: " << bl_path << "\n"
              << "  root : " << bl.root << "\n"
              << "  files: " << bl.files.size() << "\n";

    AuditCtx c = open_ctx(o);
    c.auditor->record(EventType::Scan, bl.root,
                      "baseline created: files=" + std::to_string(bl.files.size()));
    std::cout << "  sink : " << c.sink->name() << "\n";
    return kOk;
}

// -------------------------------------------------------------------- check
int cmd_check(const Opts& o) {
    Baseline bl = Baseline::load(o.get("baseline", "fiaudit.baseline"));
    ScanOptions so;
    so.quick = o.has("quick");
    so.threads = num_opt(o, "threads", 0);
    so.excludes.push_back(normalise_path(o.get("log", "fiaudit.log")));
    so.excludes.push_back(normalise_path(o.get("baseline", "fiaudit.baseline")));

    CompareResult r = compare_with_baseline(bl, so);

    if (o.has("log")) {
        AuditCtx c = open_ctx(o);
        for (const auto& ch : r.changes) {
            std::string d = ch.detail;
            if (!ch.old_hash.empty()) d += "; old=" + ch.old_hash.substr(0, 16);
            if (!ch.new_hash.empty()) d += "; new=" + ch.new_hash.substr(0, 16);
            c.auditor->record(event_type_for(ch.kind), ch.path, d);
        }
        c.auditor->record(EventType::Scan, bl.root,
                          "check: scanned=" + std::to_string(r.scanned) +
                          " changes=" + std::to_string(r.changes.size()));
    }

    if (o.has("json")) {
        std::cout << "{\"root\":\"" << json_escape(bl.root) << "\",\"scanned\":" << r.scanned
                  << ",\"changes\":[";
        for (std::size_t i = 0; i < r.changes.size(); ++i) {
            const Change& c = r.changes[i];
            std::cout << (i ? "," : "") << "{\"kind\":\"" << to_string(c.kind) << "\",\"path\":\""
                      << json_escape(c.path) << "\",\"detail\":\"" << json_escape(c.detail) << "\"}";
        }
        std::cout << "],\"errors\":" << r.errors.size() << "}\n";
    } else {
        for (const auto& c : r.changes)
            std::cout << "[" << to_string(c.kind) << "] " << c.path << "  (" << c.detail << ")\n";
        for (const auto& e : r.errors) std::cout << "[ERROR] " << e << "\n";
        std::cout << "scanned " << r.scanned << " files, " << r.changes.size()
                  << " change(s), " << r.errors.size() << " error(s)\n";
    }
    return r.changes.empty() ? kOk : kChanges;
}

// -------------------------------------------------------------------- watch
std::atomic<Watcher*> g_watcher{nullptr};

extern "C" void on_stop(int) {
    if (Watcher* w = g_watcher.load()) w->request_stop();
}
extern "C" void on_hup(int) {
    if (Watcher* w = g_watcher.load()) w->request_reload();
}

int cmd_watch(const Opts& o) {
    std::string bl_path = o.get("baseline", "fiaudit.baseline");
    std::string log_path = o.get("log", "fiaudit.log");

    auto bl = std::make_shared<Baseline>(Baseline::load(bl_path));

    // Refuse to extend a log that is already broken, unless --force.
    bool broken = false;
    {
        struct stat st;
        if (::stat(log_path.c_str(), &st) == 0 && st.st_size > 0) {
            VerifyResult v = AuditLog::verify(log_path);
            if (!v.ok) {
                std::cerr << "audit log FAILED verification at line " << v.bad_line << ": "
                          << v.message << "\n";
                if (!o.has("force")) {
                    std::cerr << "refusing to continue (use --force to append a TAMPER record and go on)\n";
                    return kError;
                }
                broken = true;
            }
        }
    }

    AuditCtx c = open_ctx(o);
    if (broken)
        c.auditor->record(EventType::Tamper, log_path, "log failed verification before watch start");

    WatchConfig cfg;
    cfg.baseline_path = bl_path;
    cfg.baseline = bl;
    cfg.extra_excludes = {normalise_path(log_path), normalise_path(bl_path)};
    cfg.debounce = std::chrono::milliseconds(num_opt(o, "debounce", 300));
    cfg.threads = num_opt(o, "threads", 2);
    cfg.heartbeat_sec = num_opt(o, "heartbeat", 0);
    cfg.initial_scan = !o.has("no-initial-scan");

    Watcher w(cfg, *c.auditor);
    g_watcher.store(&w);

    struct sigaction sa;
    std::memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = on_stop;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sa.sa_handler = on_hup;
    sigaction(SIGHUP, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);

    w.run();
    g_watcher.store(nullptr);

    WatchStats s = w.stats();
    std::cerr << "stopped: inotify_events=" << s.inotify_events
              << " paths=" << s.paths_processed << " alerts=" << s.alerts
              << " overflows=" << s.overflows << "\n";
    return kOk;
}

// -------------------------------------------------------------------- verify-log
int cmd_verify_log(const Opts& o) {
    std::string log_path = o.get("log", "fiaudit.log");
    VerifyResult v = AuditLog::verify(log_path);
    if (!v.ok) {
        std::cout << "TAMPER DETECTED in " << log_path << " at line " << v.bad_line << ": "
                  << v.message << "\n";
        return kChanges;
    }
    std::cout << "hash chain OK: " << v.records << " record(s), head=" << v.last_hash.substr(0, 16)
              << "...\n";

    auto sink = open_sink(o.get("device", kDefaultDevice), o.has("require-device"));
    if (!sink->available()) {
        std::cout << "kernel cross-check: skipped (no device)\n";
        return kOk;
    }
    std::size_t match = 0, mismatch = 0, gone = 0;
    for (const auto& r : AuditLog::read_all(log_path)) {
        if (r.kseq == 0) continue;
        switch (sink->verify(r.kseq, r.khash)) {
            case VerifyStatus::Match: ++match; break;
            case VerifyStatus::Mismatch: ++mismatch; break;
            default: ++gone; break;
        }
    }
    std::cout << "kernel cross-check (" << sink->name() << "): match=" << match
              << " mismatch=" << mismatch << " not-retained=" << gone << "\n";
    if (auto st = sink->stats()) {
        if (v.last_kseq && st->total > v.last_kseq)
            std::cout << "note: kernel holds " << (st->total - v.last_kseq)
                      << " newer event(s) than the log's last record (tail truncation, "
                         "heartbeats, or other writers)\n";
    }
    if (mismatch) {
        std::cout << "TAMPER DETECTED: log disagrees with kernel memory\n";
        return kChanges;
    }
    return kOk;
}

// -------------------------------------------------------------------- show-log
int cmd_show_log(const Opts& o) {
    auto recs = AuditLog::read_all(o.get("log", "fiaudit.log"));
    std::size_t tail = num_opt(o, "tail", 20);
    std::size_t from = recs.size() > tail ? recs.size() - tail : 0;
    for (std::size_t i = from; i < recs.size(); ++i) {
        const auto& r = recs[i];
        std::cout << "#" << r.seq << " " << iso_time(r.ts_ns) << " " << r.type << " " << r.path;
        if (!r.detail.empty()) std::cout << "  [" << r.detail << "]";
        if (r.kseq) std::cout << "  k#" << r.kseq;
        std::cout << "\n";
    }
    std::cout << "(" << recs.size() << " record(s) total)\n";
    return kOk;
}

// -------------------------------------------------------------------- device-stats
int cmd_device_stats(const Opts& o) {
    auto sink = open_sink(o.get("device", kDefaultDevice), true);
    auto st = sink->stats();
    if (!st) { std::cerr << "device does not report stats\n"; return kError; }
    std::cout << "sink       : " << sink->name() << "\n"
              << "total      : " << st->total << "\n"
              << "oldest seq : " << st->oldest << "\n"
              << "capacity   : " << st->capacity << "\n"
              << "chain head : " << st->head_hex << "\n";
    if (auto* k = dynamic_cast<KernelSink*>(sink.get())) {
        auto evs = k->read_events(5);
        for (const auto& e : evs)
            std::cout << "  event #" << e.seq << " " << to_string(static_cast<EventType>(e.type))
                      << " pid=" << e.pid << " " << e.path << "\n";
    }
    return kOk;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return kUsage; }
    std::string cmd = argv[1];
    if (cmd == "help" || cmd == "--help" || cmd == "-h") { usage(); return kOk; }
    if (cmd == "version" || cmd == "--version") { std::cout << "fiaudit " << kVersion << "\n"; return kOk; }

    Opts o;
    std::string err;
    if (!parse_args(argc, argv, 2, o, err)) { std::cerr << "error: " << err << "\n"; return kUsage; }
    set_verbose(o.has("verbose"));

    try {
        if (cmd == "init")         return cmd_init(o);
        if (cmd == "check")        return cmd_check(o);
        if (cmd == "watch")        return cmd_watch(o);
        if (cmd == "verify-log")   return cmd_verify_log(o);
        if (cmd == "show-log")     return cmd_show_log(o);
        if (cmd == "device-stats") return cmd_device_stats(o);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return kError;
    }
    std::cerr << "unknown command '" << cmd << "'\n";
    usage();
    return kUsage;
}
