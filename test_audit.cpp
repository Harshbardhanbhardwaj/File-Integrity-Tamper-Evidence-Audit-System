// Unit tests: hash-chained log, kernel-sink model, auditor, watcher (integration-level).
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include "fiaudit/audit_log.hpp"
#include "fiaudit/device.hpp"
#include "fiaudit/watcher.hpp"
#include "test_framework.hpp"

using namespace fia;

static std::string slurp(const std::string& p) {
    std::ifstream in(p, std::ios::binary);
    std::stringstream ss; ss << in.rdbuf(); return ss.str();
}
static void spit(const std::string& p, const std::string& s) {
    std::ofstream o(p, std::ios::binary | std::ios::trunc); o << s;
}

static void fill_log(const std::string& path, int n) {
    AuditLog log(path);
    for (int i = 0; i < n; ++i)
        log.append(EventType::Modify, "/f/" + std::to_string(i), "detail " + std::to_string(i));
}

TEST(log_append_and_verify) {
    tf::TempDir d;
    fill_log(d / "log", 5);
    VerifyResult v = AuditLog::verify(d / "log");
    CHECK(v.ok);
    CHECK_EQ(v.records, std::size_t(5));
    CHECK_EQ(AuditLog::read_all(d / "log").size(), std::size_t(5));
}

TEST(log_reopen_continues_chain) {
    tf::TempDir d;
    fill_log(d / "log", 3);
    fill_log(d / "log", 2);                 // new AuditLog instance on same file
    VerifyResult v = AuditLog::verify(d / "log");
    CHECK(v.ok);
    CHECK_EQ(v.records, std::size_t(5));
}

TEST(log_detects_modified_record) {
    tf::TempDir d;
    fill_log(d / "log", 5);
    std::string t = slurp(d / "log");
    auto p = t.find("/f/2");
    t.replace(p, 4, "/f/9");               // attacker rewrites a path
    spit(d / "log", t);
    VerifyResult v = AuditLog::verify(d / "log");
    CHECK(!v.ok);
    CHECK_EQ(v.bad_line, std::size_t(3));
}

TEST(log_detects_deleted_record) {
    tf::TempDir d;
    fill_log(d / "log", 5);
    auto lines = split(slurp(d / "log"), '\n');
    lines.erase(lines.begin() + 2);          // remove record #3
    std::string out;
    for (auto& l : lines) if (!l.empty()) out += l + "\n";
    spit(d / "log", out);
    VerifyResult v = AuditLog::verify(d / "log");
    CHECK(!v.ok);
    CHECK_EQ(v.bad_line, std::size_t(3));
}

TEST(log_detects_swapped_records) {
    tf::TempDir d;
    fill_log(d / "log", 4);
    auto lines = split(slurp(d / "log"), '\n');
    std::swap(lines[1], lines[2]);
    std::string out;
    for (auto& l : lines) if (!l.empty()) out += l + "\n";
    spit(d / "log", out);
    CHECK(!AuditLog::verify(d / "log").ok);
}

TEST(log_detects_partial_last_line) {
    tf::TempDir d;
    fill_log(d / "log", 3);
    std::string t = slurp(d / "log");
    t.pop_back();                            // lose final newline
    spit(d / "log", t);
    VerifyResult v = AuditLog::verify(d / "log");
    CHECK(!v.ok);
}

TEST(log_tail_truncation_is_NOT_detectable_by_chain_alone) {
    // Documents the known limitation that motivates the kernel anchor.
    tf::TempDir d;
    fill_log(d / "log", 5);
    auto lines = split(slurp(d / "log"), '\n');
    std::string out;
    for (int i = 0; i < 3; ++i) out += lines[i] + "\n";
    spit(d / "log", out);
    CHECK(AuditLog::verify(d / "log").ok);   // internally consistent...
}

TEST(log_escapes_special_characters) {
    tf::TempDir d;
    {
        AuditLog log(d / "log");
        log.append(EventType::Create, "/tmp/we\tird\nname", "d\te\nt");
    }
    CHECK(AuditLog::verify(d / "log").ok);
    auto recs = AuditLog::read_all(d / "log");
    CHECK_EQ(recs[0].path, "/tmp/we\tird\nname");
    CHECK_EQ(recs[0].detail, "d\te\nt");
}

TEST(log_concurrent_appends_stay_valid) {
    tf::TempDir d;
    AuditLog log(d / "log");
    std::vector<std::thread> th;
    for (int t = 0; t < 4; ++t)
        th.emplace_back([&log, t] {
            for (int i = 0; i < 25; ++i) log.append(EventType::Modify, "/t" + std::to_string(t), "x");
        });
    for (auto& x : th) x.join();
    VerifyResult v = AuditLog::verify(d / "log");
    CHECK(v.ok);
    CHECK_EQ(v.records, std::size_t(100));
}

TEST(log_two_writers_share_one_file) {
    tf::TempDir d;
    AuditLog a(d / "log");
    AuditLog b(d / "log");                   // second handle (like a second process)
    a.append(EventType::Modify, "/1", "");
    b.append(EventType::Modify, "/2", "");   // must notice a's record and continue chain
    a.append(EventType::Modify, "/3", "");
    VerifyResult v = AuditLog::verify(d / "log");
    CHECK(v.ok);
    CHECK_EQ(v.records, std::size_t(3));
}

TEST(memory_sink_chain_and_verify) {
    MemorySink s(8);
    auto r1 = s.submit(EventType::Create, "/a");
    auto r2 = s.submit(EventType::Modify, "/a");
    CHECK(r1.ok && r2.ok);
    CHECK_EQ(r1.seq, std::uint64_t(1));
    CHECK_EQ(r2.seq, std::uint64_t(2));
    CHECK(r1.chain_hex != r2.chain_hex);
    CHECK(s.verify(1, r1.chain_hex) == VerifyStatus::Match);
    CHECK(s.verify(1, r2.chain_hex) == VerifyStatus::Mismatch);
    CHECK(s.verify(99, r2.chain_hex) == VerifyStatus::NotRetained);
    auto st = s.stats();            // keep the optional alive (no dangling reference)
    CHECK_EQ(st->head_hex, r2.chain_hex);
}

TEST(memory_sink_ring_overwrites_oldest) {
    MemorySink s(16);
    for (int i = 0; i < 40; ++i) s.submit(EventType::Modify, "/x");
    auto st = s.stats();
    CHECK_EQ(st->total, std::uint64_t(40));
    CHECK_EQ(st->oldest, std::uint64_t(25));
    CHECK(s.verify(5, std::string(64, '0')) == VerifyStatus::NotRetained);
}

TEST(auditor_links_log_and_kernel_chain) {
    tf::TempDir d;
    AuditLog log(d / "log");
    MemorySink sink;
    Auditor aud(log, sink);
    aud.record(EventType::Modify, "/etc/passwd", "changed");
    aud.record(EventType::Delete, "/etc/shadow", "gone");
    auto recs = AuditLog::read_all(d / "log");
    CHECK_EQ(recs.size(), std::size_t(2));
    CHECK_EQ(recs[1].kseq, std::uint64_t(2));
    CHECK(sink.verify(recs[1].kseq, recs[1].khash) == VerifyStatus::Match);
}

TEST(kernel_anchor_catches_consistently_rewritten_log) {
    // Attacker rewrites the WHOLE log with a valid chain; kernel values no longer match.
    tf::TempDir d;
    MemorySink sink;
    {
        AuditLog log(d / "log");
        Auditor aud(log, sink);
        aud.record(EventType::Modify, "/secret", "attacker edit");
        aud.record(EventType::Create, "/other", "x");
    }
    std::remove((d / "log").c_str());
    {
        AuditLog forged(d / "log");            // fresh, perfectly valid chain
        forged.append(EventType::Create, "/other", "x", 2, std::string(64, 'a'));
    }
    CHECK(AuditLog::verify(d / "log").ok);     // chain alone is fooled
    auto r = AuditLog::read_all(d / "log")[0];
    CHECK(sink.verify(r.kseq, r.khash) == VerifyStatus::Mismatch);   // kernel is not
}

// ---- watcher (real inotify, in-process) ---------------------------------
static bool wait_for(const std::function<bool()>& pred, int ms = 4000) {
    for (int i = 0; i < ms / 20; ++i) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return pred();
}

static bool log_has(const std::string& log, const std::string& type, const std::string& path_suffix) {
    try {
        for (auto& r : AuditLog::read_all(log))
            if (r.type == type && r.path.size() >= path_suffix.size() &&
                r.path.compare(r.path.size() - path_suffix.size(), path_suffix.size(), path_suffix) == 0)
                return true;
    } catch (...) {}
    return false;
}

TEST(watcher_reports_live_changes) {
    tf::TempDir tree, state;
    tree.write("keep.txt", "original");
    tree.write("gone.txt", "to be deleted");
    tree.write("dir/inner.txt", "inner");
    auto bl = std::make_shared<Baseline>(build_baseline(tree.path(), {}));
    bl->save(state / "base");

    AuditLog log(state / "log");
    MemorySink sink;
    Auditor aud(log, sink);

    WatchConfig cfg;
    cfg.baseline_path = state / "base";
    cfg.baseline = bl;
    cfg.debounce = std::chrono::milliseconds(80);
    cfg.threads = 2;
    Watcher w(cfg, aud);
    std::thread th([&] { w.run(); });

    CHECK(wait_for([&] { return log_has(state / "log", "SCAN", tree.path()); }));   // started

    tree.write("keep.txt", "TAMPERED");
    unlink((tree / "gone.txt").c_str());
    tree.write("newdir/dropped.sh", "#!/bin/sh\nevil\n");     // new subtree + file
    chmod((tree / "dir/inner.txt").c_str(), 0777);

    CHECK(wait_for([&] { return log_has(state / "log", "MODIFY", "/keep.txt"); }));
    CHECK(wait_for([&] { return log_has(state / "log", "DELETE", "/gone.txt"); }));
    CHECK(wait_for([&] { return log_has(state / "log", "CREATE", "/newdir/dropped.sh"); }));
    CHECK(wait_for([&] { return log_has(state / "log", "ATTRIB", "/dir/inner.txt"); }));

    // restoring original content is reported as "restored"
    tree.write("keep.txt", "original");
    CHECK(wait_for([&] {
        for (auto& r : AuditLog::read_all(state / "log"))
            if (r.type == "SCAN" && r.detail.find("restored") != std::string::npos) return true;
        return false; }));

    w.request_stop();
    th.join();
    VerifyResult v = AuditLog::verify(state / "log");
    CHECK(v.ok);
    // every record that went through the sink is verifiable against it
    for (auto& r : AuditLog::read_all(state / "log"))
        CHECK(sink.verify(r.kseq, r.khash) == VerifyStatus::Match);
}

TEST(watcher_ignores_excluded_paths) {
    tf::TempDir tree, state;
    tree.write("a.txt", "a");
    ScanOptions so; so.excludes = {"*.tmp"};
    auto bl = std::make_shared<Baseline>(build_baseline(tree.path(), so));
    AuditLog log(state / "log");
    MemorySink sink;
    Auditor aud(log, sink);
    WatchConfig cfg; cfg.baseline = bl; cfg.baseline_path = state / "b";
    cfg.debounce = std::chrono::milliseconds(50);
    Watcher w(cfg, aud);
    std::thread th([&] { w.run(); });
    CHECK(wait_for([&] { return log_has(state / "log", "SCAN", tree.path()); }));
    tree.write("noise.tmp", "ignored");
    tree.write("real.txt", "seen");
    CHECK(wait_for([&] { return log_has(state / "log", "CREATE", "/real.txt"); }));
    w.request_stop();
    th.join();
    CHECK(!log_has(state / "log", "CREATE", "/noise.tmp"));
}
