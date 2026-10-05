#include "fiaudit/scanner.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <future>
#include <map>
#include <thread>

#include "fiaudit/sha256.hpp"
#include "fiaudit/thread_pool.hpp"

namespace fs = std::filesystem;

namespace fia {

const char* to_string(ChangeKind k) noexcept {
    switch (k) {
        case ChangeKind::Added:       return "ADDED";
        case ChangeKind::Modified:    return "MODIFIED";
        case ChangeKind::Deleted:     return "DELETED";
        case ChangeKind::MetaChanged: return "META";
        case ChangeKind::TypeChanged: return "TYPE";
    }
    return "?";
}

EventType event_type_for(ChangeKind k) noexcept {
    switch (k) {
        case ChangeKind::Added:       return EventType::Create;
        case ChangeKind::Modified:    return EventType::Modify;
        case ChangeKind::Deleted:     return EventType::Delete;
        case ChangeKind::MetaChanged: return EventType::Attrib;
        case ChangeKind::TypeChanged: return EventType::Modify;
    }
    return EventType::Scan;
}

std::string normalise_path(const std::string& p) {
    std::string s = fs::absolute(fs::path(p)).lexically_normal().string();
    while (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
}

std::optional<FileRecord> make_record(const std::string& path, bool with_hash) {
    struct stat st;
    if (::lstat(path.c_str(), &st) != 0) throw SysError("lstat " + path);

    FileRecord r;
    r.path     = path;
    r.size     = static_cast<std::uint64_t>(st.st_size);
    r.mtime_ns = static_cast<std::int64_t>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
    r.mode     = st.st_mode;
    r.uid      = st.st_uid;
    r.gid      = st.st_gid;

    if (S_ISREG(st.st_mode)) {
        r.kind = 'f';
        if (with_hash) r.sha256 = to_hex(Sha256::hash_file(path));
    } else if (S_ISLNK(st.st_mode)) {
        r.kind = 'l';
        char buf[4096];
        ssize_t n = ::readlink(path.c_str(), buf, sizeof buf);
        if (n < 0) throw SysError("readlink " + path);
        r.sha256 = Sha256::hash_hex(std::string_view(buf, static_cast<std::size_t>(n)));
    } else {
        return std::nullopt;     // dirs, sockets, fifos, devices: not tracked
    }
    return r;
}

std::vector<std::string> list_files(const std::string& root, const ExcludeSet& ex) {
    std::vector<std::string> out;
    std::error_code ec;
    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
    if (ec) throw SysError("open directory " + root, ec.value());
    while (it != end) {
        std::string p = it->path().string();
        std::error_code ec2;
        fs::file_status st = it->symlink_status(ec2);
        if (ex.excluded(p)) {
            if (!ec2 && fs::is_directory(st)) it.disable_recursion_pending();
        } else if (!ec2 && (fs::is_regular_file(st) || fs::is_symlink(st))) {
            out.push_back(std::move(p));
        }
        it.increment(ec);
        if (ec) { log_warn("directory walk stopped: " + ec.message()); break; }
    }
    std::sort(out.begin(), out.end());
    return out;
}

static unsigned pick_threads(unsigned requested) {
    if (requested) return requested;
    unsigned hc = std::thread::hardware_concurrency();
    return hc ? hc : 2;
}

Baseline build_baseline(const std::string& root_in, const ScanOptions& opt) {
    std::error_code ec;
    fs::path canon = fs::canonical(root_in, ec);
    if (ec) throw SysError("cannot resolve " + root_in, ec.value());
    if (!fs::is_directory(canon)) throw SysError("not a directory: " + root_in, ENOTDIR);

    Baseline bl;
    bl.root       = canon.string();
    bl.created_ns = now_real_ns();
    bl.excludes   = opt.excludes;

    ExcludeSet ex(opt.excludes, bl.root);
    auto files = list_files(bl.root, ex);

    ThreadPool pool(pick_threads(opt.threads));
    std::vector<std::future<std::optional<FileRecord>>> futs;
    futs.reserve(files.size());
    for (const auto& f : files)
        futs.push_back(pool.submit([f] { return make_record(f, true); }));

    for (std::size_t i = 0; i < futs.size(); ++i) {
        try {
            auto r = futs[i].get();
            if (r) bl.files[r->path] = std::move(*r);
        } catch (const SysError& e) {
            log_warn(std::string("skipped: ") + e.what());
        }
    }
    return bl;
}

CompareResult compare_with_baseline(const Baseline& bl, const ScanOptions& opt) {
    CompareResult res;
    std::vector<std::string> pats = bl.excludes;
    pats.insert(pats.end(), opt.excludes.begin(), opt.excludes.end());
    ExcludeSet ex(pats, bl.root);

    auto files = list_files(bl.root, ex);

    ThreadPool pool(pick_threads(opt.threads));
    using Fut = std::future<std::optional<FileRecord>>;
    std::vector<Fut> futs;
    futs.reserve(files.size());
    const bool quick = opt.quick;
    for (const auto& f : files) {
        const FileRecord* old = bl.find(f);
        futs.push_back(pool.submit([f, old, quick]() -> std::optional<FileRecord> {
            auto r = make_record(f, false);
            if (!r) return r;
            if (r->kind == 'f') {
                if (quick && old && old->kind == 'f' && old->size == r->size &&
                    old->mtime_ns == r->mtime_ns)
                    r->sha256 = old->sha256;               // trust metadata (fast path)
                else
                    r->sha256 = to_hex(Sha256::hash_file(f));
            }
            return r;
        }));
    }

    std::map<std::string, FileRecord> now;
    for (std::size_t i = 0; i < futs.size(); ++i) {
        try {
            auto r = futs[i].get();
            if (r) now[r->path] = std::move(*r);
            ++res.scanned;
        } catch (const SysError& e) {
            res.errors.push_back(e.what());
        }
    }

    for (const auto& kv : now) {
        auto c = classify(bl.find(kv.first), &kv.second);
        if (c) res.changes.push_back(std::move(*c));
    }
    for (const auto& kv : bl.files) {
        if (now.count(kv.first) || ex.excluded(kv.first)) continue;
        // present in baseline, not seen now: genuinely gone, or unreadable (already in errors)
        bool unreadable = false;
        for (const auto& e : res.errors)
            if (e.find(kv.first) != std::string::npos) { unreadable = true; break; }
        if (unreadable) continue;
        auto c = classify(&kv.second, nullptr);
        if (c) res.changes.push_back(std::move(*c));
    }
    std::sort(res.changes.begin(), res.changes.end(),
              [](const Change& a, const Change& b) { return a.path < b.path; });
    return res;
}

static std::string mode_str(std::uint32_t m) {
    char b[16];
    std::snprintf(b, sizeof b, "%04o", m & 07777);
    return b;
}

std::optional<Change> classify(const FileRecord* o, const FileRecord* n) {
    if (!o && !n) return std::nullopt;
    Change c;
    if (!o) {
        c.kind = ChangeKind::Added;
        c.path = n->path;
        c.new_hash = n->sha256;
        c.detail = "new file, size=" + std::to_string(n->size);
        return c;
    }
    if (!n) {
        c.kind = ChangeKind::Deleted;
        c.path = o->path;
        c.old_hash = o->sha256;
        c.detail = "file no longer present";
        return c;
    }
    c.path = n->path;
    c.old_hash = o->sha256;
    c.new_hash = n->sha256;
    if (o->kind != n->kind) {
        c.kind = ChangeKind::TypeChanged;
        c.detail = std::string("type ") + o->kind + " -> " + n->kind;
        return c;
    }
    bool content = o->sha256 != n->sha256;
    bool meta = !o->same_meta(*n);
    if (!content && !meta) return std::nullopt;

    std::string d;
    if (content) d += "size " + std::to_string(o->size) + " -> " + std::to_string(n->size);
    if (meta) {
        if (!d.empty()) d += "; ";
        d += "mode " + mode_str(o->mode) + " -> " + mode_str(n->mode);
        if (o->uid != n->uid) d += "; uid " + std::to_string(o->uid) + " -> " + std::to_string(n->uid);
        if (o->gid != n->gid) d += "; gid " + std::to_string(o->gid) + " -> " + std::to_string(n->gid);
    }
    c.kind = content ? ChangeKind::Modified : ChangeKind::MetaChanged;
    c.detail = d;
    return c;
}

} // namespace fia
