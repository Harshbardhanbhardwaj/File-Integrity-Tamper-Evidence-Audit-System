// scanner.hpp - directory walking, hashing and baseline comparison.
#pragma once
#include <optional>
#include <string>
#include <vector>

#include "fiaudit/baseline.hpp"
#include "fiaudit/types.hpp"
#include "fiaudit/util.hpp"

namespace fia {

enum class ChangeKind { Added, Modified, Deleted, MetaChanged, TypeChanged };
const char* to_string(ChangeKind k) noexcept;
EventType   event_type_for(ChangeKind k) noexcept;

struct Change {
    ChangeKind  kind;
    std::string path;
    std::string old_hash, new_hash;   // hex ("" if n/a)
    std::string detail;               // human readable
};

struct ScanOptions {
    std::vector<std::string> excludes;
    unsigned threads = 0;     // 0 = hardware concurrency
    bool     quick = false;   // compare only: trust size+mtime (fast but forgeable!)
};

struct CompareResult {
    std::vector<Change>      changes;
    std::vector<std::string> errors;   // unreadable files etc.
    std::size_t              scanned = 0;
};

// lstat() (+ optional hashing) -> FileRecord. nullopt if not a file/symlink.
// Throws SysError (ENOENT etc.).
std::optional<FileRecord> make_record(const std::string& path, bool with_hash);

// Absolute, normalised form ("/a/b/../c/" -> "/a/c").
std::string normalise_path(const std::string& p);

// All regular files + symlinks below root (no symlink following).
std::vector<std::string> list_files(const std::string& root, const ExcludeSet& ex);

Baseline      build_baseline(const std::string& root, const ScanOptions& opt);
CompareResult compare_with_baseline(const Baseline& bl, const ScanOptions& opt);

// Pure comparison of one file: old (maybe null) vs now (maybe null).
std::optional<Change> classify(const FileRecord* old_rec, const FileRecord* now_rec);

} // namespace fia
