// baseline.hpp - trusted snapshot ("known good state") of a directory tree.
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace fia {

struct FileRecord {
    std::string   path;            // absolute path
    char          kind = 'f';      // 'f' regular file, 'l' symlink
    std::uint64_t size = 0;
    std::int64_t  mtime_ns = 0;
    std::uint32_t mode = 0;        // permission bits + type (st_mode)
    std::uint32_t uid = 0, gid = 0;
    std::string   sha256;          // hex; for symlinks: hash of the link target

    bool same_content(const FileRecord& o) const { return kind == o.kind && sha256 == o.sha256; }
    bool same_meta(const FileRecord& o) const {
        return mode == o.mode && uid == o.uid && gid == o.gid;
    }
};

// On-disk format (text, TAB separated):
//   FIABASE1
//   R <root>
//   T <created_ns>
//   X <exclude pattern>            (0..n)
//   F <path> <size> <mtime_ns> <mode-octal> <uid> <gid> <kind> <sha256>
//   END sha256=<hash of all preceding bytes>
// The trailer makes the baseline itself tamper-evident.
class Baseline {
public:
    std::string                       root;
    std::uint64_t                     created_ns = 0;
    std::vector<std::string>          excludes;
    std::map<std::string, FileRecord> files;

    const FileRecord* find(const std::string& path) const {
        auto it = files.find(path);
        return it == files.end() ? nullptr : &it->second;
    }

    void save(const std::string& path) const;        // atomic: tmp + fsync + rename
    static Baseline load(const std::string& path);   // throws on corruption/tamper
};

} // namespace fia
