#include "fiaudit/baseline.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "fiaudit/sha256.hpp"
#include "fiaudit/util.hpp"

namespace fia {

static std::string body_of(const Baseline& b) {
    std::ostringstream o;
    o << "FIABASE1\n";
    o << "R\t" << pct_escape(b.root) << "\n";
    o << "T\t" << b.created_ns << "\n";
    for (const auto& x : b.excludes) o << "X\t" << pct_escape(x) << "\n";
    for (const auto& kv : b.files) {
        const FileRecord& r = kv.second;
        char mode[16];
        std::snprintf(mode, sizeof mode, "%o", r.mode);
        o << "F\t" << pct_escape(r.path) << "\t" << r.size << "\t" << r.mtime_ns << "\t"
          << mode << "\t" << r.uid << "\t" << r.gid << "\t" << r.kind << "\t" << r.sha256 << "\n";
    }
    return o.str();
}

void Baseline::save(const std::string& path) const {
    std::string body = body_of(*this);
    std::string text = body + "END\tsha256=" + Sha256::hash_hex(body) + "\n";

    std::string tmp = path + ".tmp." + std::to_string(::getpid());
    Fd fd(::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640));
    if (!fd.valid()) throw SysError("create " + tmp);
    const char* p = text.data();
    std::size_t left = text.size();
    while (left > 0) {
        ssize_t n = ::write(fd.get(), p, left);
        if (n < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            ::unlink(tmp.c_str());
            throw SysError("write " + tmp, e);
        }
        p += n;
        left -= static_cast<std::size_t>(n);
    }
    if (::fsync(fd.get()) != 0) { int e = errno; ::unlink(tmp.c_str()); throw SysError("fsync " + tmp, e); }
    fd.reset();
    if (::rename(tmp.c_str(), path.c_str()) != 0) { int e = errno; ::unlink(tmp.c_str()); throw SysError("rename " + tmp, e); }
}

Baseline Baseline::load(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw SysError("open baseline " + path, ENOENT);
    std::stringstream ss;
    ss << in.rdbuf();
    std::string all = ss.str();

    const std::string marker = "END\tsha256=";
    std::size_t pos = all.rfind(marker);
    if (pos == std::string::npos || (pos != 0 && all[pos - 1] != '\n'))
        throw std::runtime_error("baseline " + path + ": missing integrity trailer");
    std::string body = all.substr(0, pos);
    std::string want = all.substr(pos + marker.size());
    while (!want.empty() && (want.back() == '\n' || want.back() == '\r')) want.pop_back();
    if (Sha256::hash_hex(body) != want)
        throw std::runtime_error("baseline " + path + ": INTEGRITY CHECK FAILED (file was modified)");

    Baseline b;
    bool header = false;
    for (const auto& line : split(body, '\n')) {
        if (line.empty()) continue;
        if (!header) {
            if (line != "FIABASE1") throw std::runtime_error("baseline: bad header");
            header = true;
            continue;
        }
        auto f = split(line, '\t');
        if (f[0] == "R" && f.size() == 2) b.root = pct_unescape(f[1]);
        else if (f[0] == "T" && f.size() == 2) b.created_ns = std::strtoull(f[1].c_str(), nullptr, 10);
        else if (f[0] == "X" && f.size() == 2) b.excludes.push_back(pct_unescape(f[1]));
        else if (f[0] == "F" && f.size() == 9) {
            FileRecord r;
            r.path     = pct_unescape(f[1]);
            r.size     = std::strtoull(f[2].c_str(), nullptr, 10);
            r.mtime_ns = std::strtoll(f[3].c_str(), nullptr, 10);
            r.mode     = static_cast<std::uint32_t>(std::strtoul(f[4].c_str(), nullptr, 8));
            r.uid      = static_cast<std::uint32_t>(std::strtoul(f[5].c_str(), nullptr, 10));
            r.gid      = static_cast<std::uint32_t>(std::strtoul(f[6].c_str(), nullptr, 10));
            r.kind     = f[7].empty() ? 'f' : f[7][0];
            r.sha256   = f[8];
            b.files[r.path] = std::move(r);
        } else {
            throw std::runtime_error("baseline: malformed line: " + line);
        }
    }
    if (!header) throw std::runtime_error("baseline: empty");
    return b;
}

} // namespace fia
