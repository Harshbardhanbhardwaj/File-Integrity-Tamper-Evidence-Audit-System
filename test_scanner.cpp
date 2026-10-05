// Unit tests: baseline persistence and scanner/compare logic.
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include "fiaudit/baseline.hpp"
#include "fiaudit/scanner.hpp"
#include "test_framework.hpp"

using namespace fia;

static bool has_change(const CompareResult& r, ChangeKind k, const std::string& path) {
    return std::any_of(r.changes.begin(), r.changes.end(),
                       [&](const Change& c) { return c.kind == k && c.path == path; });
}

static void make_tree(const tf::TempDir& d) {
    d.write("a.txt", "alpha");
    d.write("sub/b.txt", "bravo");
    d.write("sub/deep/c.txt", "charlie");
    d.write("skip.tmp", "temporary");
}

TEST(baseline_build_and_roundtrip) {
    tf::TempDir d, out;
    make_tree(d);
    ScanOptions o; o.excludes = {"*.tmp"}; o.threads = 2;
    Baseline b = build_baseline(d.path(), o);
    CHECK_EQ(b.files.size(), std::size_t(3));
    CHECK(b.find(d / "a.txt") != nullptr);
    CHECK(b.find(d / "skip.tmp") == nullptr);

    b.save(out / "base");
    Baseline l = Baseline::load(out / "base");
    CHECK_EQ(l.root, b.root);
    CHECK_EQ(l.files.size(), b.files.size());
    CHECK_EQ(l.find(d / "a.txt")->sha256, b.find(d / "a.txt")->sha256);
    CHECK_EQ(l.excludes.size(), std::size_t(1));
}

TEST(baseline_detects_own_tampering) {
    tf::TempDir d, out;
    make_tree(d);
    Baseline b = build_baseline(d.path(), {});
    b.save(out / "base");
    // attacker edits one hash inside the baseline file
    std::string text;
    { std::ifstream in(out / "base"); text.assign(std::istreambuf_iterator<char>(in), {}); }
    auto pos = text.find("F\t");
    text[text.find('\t', text.find('\t', pos + 2) + 1) + 1] = '9';   // change size field
    { std::ofstream o(out / "base", std::ios::trunc); o << text; }
    bool threw = false;
    try { Baseline::load(out / "base"); } catch (const std::runtime_error&) { threw = true; }
    CHECK(threw);
}

TEST(baseline_handles_weird_filenames) {
    tf::TempDir d, out;
    d.write("we ird\tname\n.txt", "x");
    Baseline b = build_baseline(d.path(), {});
    b.save(out / "base");
    Baseline l = Baseline::load(out / "base");
    CHECK_EQ(l.files.size(), std::size_t(1));
    CHECK(l.find(d / "we ird\tname\n.txt") != nullptr);
}

TEST(compare_clean_tree_has_no_changes) {
    tf::TempDir d;
    make_tree(d);
    Baseline b = build_baseline(d.path(), {});
    CompareResult r = compare_with_baseline(b, {});
    CHECK(r.changes.empty());
    CHECK_EQ(r.scanned, std::size_t(4));
}

TEST(compare_detects_modify_add_delete) {
    tf::TempDir d;
    make_tree(d);
    Baseline b = build_baseline(d.path(), {});
    d.write("a.txt", "ALPHA!");                       // modified
    d.write("new.txt", "fresh");                      // added
    unlink((d / "sub/b.txt").c_str());                // deleted
    CompareResult r = compare_with_baseline(b, {});
    CHECK(has_change(r, ChangeKind::Modified, d / "a.txt"));
    CHECK(has_change(r, ChangeKind::Added, d / "new.txt"));
    CHECK(has_change(r, ChangeKind::Deleted, d / "sub/b.txt"));
    CHECK(has_change(r, ChangeKind::Added, d / "skip.tmp") == false);   // was in baseline
    CHECK_EQ(r.changes.size(), std::size_t(3));
}

TEST(compare_detects_same_size_modification_with_forged_mtime) {
    tf::TempDir d;
    d.write("f.txt", "AAAA");
    Baseline b = build_baseline(d.path(), {});
    struct stat st; stat((d / "f.txt").c_str(), &st);
    d.write("f.txt", "BBBB");                          // same size
    struct timespec ts[2] = {st.st_atim, st.st_mtim};  // forge old mtime
    utimensat(AT_FDCWD, (d / "f.txt").c_str(), ts, 0);

    ScanOptions quick; quick.quick = true;
    CompareResult rq = compare_with_baseline(b, quick);
    CHECK(rq.changes.empty());                           // documented weakness of --quick
    CompareResult rf = compare_with_baseline(b, {});
    CHECK(has_change(rf, ChangeKind::Modified, d / "f.txt"));   // full hash catches it
}

TEST(compare_detects_permission_change) {
    tf::TempDir d;
    d.write("f.sh", "#!/bin/sh\n");
    chmod((d / "f.sh").c_str(), 0644);
    Baseline b = build_baseline(d.path(), {});
    chmod((d / "f.sh").c_str(), 0777);
    CompareResult r = compare_with_baseline(b, {});
    CHECK(has_change(r, ChangeKind::MetaChanged, d / "f.sh"));
}

TEST(symlinks_are_tracked_not_followed) {
    tf::TempDir d;
    d.write("target1", "t");
    CHECK(symlink("target1", (d / "link").c_str()) == 0);
    Baseline b = build_baseline(d.path(), {});
    CHECK_EQ(b.find(d / "link")->kind, 'l');
    unlink((d / "link").c_str());
    CHECK(symlink("target-other", (d / "link").c_str()) == 0);   // retargeted link
    CompareResult r = compare_with_baseline(b, {});
    CHECK(has_change(r, ChangeKind::Modified, d / "link"));
}

TEST(classify_pure_function) {
    FileRecord a; a.path = "/x"; a.sha256 = "aa"; a.mode = 0100644;
    FileRecord b = a;
    CHECK(!classify(&a, &b).has_value());
    b.sha256 = "bb";
    CHECK(classify(&a, &b)->kind == ChangeKind::Modified);
    b = a; b.mode = 0100600;
    CHECK(classify(&a, &b)->kind == ChangeKind::MetaChanged);
    CHECK(classify(nullptr, &a)->kind == ChangeKind::Added);
    CHECK(classify(&a, nullptr)->kind == ChangeKind::Deleted);
    CHECK(!classify(nullptr, nullptr).has_value());
}

TEST(normalise_path_cleans_input) {
    CHECK_EQ(normalise_path("/a/b/../c/"), "/a/c");
    CHECK_EQ(normalise_path("/"), "/");
}
