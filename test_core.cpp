// Unit tests: SHA-256, utilities, thread pool, event types.
#include <atomic>
#include <cstring>
#include "fiaudit/sha256.hpp"
#include "fiaudit/thread_pool.hpp"
#include "fiaudit/util.hpp"
#include "test_framework.hpp"

using namespace fia;

TEST(sha256_known_vectors) {
    CHECK_EQ(Sha256::hash_hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK_EQ(Sha256::hash_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK_EQ(Sha256::hash_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(sha256_million_a) {
    Sha256 h;
    std::string chunk(1000, 'a');
    for (int i = 0; i < 1000; ++i) h.update(chunk);
    CHECK_EQ(to_hex(h.final()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(sha256_incremental_equals_oneshot) {
    std::string msg(1000, 'x');
    for (std::size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<char>('a' + i % 26);
    Sha256 h;
    for (std::size_t i = 0; i < msg.size(); i += 7) h.update(msg.substr(i, 7));
    CHECK_EQ(to_hex(h.final()), Sha256::hash_hex(msg));
}

TEST(sha256_file_matches_memory) {
    tf::TempDir d;
    std::string content(200000, 'q');
    d.write("big.bin", content);
    CHECK_EQ(to_hex(Sha256::hash_file(d / "big.bin")), Sha256::hash_hex(content));
}

TEST(sha256_file_errors) {
    tf::TempDir d;
    bool threw = false;
    try { Sha256::hash_file(d / "missing"); } catch (const SysError& e) { threw = (e.code() == ENOENT); }
    CHECK(threw);
    threw = false;
    try { Sha256::hash_file(d.path()); } catch (const SysError&) { threw = true; }   // directory
    CHECK(threw);
}

TEST(hex_roundtrip) {
    std::uint8_t in[4] = {0x00, 0xde, 0xad, 0xff}, out[4];
    CHECK_EQ(to_hex(in, 4), "00deadff");
    CHECK(from_hex("00deadff", out, 4));
    CHECK(std::memcmp(in, out, 4) == 0);
    CHECK(!from_hex("zz", out, 1));
    CHECK(!from_hex("00", out, 4));
}

TEST(percent_escape_roundtrip) {
    std::string nasty = "a\tb\nc%d\re";
    std::string esc = pct_escape(nasty);
    CHECK(esc.find('\t') == std::string::npos);
    CHECK(esc.find('\n') == std::string::npos);
    CHECK_EQ(pct_unescape(esc), nasty);
    CHECK_EQ(pct_unescape("100%"), "100%");     // dangling % is left alone
}

TEST(glob_matching) {
    CHECK(glob_match("*.tmp", "a.tmp"));
    CHECK(!glob_match("*.tmp", "a.tmpx"));
    CHECK(glob_match("a?c", "abc"));
    CHECK(glob_match("*", ""));
    CHECK(glob_match("/var/*/log", "/var/x/y/log"));
    CHECK(!glob_match("abc", "ab"));
}

TEST(exclude_set_rules) {
    ExcludeSet ex({"*.tmp", ".git", "/root/skip"}, "/root");
    CHECK(ex.excluded("/root/a/b.tmp"));
    CHECK(ex.excluded("/root/.git/config"));
    CHECK(ex.excluded("/root/skip"));
    CHECK(ex.excluded("/root/skip/deep/file"));
    CHECK(!ex.excluded("/root/skipper"));
    CHECK(!ex.excluded("/root/a/b.txt"));
    ExcludeSet ex2({"*.tmp"}, "/data/x.tmp");   // root name itself must not trigger the pattern
    CHECK(!ex2.excluded("/data/x.tmp/file.txt"));
}

TEST(event_type_names) {
    EventType t;
    CHECK(event_type_from_string("MODIFY", t));
    CHECK(t == EventType::Modify);
    CHECK(!event_type_from_string("NOPE", t));
    CHECK_EQ(std::string(to_string(EventType::Tamper)), "TAMPER");
}

TEST(thread_pool_runs_all_tasks) {
    ThreadPool pool(4);
    std::atomic<int> sum{0};
    std::vector<std::future<int>> f;
    for (int i = 1; i <= 100; ++i)
        f.push_back(pool.submit([i, &sum] { sum += i; return i * 2; }));
    int total = 0;
    for (auto& x : f) total += x.get();
    pool.wait_idle();
    CHECK_EQ(sum.load(), 5050);
    CHECK_EQ(total, 10100);
}

TEST(thread_pool_propagates_exceptions) {
    ThreadPool pool(2);
    auto f = pool.submit([]() -> int { throw std::runtime_error("boom"); });
    bool caught = false;
    try { f.get(); } catch (const std::runtime_error&) { caught = true; }
    CHECK(caught);
}

TEST(sha256_hardware_and_software_paths_agree) {
    // Computer-architecture check: the SHA-NI path must give bit-identical results.
    bool was = Sha256::hardware_enabled();
    std::string big(100003, 'k');
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<char>(i * 31 + 7);
    Sha256::set_hardware_enabled(false);
    std::string sw_abc = Sha256::hash_hex("abc"), sw_big = Sha256::hash_hex(big);
    CHECK_EQ(sw_abc, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    Sha256::set_hardware_enabled(true);          // no-op if the CPU lacks SHA-NI
    CHECK_EQ(Sha256::hash_hex("abc"), sw_abc);
    CHECK_EQ(Sha256::hash_hex(big), sw_big);
    Sha256 h; std::string chunk(1000, 'a');
    for (int i = 0; i < 1000; ++i) h.update(chunk);
    CHECK_EQ(to_hex(h.final()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    std::cerr << "    (SHA-NI supported: " << (Sha256::hardware_supported() ? "yes" : "no") << ")\n";
    Sha256::set_hardware_enabled(was);
}
