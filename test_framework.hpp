// Minimal unit-test framework (no external dependencies).
#pragma once
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>

namespace tf {

struct Case { const char* name; std::function<void()> fn; };
inline std::vector<Case>& registry() { static std::vector<Case> r; return r; }
struct Registrar { Registrar(const char* n, std::function<void()> f) { registry().push_back({n, std::move(f)}); } };

struct Failure { std::string msg; };
inline int& fail_count() { static int c = 0; return c; }

#define TEST(name) \
    static void test_##name(); \
    static tf::Registrar reg_##name(#name, test_##name); \
    static void test_##name()

#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "    CHECK failed: " #cond " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
    ++tf::fail_count(); } } while (0)

#define CHECK_EQ(a, b) do { auto&& _a = (a); auto&& _b = (b); if (!(_a == _b)) { \
    std::cerr << "    CHECK_EQ failed: " #a " == " #b " (" << __FILE__ << ":" << __LINE__ << ")\n" \
              << "      left : " << _a << "\n      right: " << _b << "\n"; \
    ++tf::fail_count(); } } while (0)

// Temporary directory removed on destruction.
class TempDir {
public:
    TempDir() {
        std::string t = (std::filesystem::temp_directory_path() / "fiatest.XXXXXX").string();
        std::vector<char> b(t.begin(), t.end()); b.push_back('\0');
        if (!mkdtemp(b.data())) { std::perror("mkdtemp"); std::exit(2); }
        path_ = std::filesystem::canonical(b.data()).string();
    }
    ~TempDir() { std::error_code ec; std::filesystem::remove_all(path_, ec); }
    const std::string& path() const { return path_; }
    std::string operator/(const std::string& rel) const { return path_ + "/" + rel; }
    void write(const std::string& rel, const std::string& content) const {
        std::filesystem::create_directories(std::filesystem::path(path_ + "/" + rel).parent_path());
        std::ofstream(path_ + "/" + rel, std::ios::binary | std::ios::trunc) << content;
    }
private:
    std::string path_;
};

} // namespace tf
