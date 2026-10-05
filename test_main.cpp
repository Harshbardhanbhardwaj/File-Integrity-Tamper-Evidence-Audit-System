#include <cstring>
#include "test_framework.hpp"

int main(int argc, char** argv) {
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int run = 0, failed = 0;
    for (auto& c : tf::registry()) {
        if (filter && !std::strstr(c.name, filter)) continue;
        int before = tf::fail_count();
        std::cerr << "[ RUN  ] " << c.name << "\n";
        try { c.fn(); }
        catch (const std::exception& e) { std::cerr << "    exception: " << e.what() << "\n"; ++tf::fail_count(); }
        ++run;
        if (tf::fail_count() != before) { ++failed; std::cerr << "[ FAIL ] " << c.name << "\n"; }
        else std::cerr << "[  OK  ] " << c.name << "\n";
    }
    std::cerr << "\n" << run << " test(s) run, " << failed << " failed\n";
    return failed ? 1 : 0;
}
