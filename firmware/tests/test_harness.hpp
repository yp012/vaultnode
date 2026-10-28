// Minimal header-only test harness: TEST(name) { CHECK(...); CHECK_EQ(a, b); }
#pragma once

#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace vn_test {

struct Case {
    const char* name;
    std::function<void()> fn;
};

inline std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

inline int& failures() {
    static int count = 0;
    return count;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> fn) { registry().push_back({name, std::move(fn)}); }
};

inline void fail(const char* file, int line, const std::string& msg) {
    ++failures();
    std::fprintf(stderr, "  FAIL %s:%d: %s\n", file, line, msg.c_str());
}

inline int run_all() {
    int failed_cases = 0;
    for (const auto& c : registry()) {
        const int before = failures();
        c.fn();
        const bool ok = failures() == before;
        failed_cases += ok ? 0 : 1;
        std::printf("[%s] %s\n", ok ? " OK " : "FAIL", c.name);
    }
    std::printf("%zu tests, %d failed\n", registry().size(), failed_cases);
    return failed_cases == 0 ? 0 : 1;
}

}  // namespace vn_test

#define VN_CAT2(a, b) a##b
#define VN_CAT(a, b) VN_CAT2(a, b)
#define TEST(name)                                                              \
    static void name();                                                         \
    static const vn_test::Registrar VN_CAT(vn_reg_, name){#name, &name};        \
    static void name()

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (!(cond)) vn_test::fail(__FILE__, __LINE__, "CHECK(" #cond ")");     \
    } while (0)

#define CHECK_EQ(a, b)                                                          \
    do {                                                                        \
        const auto& vn_a = (a);                                                 \
        const auto& vn_b = (b);                                                 \
        if (!(vn_a == vn_b)) {                                                  \
            std::ostringstream vn_os;                                           \
            vn_os << "CHECK_EQ(" #a ", " #b ")\n    left:  " << vn_a            \
                  << "\n    right: " << vn_b;                                   \
            vn_test::fail(__FILE__, __LINE__, vn_os.str());                     \
        }                                                                       \
    } while (0)
