#pragma once
#include <iostream>
#include <string>

namespace gabella_test {

inline int& passedCount() { static int n = 0; return n; }
inline int& failedCount() { static int n = 0; return n; }

inline void check(bool cond, const std::string& name)
{
    std::cout << (cond ? "  [PASS] " : "  [FAIL] ") << name << "\n";
    if (cond) ++passedCount(); else ++failedCount();
}

inline void section(const std::string& title)
{
    std::cout << "\n=== " << title << " ===\n";
}

inline int summary()
{
    std::cout << "\n===================\n";
    std::cout << "PASSED: " << passedCount() << "\n";
    std::cout << "FAILED: " << failedCount() << "\n";
    return failedCount() == 0 ? 0 : 1;
}

}
