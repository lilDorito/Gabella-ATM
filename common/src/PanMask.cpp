#include "common/PanMask.h"

std::string maskPan(const std::string& pan)
{
    if (pan.size() <= 4) return std::string(pan.size(), '*');
    return std::string(pan.size() - 4, '*') + pan.substr(pan.size() - 4);
}

bool isMaskedPan(const std::string& s)
{
    if (s.size() < 5) return false;
    std::size_t visible = s.size() - 4;
    for (std::size_t i = 0; i < visible; ++i)
        if (s[i] != '*') return false;
    for (std::size_t i = visible; i < s.size(); ++i)
        if (s[i] < '0' || s[i] > '9') return false;
    return true;
}
