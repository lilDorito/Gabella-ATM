#include "audit/DataPolicy.h"

#include "common/PanMask.h"

namespace {

constexpr std::size_t kMaxDigitRun = 12;

bool hasLongDigitRun(const std::string& s)
{
    std::size_t run = 0;
    for (char c : s)
    {
        run = (c >= '0' && c <= '9') ? run + 1 : 0;
        if (run > kMaxDigitRun) return true;
    }
    return false;
}

}

bool isLoggable(const LogEvent& e)
{
    if (!e.maskedPan.empty() && !isMaskedPan(e.maskedPan)) return false;
    if (hasLongDigitRun(e.details)) return false;
    if (hasLongDigitRun(e.actorId)) return false;
    return true;
}
