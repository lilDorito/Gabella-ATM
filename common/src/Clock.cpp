#include "common/Clock.h"

#include <chrono>

std::int64_t SystemClock::nowUnix() const
{
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::pair<int, int> monthYear(std::int64_t unix)
{
    std::int64_t days = unix / 86400;
    if (unix % 86400 < 0) --days;

    std::int64_t z = days + 719468;
    std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    std::int64_t doe = z - era * 146097;
    std::int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    std::int64_t y = yoe + era * 400;
    std::int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    std::int64_t mp = (5 * doy + 2) / 153;
    std::int64_t m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) ++y;

    return { static_cast<int>(m), static_cast<int>(y) };
}
