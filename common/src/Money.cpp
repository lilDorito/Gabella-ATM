#include "common/Money.h"

#include <limits>

std::optional<Money> Money::fromKop(std::int64_t v)
{
    if (v < 0) return std::nullopt;
    return Money(v);
}

std::optional<Money> Money::checkedAdd(Money other) const
{
    if (other._kop > std::numeric_limits<std::int64_t>::max() - _kop) return std::nullopt;
    return Money(_kop + other._kop);
}

bool Money::isMultipleOf(std::int64_t kop) const
{
    if (kop <= 0) return false;
    return _kop % kop == 0;
}
