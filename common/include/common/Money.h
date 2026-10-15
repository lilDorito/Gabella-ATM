#pragma once
#include <cstdint>
#include <optional>

class Money
{
private:
    std::int64_t _kop;

    explicit Money(std::int64_t kop) : _kop(kop) {}

public:
    static std::optional<Money> fromKop(std::int64_t v);
    static Money zero() { return Money(0); }

    std::int64_t kop() const { return _kop; }

    [[nodiscard]] std::optional<Money> checkedAdd(Money other) const;
    bool isMultipleOf(std::int64_t kop) const;

    friend bool operator==(Money a, Money b) { return a._kop == b._kop; }
    friend bool operator!=(Money a, Money b) { return a._kop != b._kop; }
    friend bool operator<(Money a, Money b) { return a._kop < b._kop; }
    friend bool operator<=(Money a, Money b) { return a._kop <= b._kop; }
    friend bool operator>(Money a, Money b) { return a._kop > b._kop; }
    friend bool operator>=(Money a, Money b) { return a._kop >= b._kop; }
};
