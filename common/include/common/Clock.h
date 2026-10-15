#pragma once
#include <cstdint>
#include <utility>

class IClock
{
public:
    virtual ~IClock() = default;
    virtual std::int64_t nowUnix() const = 0;
};

class SystemClock final : public IClock
{
public:
    std::int64_t nowUnix() const override;
};

class FakeClock final : public IClock
{
private:
    std::int64_t _now;

public:
    explicit FakeClock(std::int64_t start = 1700000000) : _now(start) {}

    std::int64_t nowUnix() const override { return _now; }
    void set(std::int64_t unix) { _now = unix; }
    void advance(std::int64_t seconds) { _now += seconds; }
};

std::pair<int, int> monthYear(std::int64_t unix);
