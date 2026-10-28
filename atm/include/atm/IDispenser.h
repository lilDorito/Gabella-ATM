#pragma once
#include <cstdint>
#include <map>

#include "atm/DispenseResult.h"
#include "atm/ServerMessages.h"

class IDispenser
{
public:
    virtual ~IDispenser() = default;

    [[nodiscard]] virtual DispenseResult dispense(const DispenseCommand& command) = 0;
    virtual void lock() = 0;
    virtual void unlock() = 0;
    virtual std::map<int, int> cassetteCounts() const = 0;
    virtual void loadCash(const std::map<int, int>& notes) = 0;
    virtual std::map<int, int> unloadCash() = 0;
    virtual std::uint64_t lastSequence() const = 0;
};
