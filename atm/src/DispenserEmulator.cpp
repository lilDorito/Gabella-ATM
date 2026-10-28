#include "atm/DispenserEmulator.h"

#include <algorithm>
#include <climits>
#include <vector>

#include "common/Invariant.h"

namespace
{

    using Denominations = std::vector<std::pair<int, int>>;

    bool solve(const Denominations& d, std::size_t i, long long remaining, std::vector<int>& take)
    {
        if (i == d.size()) return remaining == 0;

        const long long maxCount = std::min<long long>(d[i].second, remaining / d[i].first);
        for (long long n = maxCount; n >= 0; --n)
        {
            take[i] = static_cast<int>(n);
            if (solve(d, i + 1, remaining - n * d[i].first, take)) return true;
        }
        take[i] = 0;
        return false;
    }

    Denominations sortedDenominations(const std::map<int, int>& cassettes, bool unlimited)
    {
        Denominations d;
        for (const auto& [value, count] : cassettes)
        {
            if (value > 0) d.emplace_back(value, unlimited ? INT_MAX : count);
        }
        std::sort(d.begin(), d.end(),
            [](const auto& a, const auto& b) { return a.first > b.first; });
        return d;
    }

}

DispenserEmulator::DispenserEmulator(std::string atmId, const AtmHsm& hsm, std::map<int, int> cassettes)
    : _atmId(std::move(atmId)), _hsm(hsm), _cassettes(std::move(cassettes))
{
    ATM_INVARIANT(!_atmId.empty(), "dispenser: atmId must not be empty");
    for (const auto& [value, count] : _cassettes)
    {
        ATM_INVARIANT(value > 0 && count >= 0, "dispenser: invalid cassette definition");
    }
}

DispenseResult DispenserEmulator::dispense(const DispenseCommand& command)
{
    if (_locked) return DispenseResult::Locked;

    if (!_hsm.verifyServer(SignDomain::Dispense, command.signedPayload(), command.signature))
        return DispenseResult::InvalidSignature;

    if (command.atmId != _atmId) return DispenseResult::WrongAtm;

    if (command.sequence <= _lastSequence) return DispenseResult::ReplayedSequence;

    if (command.amountKop <= 0 || command.amountKop % 100 != 0)
        return DispenseResult::AmountNotDispensable;

    const long long hryvnia = command.amountKop / 100;

    std::vector<int> unlimitedTake(_cassettes.size(), 0);
    if (!solve(sortedDenominations(_cassettes, true), 0, hryvnia, unlimitedTake))
        return DispenseResult::AmountNotDispensable;

    const Denominations denominations = sortedDenominations(_cassettes, false);
    std::vector<int> take(denominations.size(), 0);
    if (!solve(denominations, 0, hryvnia, take))
        return DispenseResult::InsufficientCash;

    long long total = 0;
    for (std::size_t i = 0; i < denominations.size(); ++i)
        total += static_cast<long long>(take[i]) * denominations[i].first;
    ATM_INVARIANT(total == hryvnia, "dispenser: composed amount does not match command");

    _lastSequence = command.sequence;

    if (_fault) return DispenseResult::HardwareFault;

    _lastDispensed.clear();
    for (std::size_t i = 0; i < denominations.size(); ++i)
    {
        if (take[i] == 0) continue;
        _cassettes[denominations[i].first] -= take[i];
        _lastDispensed[denominations[i].first] = take[i];
    }
    return DispenseResult::Ok;
}

void DispenserEmulator::loadCash(const std::map<int, int>& notes)
{
    for (const auto& [value, count] : notes)
    {
        if (value > 0 && count > 0) _cassettes[value] += count;
    }
}

std::map<int, int> DispenserEmulator::unloadCash()
{
    std::map<int, int> out = _cassettes;
    for (auto& entry : _cassettes) entry.second = 0;
    return out;
}
