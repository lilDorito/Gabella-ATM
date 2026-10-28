#include "atm/KeypadEmulator.h"

#include <algorithm>

#include "crypto/CryptoCore.h"

namespace
{

    bool allDigits(const std::string& s)
    {
        return !s.empty() && std::all_of(s.begin(), s.end(),
            [](unsigned char c) { return c >= '0' && c <= '9'; });
    }

}

bool KeypadEmulator::readHiddenPin(std::string& out)
{
    if (!_enabled || !_input.nextInto(out))
    {
        CryptoCore::cleanse(out);
        return false;
    }

    if (out.size() < 4 || out.size() > 12 || !allDigits(out))
    {
        CryptoCore::cleanse(out);
        return false;
    }
    return true;
}

bool KeypadEmulator::readHiddenSecret(std::string& out)
{
    if (!_enabled || !_input.nextInto(out) || out.empty())
    {
        CryptoCore::cleanse(out);
        return false;
    }
    return true;
}

std::optional<Action> KeypadEmulator::readAction()
{
    std::string s;
    if (!_enabled || !_input.nextInto(s)) return std::nullopt;

    if (s == "1" || s == "balance") return Action::CheckBalance;
    if (s == "2" || s == "withdraw") return Action::Withdraw;
    return std::nullopt;
}

std::optional<Money> KeypadEmulator::readAmount()
{
    std::string s;
    if (!_enabled || !_input.nextInto(s)) return std::nullopt;
    if (s.size() > 12 || !allDigits(s)) return std::nullopt;

    return Money::fromKop(std::stoll(s) * 100);
}

std::optional<std::string> KeypadEmulator::readText()
{
    std::string s;
    if (!_enabled || !_input.nextInto(s)) return std::nullopt;
    return s;
}
