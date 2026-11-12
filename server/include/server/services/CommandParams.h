#pragma once
#include <optional>
#include <string>

// params of a dual control request that targets one ATM: "atm=<atmId>" or "atm=<atmId>|<extra>".
// The target ATM is part of the signed-off request, so approving a request for ATM-001 can never
// produce a command for ATM-002.
struct CommandTarget
{
    std::string atmId;
    std::string extra;
};

inline std::optional<std::string> makeCommandParams(const std::string& atmId, const std::string& extra = "")
{
    if (atmId.empty() || atmId.find('|') != std::string::npos) return std::nullopt;
    return "atm=" + atmId + (extra.empty() ? std::string() : "|" + extra);
}

inline std::optional<CommandTarget> parseCommandParams(const std::string& params)
{
    const std::string prefix = "atm=";
    if (params.compare(0, prefix.size(), prefix) != 0) return std::nullopt;

    const std::size_t bar = params.find('|');
    CommandTarget t;
    t.atmId = params.substr(prefix.size(), bar == std::string::npos ? std::string::npos : bar - prefix.size());
    if (bar != std::string::npos) t.extra = params.substr(bar + 1);
    if (t.atmId.empty()) return std::nullopt;
    return t;
}
