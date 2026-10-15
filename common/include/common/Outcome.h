#pragma once
#include <optional>
#include <string_view>

enum class Outcome
{
    Success,
    Failure,
    Info
};

const char* outcomeToString(Outcome o);
std::optional<Outcome> outcomeFromString(std::string_view s);
