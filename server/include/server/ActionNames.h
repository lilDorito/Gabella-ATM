#pragma once
#include <optional>
#include <string>

#include "common/Action.h"

// Action has no parser of its own; the names are the ones actionToString() writes.
inline std::optional<Action> actionFromString(const std::string& text)
{
    for (int i = 0; i < 64; ++i)
    {
        const Action a = static_cast<Action>(i);
        const std::string name = actionToString(a);
        if (!name.empty() && name == text) return a;
    }
    return std::nullopt;
}
