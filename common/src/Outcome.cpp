#include "common/Outcome.h"

const char* outcomeToString(Outcome o)
{
    switch (o) {
    case Outcome::Success: return "Success";
    case Outcome::Failure: return "Failure";
    case Outcome::Info: return "Info";
    }
    return "";
}

std::optional<Outcome> outcomeFromString(std::string_view s)
{
    for (Outcome o : { Outcome::Success, Outcome::Failure, Outcome::Info })
    {
        if (s == outcomeToString(o)) return o;
    }
    return std::nullopt;
}
