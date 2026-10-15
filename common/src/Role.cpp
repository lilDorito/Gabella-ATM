#include "common/Role.h"

const char* roleToString(Role r)
{
    switch (r) {
    case Role::Client: return "Client";
    case Role::ServiceEngineer: return "ServiceEngineer";
    case Role::CashCollector: return "CashCollector";
    case Role::Auditor: return "Auditor";
    case Role::Admin: return "Admin";
    case Role::System: return "System";
    }
    return "";
}

std::optional<Role> roleFromString(std::string_view s)
{
    for (Role r : { Role::Client, Role::ServiceEngineer, Role::CashCollector,
                    Role::Auditor, Role::Admin, Role::System })
    {
        if (s == roleToString(r)) return r;
    }
    return std::nullopt;
}
