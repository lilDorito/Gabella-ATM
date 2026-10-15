#pragma once
#include <optional>
#include <string_view>

enum class Role
{
    Client,
    ServiceEngineer,
    CashCollector,
    Auditor,
    Admin,
    System
};

const char* roleToString(Role r);
std::optional<Role> roleFromString(std::string_view s);
