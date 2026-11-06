#pragma once
#include <cstdint>
#include <set>

#include "common/Action.h"

struct ApprovalPolicy
{
    std::set<Action> critical;
    std::int64_t ttlSeconds = 1800;

    [[nodiscard]] static ApprovalPolicy makeDefault();

    [[nodiscard]] bool isCritical(Action a) const { return critical.count(a) > 0; }

    [[nodiscard]] std::uint32_t requiredApprovals(std::uint32_t activeAdmins) const;
};