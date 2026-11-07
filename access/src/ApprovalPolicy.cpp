#include "access/ApprovalPolicy.h"

#include <algorithm>

ApprovalPolicy ApprovalPolicy::makeDefault()
{
    ApprovalPolicy p;
    p.critical = { Action::UpdateWorkingKey, Action::InstallMasterKey, Action::RestoreFromOutOfService, Action::ResolveTransaction };
    p.ttlSeconds = 1800;
    return p;
}

std::uint32_t ApprovalPolicy::requiredApprovals(std::uint32_t activeAdmins) const
{
    const std::uint64_t n = activeAdmins;
    const std::uint64_t twoThirdsCeil = (2 * n + 2) / 3;
    return static_cast<std::uint32_t>(std::max<std::uint64_t>(2, twoThirdsCeil));
}
