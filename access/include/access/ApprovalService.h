#pragma once
#include <string>

#include "access/AccessTypes.h"
#include "access/DualControlManager.h"
#include "access/StaffTokenStore.h"

class ApprovalService
{
private:
    StaffTokenStore& _tokens;
    DualControlManager& _dualControl;

public:
    ApprovalService(StaffTokenStore& tokens, DualControlManager& dualControl);

    ApprovalService(const ApprovalService&) = delete;
    ApprovalService& operator=(const ApprovalService&) = delete;

    [[nodiscard]] ApprovalResult approve(const std::string& requestId, const std::string& token);
};
