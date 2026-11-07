#include "access/ApprovalService.h"

ApprovalService::ApprovalService(StaffTokenStore& tokens, DualControlManager& dualControl) : _tokens(tokens), _dualControl(dualControl) {}

ApprovalResult ApprovalService::approve(const std::string& requestId, const std::string& token)
{
    const auto who = _tokens.resolve(token);
    if (!who || who->role != Role::Admin || who->atmId != kAdminConsoleAtmId) return ApprovalResult::NotEligible;
    return _dualControl.approve(requestId, who->staffId);
}
