#pragma once
#include <string>

#include "common/Action.h"

enum class Verdict
{
    Allowed,
    Denied,
    PendingApproval
};

enum class DenyReason
{
    None,
    NoSession,
    NotLoggedIn,
    NotPermitted,
    AtmOutOfService,
    AuditUnavailable
};

struct AccessRequest
{
    std::string atmId;
    std::string sessionId;
    std::string staffToken;
    Action action = Action::CheckBalance;
    std::string params;
};

struct Decision
{
    Verdict verdict = Verdict::Denied;
    DenyReason reason = DenyReason::NotPermitted;
    std::string requestId;
};

const char* verdictToString(Verdict v);
const char* denyReasonToString(DenyReason r);