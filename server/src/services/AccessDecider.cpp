#include "server/services/AccessDecider.h"

#include <exception>

#include "server/services/CommandParams.h"
#include "server/services/LogHelpers.h"

Decision AccessDecider::deny(DenyReason reason, const AccessRequest& request)
{
    LogEvent e;
    e.type = EventType::ACCESS_DENIED;
    e.outcome = Outcome::Failure;
    e.sessionId = request.sessionId;
    e.actorRole = Role::System;
    e.actorId = request.atmId;
    e.details = std::string("action=") + actionToString(request.action) + " reason=" + denyReasonToString(reason);
    (void)recordBestEffort(_log, e);

    Decision d;
    d.verdict = Verdict::Denied;
    d.reason = reason;
    return d;
}

Decision AccessDecider::decide(const AccessRequest& request)
{
    try
    {
        const auto atm = _atms.find(request.atmId);
        if (!atm) return deny(DenyReason::NotPermitted, request);
        if (atm->status != AtmStatus::Active) return deny(DenyReason::AtmOutOfService, request);

        AccessRequest bound = request;
        if (_policy.isCritical(request.action))
        {
            // The ATM that asks is the ATM the approved command will be addressed to; whatever the
            // ATM put into params only becomes the extra part and cannot name another machine.
            const auto params = makeCommandParams(request.atmId, request.params);
            if (!params) return deny(DenyReason::NotPermitted, request);
            bound.params = *params;
        }
        return _access.decide(bound);
    }
    catch (const std::exception&)
    {
        // Fail closed: a storage fault is a "no", never an "allowed".
        return deny(DenyReason::NotPermitted, request);
    }
}
