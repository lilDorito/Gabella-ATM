#pragma once
#include "access/AccessControl.h"
#include "access/ApprovalPolicy.h"
#include "access/IAccessDecider.h"
#include "audit/IAuditSink.h"
#include "server/repo/AtmRepository.h"

// The server's answer to "may this token do this action on this ATM". Identity, role and dual control
// are AccessControl's job; this class adds what only the server knows: the ATM exists and is in service,
// and a critical request is bound to the ATM that asked for it.
class AccessDecider final : public IAccessDecider
{
private:
    AccessControl& _access;
    const ApprovalPolicy& _policy;
    AtmRepository& _atms;
    IAuditSink& _log;

    Decision deny(DenyReason reason, const AccessRequest& request);

public:
    AccessDecider(AccessControl& access, const ApprovalPolicy& policy, AtmRepository& atms, IAuditSink& log)
        : _access(access), _policy(policy), _atms(atms), _log(log)
    {
    }

    [[nodiscard]] Decision decide(const AccessRequest& request) override;
};
