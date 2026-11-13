#pragma once
#include "access/AccessControl.h"
#include "access/ApprovalPolicy.h"
#include "access/IAccessDecider.h"
#include "audit/IAuditSink.h"
#include "server/repo/AtmRepository.h"

class AccessDecider final : public IAccessDecider
{
private:
    AccessControl& _access;
    const ApprovalPolicy& _policy;
    AtmRepository& _atms;
    IAuditSink& _log;

    Decision deny(DenyReason reason, const AccessRequest& request);

public:
    AccessDecider(AccessControl& access, const ApprovalPolicy& policy, AtmRepository& atms, IAuditSink& log) : _access(access), _policy(policy), _atms(atms), _log(log) {}

    [[nodiscard]] Decision decide(const AccessRequest& request) override;
};
