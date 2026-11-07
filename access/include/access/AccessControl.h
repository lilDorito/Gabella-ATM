#pragma once
#include <string>

#include "access/AccessTypes.h"
#include "access/DualControlManager.h"
#include "access/PermissionTable.h"
#include "access/SessionRegistry.h"
#include "access/StaffTokenStore.h"
#include "audit/IAuditSink.h"
#include "common/AccessTypes.h"
#include "common/Role.h"

class AccessControl
{
private:
    const PermissionTable& _permissions;
    DualControlManager& _dualControl;
    SessionRegistry& _sessions;
    StaffTokenStore& _tokens;
    IAuditSink& _sink;

    Decision deny(DenyReason reason, const AccessRequest& req, Role role, const std::string& actorId) const;

public:
    AccessControl(const PermissionTable& permissions, DualControlManager& dualControl, SessionRegistry& sessions, StaffTokenStore& tokens, IAuditSink& sink);

    AccessControl(const AccessControl&) = delete;
    AccessControl& operator=(const AccessControl&) = delete;

    [[nodiscard]] Decision decide(const AccessRequest& req);
    [[nodiscard]] bool isPermitted(Role role, Action action) const;
};
