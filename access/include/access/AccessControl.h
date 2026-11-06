#pragma once
#include <optional>
#include <string>

#include "access/AccessTypes.h"
#include "access/DualControlManager.h"
#include "access/IStaffAuthenticator.h"
#include "access/PermissionTable.h"
#include "access/SessionRegistry.h"
#include "access/StaffTokenStore.h"
#include "atm/ServerMessages.h"
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
    IStaffAuthenticator& _auth;
    IAuditSink& _sink;

    Decision deny(DenyReason reason, const AccessRequest& req, Role role,
        const std::string& actorId) const;
    bool logLogin(bool success, const std::string& staffId, Role role) const;

public:
    AccessControl(const PermissionTable& permissions, DualControlManager& dualControl,
        SessionRegistry& sessions, StaffTokenStore& tokens, IStaffAuthenticator& auth,
        IAuditSink& sink);

    AccessControl(const AccessControl&) = delete;
    AccessControl& operator=(const AccessControl&) = delete;

    [[nodiscard]] std::optional<StaffLoginResult> staffLogin(const std::string& staffId,
        const std::string& password, const std::string& atmId);

    void staffLogout(const std::string& token);

    [[nodiscard]] Decision decide(const AccessRequest& req);

    [[nodiscard]] ApprovalResult approve(const std::string& requestId, const std::string& token);

    [[nodiscard]] bool isPermitted(Role role, Action action) const;
};