#include "access/AccessControl.h"

#include <utility>

AccessControl::AccessControl(const PermissionTable& permissions, DualControlManager& dualControl,
    SessionRegistry& sessions, StaffTokenStore& tokens, IStaffAuthenticator& auth,
    IAuditSink& sink)
    : _permissions(permissions),
    _dualControl(dualControl),
    _sessions(sessions),
    _tokens(tokens),
    _auth(auth),
    _sink(sink)
{
}

Decision AccessControl::deny(DenyReason reason, const AccessRequest& req, Role role,
    const std::string& actorId) const
{
    LogEvent e;
    e.type = EventType::ACCESS_DENIED;
    e.outcome = Outcome::Failure;
    e.sessionId = req.sessionId;
    e.actorRole = role;
    e.actorId = actorId;
    e.details = std::string("action=") + actionToString(req.action)
        + " reason=" + denyReasonToString(reason);
    (void)_sink.record(e);

    Decision d;
    d.verdict = Verdict::Denied;
    d.reason = reason;
    return d;
}

bool AccessControl::logLogin(bool success, const std::string& staffId, Role role) const
{
    LogEvent e;
    e.type = EventType::STAFF_LOGIN;
    e.outcome = success ? Outcome::Success : Outcome::Failure;
    e.actorRole = role;
    e.actorId = staffId;
    e.details = success ? "login" : "login failed";
    if (_sink.record(e)) return true;

    if (!success)
    {
        e.actorId.clear();
        e.details = "login failed (id withheld)";
        return _sink.record(e);
    }
    return false;
}

std::optional<StaffLoginResult> AccessControl::staffLogin(const std::string& staffId,
    const std::string& password, const std::string& atmId)
{
    if (staffId.empty() || password.empty() || atmId.empty()) return std::nullopt;

    const auto role = _auth.verify(staffId, password);
    if (!role || *role == Role::Client || *role == Role::System)
    {
        (void)logLogin(false, staffId, Role::System);
        return std::nullopt;
    }

    std::string token = _tokens.issue(staffId, *role, atmId);
    if (!logLogin(true, staffId, *role))
    {
        _tokens.revoke(token);
        return std::nullopt;
    }

    StaffLoginResult result;
    result.token = std::move(token);
    result.role = *role;
    return result;
}

void AccessControl::staffLogout(const std::string& token)
{
    _tokens.revoke(token);
}

Decision AccessControl::decide(const AccessRequest& req)
{
    Role role = Role::System;
    std::string actorId;

    if (!req.staffToken.empty())
    {
        const auto who = _tokens.resolve(req.staffToken);
        if (!who || who->atmId != req.atmId)
            return deny(DenyReason::NotLoggedIn, req, Role::System, "");
        role = who->role;
        actorId = who->staffId;
    }
    else if (!req.sessionId.empty())
    {
        if (!_sessions.isOpen(req.sessionId))
            return deny(DenyReason::NoSession, req, Role::System, "");
        role = Role::Client;
    }
    else
    {
        return deny(DenyReason::NotLoggedIn, req, Role::System, "");
    }

    if (!_permissions.isAllowed(role, req.action))
        return deny(DenyReason::NotPermitted, req, role, actorId);

    Decision d;
    if (_dualControl.requiresApproval(req.action))
    {
        const auto requestId = _dualControl.open(actorId, req.action, req.params);
        if (!requestId) return deny(DenyReason::NotPermitted, req, role, actorId);

        d.verdict = Verdict::PendingApproval;
        d.reason = DenyReason::None;
        d.requestId = *requestId;
        return d;
    }

    d.verdict = Verdict::Allowed;
    d.reason = DenyReason::None;
    return d;
}

ApprovalResult AccessControl::approve(const std::string& requestId, const std::string& token)
{
    const auto who = _tokens.resolve(token);
    if (!who || who->role != Role::Admin) return ApprovalResult::NotEligible;
    return _dualControl.approve(requestId, who->staffId);
}

bool AccessControl::isPermitted(Role role, Action action) const
{
    return _permissions.isAllowed(role, action);
}