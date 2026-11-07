#include "access/AccessControl.h"

AccessControl::AccessControl(const PermissionTable& permissions, DualControlManager& dualControl, SessionRegistry& sessions, StaffTokenStore& tokens, IAuditSink& sink)
    : _permissions(permissions),
      _dualControl(dualControl),
      _sessions(sessions),
      _tokens(tokens),
      _sink(sink)
{
}

Decision AccessControl::deny(DenyReason reason, const AccessRequest& req, Role role, const std::string& actorId) const
{
    LogEvent e;
    e.type = EventType::ACCESS_DENIED;
    e.outcome = Outcome::Failure;
    e.sessionId = req.sessionId;
    e.actorRole = role;
    e.actorId = actorId;
    e.details = std::string("action=") + actionToString(req.action) + " reason=" + denyReasonToString(reason);
    (void)_sink.record(e);

    Decision d;
    d.verdict = Verdict::Denied;
    d.reason = reason;
    return d;
}

Decision AccessControl::decide(const AccessRequest& req)
{
    Role role = Role::System;
    std::string actorId;

    if (!req.staffToken.empty())
    {
        const auto who = _tokens.resolve(req.staffToken);
        if (!who || who->atmId != req.atmId) return deny(DenyReason::NotLoggedIn, req, Role::System, "");
        role = who->role;
        actorId = who->staffId;
    }
    else if (!req.sessionId.empty())
    {
        if (!_sessions.isOpen(req.sessionId)) return deny(DenyReason::NoSession, req, Role::System, "");
        role = Role::Client;
    }
    else
    {
        return deny(DenyReason::NotLoggedIn, req, Role::System, "");
    }

    if (!_permissions.isAllowed(role, req.action)) return deny(DenyReason::NotPermitted, req, role, actorId);

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

bool AccessControl::isPermitted(Role role, Action action) const { return _permissions.isAllowed(role, action); }
