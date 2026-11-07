#include "access/StaffAuthService.h"

#include <utility>

#include "access/AccessTypes.h"

StaffAuthService::StaffAuthService(StaffTokenStore& tokens, IStaffAuthenticator& auth, IAuditSink& sink) : _tokens(tokens), _auth(auth), _sink(sink) {}

bool StaffAuthService::logLogin(bool success, const std::string& staffId, Role role, const std::string& reason) const
{
    LogEvent e;
    e.type = EventType::STAFF_LOGIN;
    e.outcome = success ? Outcome::Success : Outcome::Failure;
    e.actorRole = role;
    e.actorId = staffId;
    e.details = success ? "" : "reason=" + reason;
    if (_sink.record(e)) return true;

    if (!success)
    {
        e.actorId.clear();
        e.details = "reason=" + reason + " actor_id=withheld";
        return _sink.record(e);
    }
    return false;
}

std::optional<StaffLoginResult> StaffAuthService::staffLogin(const std::string& staffId, const std::string& password, const std::string& atmId)
{
    if (staffId.empty() || password.empty() || atmId.empty()) return std::nullopt;

    const auto role = _auth.verify(staffId, password);
    const bool console = atmId == kAdminConsoleAtmId;
    if (!role || *role == Role::Client || *role == Role::System)
    {
        (void)logLogin(false, staffId, Role::System, "bad_credentials");
        return std::nullopt;
    }
    if ((*role == Role::Admin) != console)
    {
        (void)logLogin(false, staffId, *role, "wrong_terminal");
        return std::nullopt;
    }

    std::string token = _tokens.issue(staffId, *role, atmId);
    if (!logLogin(true, staffId, *role, ""))
    {
        _tokens.revoke(token);
        return std::nullopt;
    }

    StaffLoginResult result;
    result.token = std::move(token);
    result.role = *role;
    return result;
}

void StaffAuthService::staffLogout(const std::string& token) { _tokens.revoke(token); }
