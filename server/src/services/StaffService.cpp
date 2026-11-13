#include "server/services/StaffService.h"

#include "crypto/CryptoCore.h"
#include "server/services/LogHelpers.h"

void StaffService::refuse(const StaffLoginRequest& request, const std::string& reason)
{
    LogEvent e;
    e.type = EventType::STAFF_LOGIN;
    e.outcome = Outcome::Failure;
    e.actorRole = Role::System;
    e.actorId = request.staffId;
    e.details = "reason=" + reason + " atm=" + request.atmId;
    (void)recordBestEffort(_log, e);
}

std::optional<StaffLoginResult> StaffService::staffLogin(const StaffLoginRequest& request)
{
    if (request.staffId.empty() || request.atmId.empty() || request.atmId == kAdminConsoleAtmId)
    {
        refuse(request, "bad_request");
        return std::nullopt;
    }

    std::string password;
    CryptoCore::StringWiper wiper{ password };
    if (!_hsm.openPassword(request.sealedPassword, request.binding(), password) || password.empty() || password.size() > kMaxPasswordBytes)
    {
        refuse(request, "unseal_failed");
        return std::nullopt;
    }
    return _staffAuth.staffLogin(request.staffId, password, request.atmId);
}

void StaffService::staffLogout(const std::string& token) { _staffAuth.staffLogout(token); }
