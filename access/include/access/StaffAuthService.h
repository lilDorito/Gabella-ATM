#pragma once
#include <optional>
#include <string>

#include "access/IStaffAuthenticator.h"
#include "access/StaffTokenStore.h"
#include "audit/IAuditSink.h"
#include "common/Role.h"
#include "common/ServerMessages.h"

class StaffAuthService
{
private:
    StaffTokenStore& _tokens;
    IStaffAuthenticator& _auth;
    IAuditSink& _sink;

    bool logLogin(bool success, const std::string& staffId, Role role, const std::string& reason) const;

public:
    StaffAuthService(StaffTokenStore& tokens, IStaffAuthenticator& auth, IAuditSink& sink);

    StaffAuthService(const StaffAuthService&) = delete;
    StaffAuthService& operator=(const StaffAuthService&) = delete;

    [[nodiscard]] std::optional<StaffLoginResult> staffLogin(const std::string& staffId, const std::string& password, const std::string& atmId);
    void staffLogout(const std::string& token);
};
