#pragma once
#include <optional>
#include <string>

#include "access/AccessControl.h"
#include "audit/IAuditSink.h"
#include "common/ServerMessages.h"
#include "crypto/BankHsm.h"
#include "server/services/ServerServices.h"

// Staff login and logout as the BankServer sees them: open the sealed password, let AccessControl check
// it (SqliteStaffAuthenticator does the hash and the lockout) and issue the token, wipe the password.
class StaffService final : public IStaffService
{
private:
    static constexpr std::size_t kMaxPasswordBytes = 128;

    const BankHsm& _hsm;
    AccessControl& _access;
    IAuditSink& _log;

    void refuse(const StaffLoginRequest& request, const std::string& reason);

public:
    StaffService(const BankHsm& hsm, AccessControl& access, IAuditSink& log) : _hsm(hsm), _access(access), _log(log) {}

    [[nodiscard]] std::optional<StaffLoginResult> staffLogin(const StaffLoginRequest& request) override;
    void staffLogout(const std::string& token) override;
};
