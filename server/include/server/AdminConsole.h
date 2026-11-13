#pragma once
#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

#include "access/AccessControl.h"
#include "access/ApprovalService.h"
#include "access/DualControlManager.h"
#include "access/StaffAuthService.h"
#include "access/StaffTokenStore.h"
#include "audit/IAuditSink.h"
#include "server/repo/AtmRepository.h"
#include "server/services/CommandService.h"

struct ConsoleApproval
{
    ApprovalResult result = ApprovalResult::NotEligible;
    std::optional<EnqueueResult> queued;   // set only when this approval completed the request
};

struct PendingView
{
    CriticalRequest request;
    std::string atmId;
    std::uint32_t approvals = 0;
};

// The administrator's console on the server itself. Every call needs the token of a logged-in Admin;
// the token is bound to kAdminConsoleAtmId, so a token from an ATM does not work here.
class AdminConsole
{
private:
    AccessControl& _access;
    StaffAuthService& _staffAuth;
    ApprovalService& _approvals;
    StaffTokenStore& _tokens;
    DualControlManager& _dual;
    CommandService& _commands;
    AtmRepository& _atms;
    IAuditSink& _log;

    std::optional<StaffIdentity> adminOf(const std::string& token);

public:
    AdminConsole(AccessControl& access,
        StaffAuthService& staffAuth,
        ApprovalService& approvals,
        StaffTokenStore& tokens,
        DualControlManager& dual,
        CommandService& commands,
        AtmRepository& atms,
        IAuditSink& log)
        : _access(access),
          _staffAuth(staffAuth),
          _approvals(approvals),
          _tokens(tokens),
          _dual(dual),
          _commands(commands),
          _atms(atms),
          _log(log)
    {
    }

    [[nodiscard]] std::optional<StaffLoginResult> login(const std::string& staffId, const std::string& password);
    void logout(const std::string& token);

    // PendingApproval + requestId when the request was opened; the initiator's own approval is counted.
    [[nodiscard]] Decision createRequest(const std::string& token, Action action, const std::string& atmId, const std::string& extra = "");
    [[nodiscard]] ConsoleApproval approve(const std::string& token, const std::string& requestId);

    [[nodiscard]] std::vector<PendingView> pending(const std::string& token);
    [[nodiscard]] std::vector<AtmRecord> atms(const std::string& token);

    static std::string formatAtm(const AtmRecord& atm);
    static std::string formatPending(const PendingView& view);

    // Line-oriented session: help, login, atms, pending, request, approve, logout, quit.
    int run(std::istream& in, std::ostream& out);
};
