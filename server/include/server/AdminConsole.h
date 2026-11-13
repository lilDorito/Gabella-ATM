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
#include "common/Clock.h"
#include "server/repo/AtmRepository.h"
#include "server/services/CommandService.h"
#include "server/services/DisputeService.h"

struct ConsoleApproval
{
    ApprovalResult result = ApprovalResult::NotEligible;
    std::optional<EnqueueResult> queued;
    std::optional<ResolveResult> resolved;
};

struct PendingView
{
    CriticalRequest request;
    std::string atmId;
    std::uint32_t approvals = 0;
};

class AdminConsole
{
private:
    AccessControl& _access;
    StaffAuthService& _staffAuth;
    ApprovalService& _approvals;
    StaffTokenStore& _tokens;
    DualControlManager& _dual;
    CommandService& _commands;
    DisputeService& _disputes;
    AtmRepository& _atms;
    IAuditSink& _log;
    const IClock& _clock;

    std::optional<StaffIdentity> adminOf(const std::string& token);

public:
    AdminConsole(AccessControl& access,
        StaffAuthService& staffAuth,
        ApprovalService& approvals,
        StaffTokenStore& tokens,
        DualControlManager& dual,
        CommandService& commands,
        DisputeService& disputes,
        AtmRepository& atms,
        IAuditSink& log,
        const IClock& clock)
        : _access(access),
          _staffAuth(staffAuth),
          _approvals(approvals),
          _tokens(tokens),
          _dual(dual),
          _commands(commands),
          _disputes(disputes),
          _atms(atms),
          _log(log),
          _clock(clock)
    {
    }

    [[nodiscard]] std::optional<StaffLoginResult> login(const std::string& staffId, const std::string& password);
    void logout(const std::string& token);

    [[nodiscard]] Decision createRequest(const std::string& token, Action action, const std::string& atmId, const std::string& extra = "");
    [[nodiscard]] ConsoleApproval approve(const std::string& token, const std::string& requestId);
    [[nodiscard]] Decision proposeResolution(const std::string& token, std::int64_t txId, bool commit, const std::string& reason);

    [[nodiscard]] std::vector<PendingView> pending(const std::string& token);
    [[nodiscard]] std::vector<AtmRecord> atms(const std::string& token);
    [[nodiscard]] std::vector<TxRecord> disputes(const std::string& token);

    static std::string formatAtm(const AtmRecord& atm);
    static std::string formatPending(const PendingView& view);
    static std::string formatDispute(const TxRecord& tx, std::int64_t now);

    int run(std::istream& in, std::ostream& out);
};
