#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "access/IAccessDecider.h"
#include "audit/IAuditSink.h"
#include "common/Clock.h"
#include "crypto/BankHsm.h"
#include "server/RequestGate.h"
#include "server/SystemConfig.h"
#include "server/repo/AtmRepository.h"
#include "server/services/CheckpointService.h"
#include "server/services/ServerServices.h"
#include "server_api/IServerApi.h"

struct ServerParts
{
    IAuthorizationService& authorization;
    IReconciliationService& reconciliation;
    IStaffService& staff;
    IAccessDecider& access;
    ICommandService& commands;
};

class BankServer final : public IServerApi
{
private:
    const BankHsm& _hsm;
    IAuditSink& _log;
    RequestGate& _gate;
    AtmRepository& _atms;
    CheckpointService& _checkpoints;
    ServerParts _parts;

    bool admitted(ApiCall call, const RequestHeader& header, const std::string& body, bool allowOutOfService);
    void noteFailure(const char* call) noexcept;

    template <typename T, typename F>
    T guarded(const char* call, F&& work) noexcept
    {
        try
        {
            return work();
        }
        catch (...)
        {
            noteFailure(call);
            return T{};
        }
    }

public:
    BankServer(const BankHsm& hsm, IAuditSink& log, RequestGate& gate, AtmRepository& atms, CheckpointService& checkpoints, ServerParts parts);

    AuthResponse authorize(const AuthRequest& request) override;
    bool reportDispense(const RequestHeader& header, const DispenseReport& report) override;
    bool syncStatus(const RequestHeader& header, const StatusReport& report) override;
    bool endSession(const RequestHeader& header, const std::string& sessionId) override;
    std::optional<StaffLoginResult> staffLogin(const RequestHeader& header, const StaffLoginRequest& request) override;
    bool staffLogout(const RequestHeader& header, const std::string& token) override;
    Decision decide(const RequestHeader& header, const AccessRequest& request) override;
    bool submitCheckpoint(const RequestHeader& header, const Checkpoint& checkpoint) override;
    std::optional<SignedCheckpoint> latestCheckpoint(const RequestHeader& header, const std::string& auditorToken) override;
    bool reportTamper(const RequestHeader& header) override;
    std::vector<SignedCommand> pollCommands(const RequestHeader& header) override;
    bool reportCommandResult(const RequestHeader& header, std::uint64_t commandSeq, bool ok) override;
};
