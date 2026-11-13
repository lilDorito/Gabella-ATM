#include "server/BankServer.h"

#include <utility>

BankServer::BankServer(const BankHsm& hsm, IAuditSink& log, RequestGate& gate, AtmRepository& atms, CheckpointService& checkpoints, ServerParts parts)
    : _hsm(hsm),
      _log(log),
      _gate(gate),
      _atms(atms),
      _checkpoints(checkpoints),
      _parts(parts)
{
}

bool BankServer::admitted(ApiCall call, const RequestHeader& header, const std::string& body, bool allowOutOfService)
{
    return _gate.admit(call, header, body, allowOutOfService) == GateVerdict::Admitted;
}

void BankServer::noteFailure(const char* call) noexcept
{
    try
    {
        LogEvent e;
        e.type = EventType::AUTH_DECISION;
        e.outcome = Outcome::Failure;
        e.actorRole = Role::System;
        e.details = std::string("reason=internal_error call=") + call;
        (void)_log.record(e);
    }
    catch (...)
    {
    }
}

AuthResponse BankServer::authorize(const AuthRequest& request)
{
    return guarded<AuthResponse>("Authorize",
        [&]
        {
            AuthResponse refused;
            refused.sessionId = request.getSessionId();
            if (_gate.admitAuthorization(request) != GateVerdict::Admitted) return refused;

            AuthResponse response = _parts.authorization.authorize(request);
            auto signature = _hsm.sign(SignDomain::Response, response.signedPayload());
            if (!signature) return refused;
            response.signature = std::move(*signature);
            return response;
        });
}

bool BankServer::reportDispense(const RequestHeader& header, const DispenseReport& report)
{
    return guarded<bool>(
        "ReportDispense", [&] { return report.atmId == header.atmId && admitted(ApiCall::ReportDispense, header, report.payload(), true) && _parts.reconciliation.onDispenseReport(report); });
}

bool BankServer::syncStatus(const RequestHeader& header, const StatusReport& report)
{
    return guarded<bool>("SyncStatus", [&] { return report.atmId == header.atmId && admitted(ApiCall::SyncStatus, header, report.payload(), true) && _parts.reconciliation.onStatusReport(report); });
}

bool BankServer::endSession(const RequestHeader& header, const std::string& sessionId)
{
    return guarded<bool>("EndSession", [&] { return admitted(ApiCall::EndSession, header, ApiBody::endSession(sessionId), true) && _parts.authorization.endSession(header.atmId, sessionId); });
}

std::optional<StaffLoginResult> BankServer::staffLogin(const RequestHeader& header, const StaffLoginRequest& request)
{
    return guarded<std::optional<StaffLoginResult>>("StaffLogin",
        [&]() -> std::optional<StaffLoginResult>
        {
            const bool consistent = request.atmId == header.atmId && request.nonce == header.nonce && request.timestamp == header.timestamp;
            if (!consistent || !admitted(ApiCall::StaffLogin, header, request.payload(), false)) return std::nullopt;
            return _parts.staff.staffLogin(request);
        });
}

bool BankServer::staffLogout(const RequestHeader& header, const std::string& token)
{
    return guarded<bool>("StaffLogout",
        [&]
        {
            if (!admitted(ApiCall::StaffLogout, header, ApiBody::staffLogout(token), true)) return false;
            _parts.staff.staffLogout(token);
            return true;
        });
}

Decision BankServer::decide(const RequestHeader& header, const AccessRequest& request)
{
    return guarded<Decision>("Decide",
        [&]
        {
            if (request.atmId != header.atmId || !admitted(ApiCall::Decide, header, request.payload(), false)) return Decision{};
            return _parts.access.decide(request);
        });
}

bool BankServer::submitCheckpoint(const RequestHeader& header, const Checkpoint& checkpoint)
{
    return guarded<bool>("SubmitCheckpoint",
        [&]
        {
            if (!admitted(ApiCall::SubmitCheckpoint, header, checkpoint.payload(), true)) return false;
            const CheckpointVerdict verdict = _checkpoints.submit(header.atmId, checkpoint);
            return verdict == CheckpointVerdict::Accepted || verdict == CheckpointVerdict::AlreadyKnown;
        });
}

std::optional<SignedCheckpoint> BankServer::latestCheckpoint(const RequestHeader& header, const std::string& auditorToken)
{
    return guarded<std::optional<SignedCheckpoint>>("LatestCheckpoint",
        [&]() -> std::optional<SignedCheckpoint>
        {
            if (!admitted(ApiCall::LatestCheckpoint, header, ApiBody::latestCheckpoint(auditorToken), true)) return std::nullopt;
            return _checkpoints.latestFor(header.atmId, auditorToken, header.nonce);
        });
}

bool BankServer::reportTamper(const RequestHeader& header)
{
    return guarded<bool>("ReportTamper",
        [&]
        {
            bool authenticated = false;
            if (!header.mac.empty())
            {
                const GateVerdict verdict = _gate.admit(ApiCall::ReportTamper, header, ApiBody::empty(), true);
                authenticated = verdict == GateVerdict::Admitted;
                if (!authenticated && verdict != GateVerdict::BadMac) return false;
            }
            if (!_atms.find(header.atmId)) return false;

            LogEvent e;
            e.type = EventType::TAMPER_DETECTED;
            e.outcome = Outcome::Failure;
            e.actorRole = Role::System;
            e.actorId = header.atmId;
            e.details = std::string("source=atm_report authenticated=") + (authenticated ? "yes" : "no");
            (void)_log.record(e);
            return _atms.setStatus(header.atmId, AtmStatus::OutOfService);
        });
}

std::vector<SignedCommand> BankServer::pollCommands(const RequestHeader& header)
{
    return guarded<std::vector<SignedCommand>>("PollCommands",
        [&]() -> std::vector<SignedCommand>
        {
            if (!admitted(ApiCall::PollCommands, header, ApiBody::empty(), true)) return {};
            return _parts.commands.pollCommands(header.atmId);
        });
}

bool BankServer::reportCommandResult(const RequestHeader& header, std::uint64_t commandSeq, bool ok)
{
    return guarded<bool>("ReportCommandResult",
        [&] { return admitted(ApiCall::ReportCommandResult, header, ApiBody::commandResult(commandSeq, ok), true) && _parts.commands.reportCommandResult(header.atmId, commandSeq, ok); });
}
