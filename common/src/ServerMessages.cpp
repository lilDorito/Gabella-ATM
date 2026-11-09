#include "common/ServerMessages.h"

#include "common/Canonical.h"

std::string DispenseCommand::signedPayload() const { return canonicalEncode("", { atmId, sessionId, std::to_string(amountKop), std::to_string(sequence), std::to_string(expiresAt) }); }

std::string AuthResponse::signedPayload() const
{
    return canonicalEncode("", { authStatusToString(status), sessionId, balance ? std::to_string(balance->kop()) : std::string("-"), command ? command->signedPayload() : std::string("-") });
}

std::string StaffLoginRequest::binding() const { return canonicalEncode("PWDCTX:", { atmId, staffId, nonce, std::to_string(timestamp) }); }

std::string SignedCommand::signedPayload() const { return canonicalEncode("", { atmId, std::to_string(commandSeq), std::string(actionToString(action)), params, std::to_string(expiresAt) }); }

const char* dispenseResultToString(DispenseResult r)
{
    switch (r)
    {
    case DispenseResult::Ok: return "Ok";
    case DispenseResult::InvalidSignature: return "InvalidSignature";
    case DispenseResult::WrongAtm: return "WrongAtm";
    case DispenseResult::Expired: return "Expired";
    case DispenseResult::ReplayedSequence: return "ReplayedSequence";
    case DispenseResult::AmountNotDispensable: return "AmountNotDispensable";
    case DispenseResult::InsufficientCash: return "InsufficientCash";
    case DispenseResult::Locked: return "Locked";
    case DispenseResult::HardwareFault: return "HardwareFault";
    }
    return "";
}

const char* authStatusToString(AuthStatus s)
{
    switch (s)
    {
    case AuthStatus::Approved: return "Approved";
    case AuthStatus::WrongPin: return "WrongPin";
    case AuthStatus::CardBlocked: return "CardBlocked";
    case AuthStatus::InsufficientFunds: return "InsufficientFunds";
    case AuthStatus::LimitExceeded: return "LimitExceeded";
    case AuthStatus::Declined: return "Declined";
    case AuthStatus::Error: return "Error";
    }
    return "";
}

namespace
{
std::string encodeCounts(const std::map<int, int>& counts)
{
    std::string out;
    for (const auto& [denomination, count] : counts)
    {
        if (!out.empty()) out += ",";
        out += std::to_string(denomination) + "x" + std::to_string(count);
    }
    return out;
}

const char* statusReasonToString(StatusReason reason)
{
    switch (reason)
    {
    case StatusReason::Reconnect: return "Reconnect";
    case StatusReason::CashLoaded: return "CashLoaded";
    case StatusReason::CashCollected: return "CashCollected";
    }
    return "";
}
}

std::string DispenseReport::payload() const
{
    return canonicalEncode("RPT:", { atmId, sessionId, std::to_string(sequence), dispenseResultToString(result), encodeCounts(cassetteCounts), std::to_string(timestamp) });
}

std::string StatusReport::payload() const
{
    return canonicalEncode("STS:", { atmId, statusReasonToString(reason), staffToken, std::to_string(lastExecutedSequence), encodeCounts(cassetteCounts), std::to_string(timestamp) });
}

std::string StaffLoginRequest::payload() const { return canonicalEncode("LGN:", { atmId, staffId, nonce, std::to_string(timestamp), sealedPassword }); }

const char* apiCallToString(ApiCall call)
{
    switch (call)
    {
    case ApiCall::ReportDispense: return "ReportDispense";
    case ApiCall::SyncStatus: return "SyncStatus";
    case ApiCall::EndSession: return "EndSession";
    case ApiCall::StaffLogin: return "StaffLogin";
    case ApiCall::StaffLogout: return "StaffLogout";
    case ApiCall::Decide: return "Decide";
    case ApiCall::SubmitCheckpoint: return "SubmitCheckpoint";
    case ApiCall::LatestCheckpoint: return "LatestCheckpoint";
    case ApiCall::ReportTamper: return "ReportTamper";
    case ApiCall::PollCommands: return "PollCommands";
    case ApiCall::ReportCommandResult: return "ReportCommandResult";
    }
    return "";
}

std::string RequestHeader::macPayload(ApiCall call, const std::string& body) const { return canonicalEncode("API:", { apiCallToString(call), atmId, nonce, std::to_string(timestamp), body }); }

std::string SignedCheckpoint::signedPayload() const { return canonicalEncode("", { checkpoint.payload(), requestNonce }); }

std::string ApiBody::endSession(const std::string& sessionId) { return canonicalEncode("SES:", { sessionId }); }
std::string ApiBody::staffLogout(const std::string& token) { return canonicalEncode("OUT:", { token }); }
std::string ApiBody::latestCheckpoint(const std::string& auditorToken) { return canonicalEncode("AUD:", { auditorToken }); }
std::string ApiBody::commandResult(std::uint64_t commandSeq, bool ok) { return canonicalEncode("RES:", { std::to_string(commandSeq), ok ? "1" : "0" }); }
std::string ApiBody::empty() { return canonicalEncode("NIL:", {}); }
