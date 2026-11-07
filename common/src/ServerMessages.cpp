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
