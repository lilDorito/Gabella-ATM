#include "atm/DispenseResult.h"
#include "atm/ServerMessages.h"
#include "atm/SessionState.h"

const char* dispenseResultToString(DispenseResult r)
{
    switch (r)
    {
    case DispenseResult::Ok: return "Ok";
    case DispenseResult::InvalidSignature: return "InvalidSignature";
    case DispenseResult::WrongAtm: return "WrongAtm";
    case DispenseResult::ReplayedSequence: return "ReplayedSequence";
    case DispenseResult::AmountNotDispensable: return "AmountNotDispensable";
    case DispenseResult::InsufficientCash: return "InsufficientCash";
    case DispenseResult::Locked: return "Locked";
    case DispenseResult::HardwareFault: return "HardwareFault";
    }
    return "";
}

const char* sessionStateToString(SessionState s)
{
    switch (s)
    {
    case SessionState::Idle: return "Idle";
    case SessionState::CardInserted: return "CardInserted";
    case SessionState::OperationSelect: return "OperationSelect";
    case SessionState::AwaitingPin: return "AwaitingPin";
    case SessionState::Authorizing: return "Authorizing";
    case SessionState::Approved: return "Approved";
    case SessionState::Dispensing: return "Dispensing";
    case SessionState::Completing: return "Completing";
    case SessionState::Terminated: return "Terminated";
    case SessionState::OutOfService: return "OutOfService";
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
