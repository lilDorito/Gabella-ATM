#include "atm/SessionState.h"

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
