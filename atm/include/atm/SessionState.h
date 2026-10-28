#pragma once

enum class SessionState
{
    Idle,
    CardInserted,
    OperationSelect,
    AwaitingPin,
    Authorizing,
    Approved,
    Dispensing,
    Completing,
    Terminated,
    OutOfService
};

const char* sessionStateToString(SessionState s);
