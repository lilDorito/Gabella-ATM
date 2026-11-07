#pragma once

enum class DispenseResult
{
    Ok,
    InvalidSignature,
    WrongAtm,
    Expired,
    ReplayedSequence,
    AmountNotDispensable,
    InsufficientCash,
    Locked,
    HardwareFault
};

const char* dispenseResultToString(DispenseResult r);
