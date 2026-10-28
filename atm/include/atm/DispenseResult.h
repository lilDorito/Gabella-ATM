#pragma once

enum class DispenseResult
{
    Ok,
    InvalidSignature,
    WrongAtm,
    ReplayedSequence,
    AmountNotDispensable,
    InsufficientCash,
    Locked,
    HardwareFault
};

const char* dispenseResultToString(DispenseResult r);
