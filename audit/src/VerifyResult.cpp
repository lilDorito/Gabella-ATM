#include "audit/VerifyResult.h"

const char* verifyErrorToString(VerifyError e)
{
    switch (e) {
    case VerifyError::None: return "None";
    case VerifyError::MalformedEntry: return "MalformedEntry";
    case VerifyError::SeqGap: return "SeqGap";
    case VerifyError::ChainBroken: return "ChainBroken";
    case VerifyError::HashMismatch: return "HashMismatch";
    case VerifyError::TornTail: return "TornTail";
    case VerifyError::CheckpointBadMac: return "CheckpointBadMac";
    case VerifyError::CheckpointMissingEntry: return "CheckpointMissingEntry";
    case VerifyError::CheckpointHashMismatch: return "CheckpointHashMismatch";
    }
    return "";
}
