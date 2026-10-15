#pragma once
#include <cstdint>
#include <optional>
#include <string>

enum class VerifyError
{
    None,
    MalformedEntry,
    SeqGap,
    ChainBroken,
    HashMismatch,
    TornTail,
    CheckpointBadMac,
    CheckpointMissingEntry,
    CheckpointHashMismatch
};

const char* verifyErrorToString(VerifyError e);

struct VerifyResult
{
    bool ok = true;
    std::optional<std::uint64_t> firstBadSeq;
    VerifyError reason = VerifyError::None;

    std::uint64_t entryCount = 0;
    std::uint64_t recoveredTornEntries = 0;
    std::uint64_t tailSeqNo = 0;
    std::string tailHash;
};
