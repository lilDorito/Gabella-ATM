#pragma once
#include <cstdint>
#include <vector>

#include "audit/IAuditSigner.h"
#include "audit/LogEntry.h"
#include "audit/LogStorage.h"
#include "audit/VerifyResult.h"
#include "common/Checkpoint.h"

class LogVerifier final
{
private:
    const LogStorage& _storage;
    const IAuditSigner& _signer;

public:
    LogVerifier(const LogStorage& storage, const IAuditSigner& signer)
        : _storage(storage), _signer(signer) {}

    VerifyResult verifyChain() const;
    VerifyResult verifyAgainstCheckpoint(const Checkpoint& cp) const;
    std::vector<LogEntry> readEntries(std::uint64_t from, std::uint64_t to) const;
};
