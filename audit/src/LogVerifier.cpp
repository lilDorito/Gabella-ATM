#include "audit/LogVerifier.h"

#include <string>

#include "audit/CheckpointPayload.h"
#include "audit/LogFormat.h"

namespace {

void fail(VerifyResult& r, VerifyError reason, std::uint64_t seq)
{
    if (!r.ok) return;
    r.ok = false;
    r.reason = reason;
    r.firstBadSeq = seq;
}

bool isTornMarker(const LogEntry& e)
{
    const std::string marker = kTornEntryMarker;
    return e.getEvent().type == EventType::LOG_INTEGRITY_FAILURE
        && e.getEvent().details.compare(0, marker.size(), marker) == 0;
}

}

VerifyResult LogVerifier::verifyChain() const
{
    VerifyResult r;
    r.tailHash = genesisHash();

    std::uint64_t expectedSeq = 1;
    std::string prevHash = genesisHash();
    bool pendingTorn = false;

    for (const std::string& line : _storage.readAll())
    {
        auto entry = parseEntry(line);
        if (!entry)
        {
            if (pendingTorn) fail(r, VerifyError::MalformedEntry, expectedSeq);
            pendingTorn = true;
            continue;
        }

        r.tailSeqNo = entry->getSeqNo();
        r.tailHash = entry->getHash();
        ++r.entryCount;

        if (!r.ok) continue;

        if (pendingTorn)
        {
            if (!isTornMarker(*entry))
            {
                fail(r, VerifyError::MalformedEntry, expectedSeq);
                continue;
            }
            pendingTorn = false;
            ++r.recoveredTornEntries;
        }

        if (entry->getSeqNo() != expectedSeq)
        {
            fail(r, VerifyError::SeqGap, expectedSeq);
            continue;
        }
        if (entry->getPrevHash() != prevHash)
        {
            fail(r, VerifyError::ChainBroken, entry->getSeqNo());
            continue;
        }

        std::string canonical = serializeEntry(entry->getSeqNo(),
            entry->getTimestamp(), entry->getEvent());
        if (computeEntryHash(prevHash, canonical) != entry->getHash())
        {
            fail(r, VerifyError::HashMismatch, entry->getSeqNo());
            continue;
        }

        prevHash = entry->getHash();
        ++expectedSeq;
    }

    if (pendingTorn) fail(r, VerifyError::TornTail, expectedSeq);
    return r;
}

VerifyResult LogVerifier::verifyAgainstCheckpoint(const Checkpoint& cp) const
{
    VerifyResult r;

    if (!verifyCheckpointMac(cp, _signer))
    {
        fail(r, VerifyError::CheckpointBadMac, cp.seqNo);
        return r;
    }

    for (const std::string& line : _storage.readAll())
    {
        auto entry = parseEntry(line);
        if (!entry || entry->getSeqNo() != cp.seqNo) continue;

        r.entryCount = 1;
        r.tailSeqNo = entry->getSeqNo();
        r.tailHash = entry->getHash();
        if (entry->getHash() != cp.hash)
            fail(r, VerifyError::CheckpointHashMismatch, cp.seqNo);
        return r;
    }

    fail(r, VerifyError::CheckpointMissingEntry, cp.seqNo);
    return r;
}

std::vector<LogEntry> LogVerifier::readEntries(std::uint64_t from, std::uint64_t to) const
{
    std::vector<LogEntry> out;
    for (const std::string& line : _storage.readAll())
    {
        auto entry = parseEntry(line);
        if (!entry) continue;
        if (entry->getSeqNo() >= from && entry->getSeqNo() <= to)
            out.push_back(std::move(*entry));
    }
    return out;
}
