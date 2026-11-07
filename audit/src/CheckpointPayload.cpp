#include "audit/CheckpointPayload.h"

#include "common/Canonical.h"

std::string checkpointPayload(const Checkpoint& cp) { return canonicalEncode("CKPT:", { cp.logId, std::to_string(cp.seqNo), cp.hash, std::to_string(cp.timestamp) }); }

bool verifyCheckpointMac(const Checkpoint& cp, const IAuditSigner& signer)
{
    if (cp.mac.empty()) return false;
    return signer.verify(checkpointPayload(cp), cp.mac);
}
