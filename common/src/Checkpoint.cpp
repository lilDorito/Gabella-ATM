#include "common/Checkpoint.h"

#include "common/Canonical.h"

std::string Checkpoint::payload() const { return canonicalEncode("CKP:", { logId, std::to_string(seqNo), hash, std::to_string(timestamp), mac }); }
