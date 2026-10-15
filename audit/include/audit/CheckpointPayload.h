#pragma once
#include <string>

#include "audit/IAuditSigner.h"
#include "common/Checkpoint.h"

std::string checkpointPayload(const Checkpoint& cp);

[[nodiscard]] bool verifyCheckpointMac(const Checkpoint& cp, const IAuditSigner& signer);
