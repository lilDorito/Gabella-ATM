#pragma once
#include <string>

#include "HsmFixture.h"
#include "access/StaffTokenStore.h"
#include "audit/AnchorStore.h"
#include "audit/AuditLogger.h"
#include "audit/HsmAuditSigners.h"
#include "audit/LogStorage.h"
#include "audit/LogVerifier.h"
#include "common/Clock.h"
#include "common/ServerMessages.h"
#include "crypto/CryptoCore.h"
#include "server/BankServer.h"
#include "server/RequestGate.h"
#include "server/SystemConfig.h"
#include "server/db/Database.h"
#include "server/repo/AtmRepository.h"
#include "server/repo/CheckpointRepository.h"
#include "server/repo/NonceRepository.h"
#include "server/services/CheckpointService.h"
#include "server/services/ServerServices.h"

inline const std::string kRigAtm = "ATM-001";

inline RandomBytesFn rigRng()
{
    return [](std::size_t n) { return CryptoCore::randomBytes(n); };
}

struct ServerRig
{
    HsmFixture fx;
    FakeClock clock;
    SystemConfig config;
    Database db{ ":memory:" };
    AtmRepository atms{ db };
    NonceRepository nonces{ db };
    CheckpointRepository checkpoints{ db };
    InMemoryLogStorage logStorage;
    InMemoryAnchorStore logAnchors;
    ServerCheckpointSink logSink{ checkpoints, clock };
    BankHsmAuditSigner logSigner{ *fx.bank };
    AuditLogger log{ kServerLogId, logStorage, logAnchors, logSigner, logSink, clock, 50 };
    StaffTokenStore tokens{ clock, rigRng() };
    RequestGate gate{ *fx.bank, atms, nonces, log, clock, config };
    CheckpointService checkpointService{ *fx.bank, checkpoints, atms, tokens, log, clock, config };
    UnavailableServices unavailable;
    BankServer server{ *fx.bank, log, gate, atms, checkpointService, ServerParts{ unavailable, unavailable, unavailable, unavailable, unavailable } };
    int nonceCounter = 0;

    ServerRig()
    {
        (void)log.init();
        atms.insert(kRigAtm);
    }

    std::string freshNonce() { return "nonce-" + std::to_string(++nonceCounter); }

    RequestHeader header(ApiCall call, const std::string& body, const std::string& atmId = kRigAtm)
    {
        RequestHeader h;
        h.atmId = atmId;
        h.nonce = freshNonce();
        h.timestamp = clock.nowUnix();
        h.mac = *fx.atm->macMessage(h.macPayload(call, body));
        return h;
    }

    std::size_t count(EventType type) const
    {
        std::size_t n = 0;
        for (const auto& entry : LogVerifier(logStorage, logSigner).readEntries(1, 1000000))
            if (entry.getEvent().type == type) ++n;
        return n;
    }
};
