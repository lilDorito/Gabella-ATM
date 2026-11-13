#pragma once
#include <array>
#include <filesystem>
#include <string>

#include "DemoData.h"
#include "access/AccessControl.h"
#include "access/ApprovalPolicy.h"
#include "access/ApprovalService.h"
#include "access/DualControlManager.h"
#include "access/PermissionTable.h"
#include "access/SessionRegistry.h"
#include "access/StaffAuthService.h"
#include "access/StaffTokenStore.h"
#include "audit/AnchorStore.h"
#include "audit/AuditLogger.h"
#include "audit/HsmAuditSigners.h"
#include "audit/IntentRecovery.h"
#include "audit/LogStorage.h"
#include "audit/LogVerifier.h"
#include "common/Clock.h"
#include "crypto/BankHsm.h"
#include "crypto/CryptoCore.h"
#include "server/AdminConsole.h"
#include "server/BankServer.h"
#include "server/RequestGate.h"
#include "server/SystemConfig.h"
#include "server/db/Database.h"
#include "server/db/Statement.h"
#include "server/repo/AccountRepository.h"
#include "server/repo/AtmRepository.h"
#include "server/repo/CardRepository.h"
#include "server/repo/CassetteRepository.h"
#include "server/repo/CheckpointRepository.h"
#include "server/repo/CommandRepository.h"
#include "server/repo/DualControlRepository.h"
#include "server/repo/NonceRepository.h"
#include "server/repo/StaffRepository.h"
#include "server/repo/TxRepository.h"
#include "server/services/AccessDecider.h"
#include "server/services/AuthorizationService.h"
#include "server/services/CheckpointService.h"
#include "server/services/CommandService.h"
#include "server/services/DisputeService.h"
#include "server/services/PasswordVerifier.h"
#include "server/services/ReconciliationService.h"
#include "server/services/StaffAuthenticator.h"
#include "server/services/StaffService.h"

struct ServerKeys
{
    std::string serverKey;
    std::string pinKey;
    std::array<unsigned char, 32> signPublic{};
    std::array<unsigned char, 64> signSecret{};
    std::array<unsigned char, 32> boxPublic{};
    std::array<unsigned char, 32> boxSecret{};
};

inline RandomBytesFn systemRandom()
{
    return [](std::size_t n) { return CryptoCore::randomBytes(n); };
}

struct BankNode
{
    const IClock& clock;
    SystemConfig config;
    BankHsm hsm;
    Database db;

    AtmRepository atms{ db };
    NonceRepository nonces{ db };
    CheckpointRepository checkpoints{ db };
    AccountRepository accounts{ db };
    CardRepository cards{ db };
    TxRepository txs{ db };
    CassetteRepository cassettes{ db };
    StaffRepository staff{ db };
    DualControlRepository requests{ db };
    CommandRepository commandQueue{ db };

    FileLogStorage logStorage;
    FileAnchorStore logAnchors;
    ServerCheckpointSink logSink{ checkpoints, clock };
    BankHsmAuditSigner logSigner{ hsm };
    AuditLogger log{ kServerLogId, logStorage, logAnchors, logSigner, logSink, clock, config.checkpointInterval };

    PermissionTable permissions = PermissionTable::makeDefault();
    ApprovalPolicy policy = ApprovalPolicy::makeDefault();
    SessionRegistry sessions{ clock, config.clientSessionSeconds };
    StaffTokenStore tokens{ clock, systemRandom(), config.staffTokenIdleSeconds, config.staffTokenMaxSeconds };
    DualControlManager dual{ requests, policy, clock, log, systemRandom(), [this] { return staff.countActiveAdmins(); } };
    SqliteStaffAuthenticator authenticator{ staff, log, clock, config, makeArgon2idVerifier(), makeDummyArgon2idHash() };
    AccessControl access{ permissions, dual, sessions, tokens, log };
    StaffAuthService staffAuth{ tokens, authenticator, log };
    ApprovalService approvals{ tokens, dual };

    RequestGate gate{ hsm, atms, nonces, log, clock, config };
    CheckpointService checkpointService{ hsm, checkpoints, atms, tokens, log, clock, config };
    AuthorizationService authorization{ hsm, db, atms, cards, accounts, txs, sessions, log, clock, config };
    AccessDecider decider{ access, policy, atms, log };
    ReconciliationService reconciliation{ db, txs, accounts, cassettes, decider, log, clock, config };
    StaffService staffService{ hsm, staffAuth, log };
    CommandService commands{ hsm, db, atms, commandQueue, dual, requests, log, clock, config };
    DisputeService disputes{ dual, requests, txs, reconciliation };
    AdminConsole console{ access, staffAuth, approvals, tokens, dual, commands, disputes, atms, log, clock };
    BankServer server{ hsm, log, gate, atms, checkpointService, ServerParts{ authorization, reconciliation, staffService, decider, commands } };

    BankNode(const IClock& clockRef, const ServerKeys& keys, const std::filesystem::path& dataDir)
        : clock(clockRef),
          hsm(keys.serverKey, keys.pinKey, keys.signPublic, keys.signSecret, keys.boxPublic, keys.boxSecret),
          db((dataDir / "bank.db").string()),
          logStorage(dataDir / "logs" / "server.log"),
          logAnchors(dataDir / "logs" / "server.anchor")
    {
    }

    bool seeded()
    {
        Statement s(db, "SELECT count(*) FROM accounts");
        return s.step() && s.columnInt64(0) > 0;
    }

    void seedIfEmpty()
    {
        if (!seeded()) seedDatabase(db, hsm);
    }

    RecoveryReport recover()
    {
        const LogVerifier verifier(logStorage, logSigner);
        IntentRecovery recovery(verifier, log);
        return recovery.run({ &checkpointService, &authorization, &reconciliation, &commands, &authenticator });
    }

    void tick()
    {
        (void)reconciliation.tick();
        (void)commands.tick();
        (void)disputes.tick();
    }
};
