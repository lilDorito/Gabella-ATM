#include <array>
#include <exception>
#include <iostream>
#include <sodium.h>
#include <string>

#include "access/AccessClient.h"
#include "atm/PendingReportQueue.h"
#include "atm/ServerLink.h"
#include "audit/AnchorStore.h"
#include "audit/AuditLogger.h"
#include "audit/HsmAuditSigners.h"
#include "audit/InMemoryCheckpointSink.h"
#include "audit/LogStorage.h"
#include "audit/LogVerifier.h"
#include "common/Clock.h"
#include "common/PanMask.h"
#include "crypto/AtmHsm.h"
#include "crypto/BankHsm.h"
#include "crypto/CryptoCore.h"
#include "crypto/KeyWrap.h"
#include "server/BankServer.h"
#include "server/RequestGate.h"
#include "server/SystemConfig.h"
#include "server/db/Database.h"
#include "server/db/Statement.h"
#include "server/repo/AccountRepository.h"
#include "server/repo/AtmRepository.h"
#include "server/repo/CassetteRepository.h"
#include "server/repo/CheckpointRepository.h"
#include "server/repo/NonceRepository.h"
#include "server/repo/TxRepository.h"
#include "server/services/CheckpointService.h"
#include "server/services/ReconciliationService.h"
#include "server/services/ServerServices.h"

namespace
{
const std::string kMasterKey = "0123456789ABCDEF";
const std::string kEncKey = "FEDCBA9876543210";
const std::string kMacKey = "1111222233334444";
const std::string kAuditKey = "AAAABBBBCCCCDDDD";
const std::string kServerKey = "SERVERSERVERSRV1";
const std::string kPinKey = "PINPINPINPINPIN1";

std::array<unsigned char, 32> demoSeed(char fill)
{
    std::array<unsigned char, 32> seed{};
    seed.fill(static_cast<unsigned char>(fill));
    return seed;
}

bool bringUp(AtmHsm& atm)
{
    if (!atm.installMasterKey(kMasterKey)) return false;
    for (const auto& [type, key] : { std::pair{ KeyType::Encryption, kEncKey }, std::pair{ KeyType::Mac, kMacKey }, std::pair{ KeyType::Audit, kAuditKey } })
    {
        auto blob = wrapWorkingKey(kMasterKey, type, key);
        if (!blob || !atm.updateWorkingKey(type, *blob)) return false;
    }
    return atm.state() == AtmHsmState::Operational;
}

void report(const std::string& name, const AuditLogger& log, const LogVerifier& verifier)
{
    VerifyResult r = verifier.verifyChain();
    std::cout << name << ": state=" << loggerStateToString(log.state()) << " entries=" << r.entryCount << " chain=" << (r.ok ? "ok" : verifyErrorToString(r.reason)) << "\n";
}
}

int main()
{
    try
    {
        if (!CryptoCore::init())
        {
            std::cerr << "fatal: libsodium initialization failed\n";
            return 1;
        }

        std::array<unsigned char, 32> signPub{};
        std::array<unsigned char, 64> signSecret{};
        std::array<unsigned char, 32> boxPub{};
        std::array<unsigned char, 32> boxSecret{};
        crypto_sign_seed_keypair(signPub.data(), signSecret.data(), demoSeed('S').data());
        crypto_box_seed_keypair(boxPub.data(), boxSecret.data(), demoSeed('B').data());

        SystemClock clock;

        BankHsm bankHsm(kServerKey, kPinKey, signPub, signSecret, boxPub, boxSecret);
        if (!bankHsm.provisionAtm("ATM-001", AtmKeySet{ kMasterKey, kEncKey, kMacKey, kAuditKey }))
        {
            std::cerr << "fatal: bank HSM could not provision ATM-001\n";
            return 1;
        }
        BankHsmAuditSigner serverSigner(bankHsm);
        FileLogStorage serverStorage("logs/server.log");
        FileAnchorStore serverAnchors("logs/server.anchor");
        InMemoryCheckpointSink serverCheckpoints;
        AuditLogger serverLog("SERVER", serverStorage, serverAnchors, serverSigner, serverCheckpoints, clock);
        serverLog.init();

        AtmHsm atmHsm(bankHsm.signPublicKey(), bankHsm.boxPublicKey());
        if (!bringUp(atmHsm))
        {
            std::cerr << "fatal: AtmHsm key ceremony failed\n";
            return 1;
        }
        SystemConfig config;
        Database db(":memory:");
        AtmRepository atms(db);
        NonceRepository nonces(db);
        CheckpointRepository checkpoints(db);
        AccountRepository accounts(db);
        TxRepository txs(db);
        CassetteRepository cassettes(db);
        StaffTokenStore tokens(clock, [](std::size_t n) { return CryptoCore::randomBytes(n); });
        RequestGate gate(bankHsm, atms, nonces, serverLog, clock, config);
        CheckpointService checkpointService(bankHsm, checkpoints, atms, tokens, serverLog, clock, config);
        UnavailableServices unavailable;
        ReconciliationService reconciliation(db, txs, accounts, cassettes, unavailable, serverLog, clock, config);
        BankServer bankServer(bankHsm, serverLog, gate, atms, checkpointService, ServerParts{ unavailable, reconciliation, unavailable, unavailable, unavailable });
        atms.insert("ATM-001");

        PendingReportQueue queue("logs/atm-001.pending");
        (void)queue.load();
        ServerLink link(bankServer, atmHsm, queue, clock, "ATM-001");
        AccessClient access(link, "ATM-001");

        AtmHsmAuditSigner atmSigner(atmHsm);
        FileLogStorage atmStorage("logs/atm-001.log");
        FileAnchorStore atmAnchors("logs/atm-001.anchor");
        AuditLogger atmLog("ATM-001", atmStorage, atmAnchors, atmSigner, link, clock);
        atmLog.init();

        LogEvent inserted;
        inserted.type = EventType::CARD_INSERTED;
        inserted.maskedPan = maskPan("5432101234567890");
        LogEvent requested = inserted;
        requested.type = EventType::AUTH_REQUESTED;
        requested.actorRole = Role::Client;
        requested.amount = Money::fromKop(50000);
        LogEvent decided = requested;
        decided.type = EventType::AUTH_DECISION;
        decided.outcome = Outcome::Success;

        bool ok = atmLog.record(inserted) && atmLog.record(requested);
        ok = serverLog.record(decided) && ok;
        ok = atmLog.sealCheckpoint() && ok;

        report("ATM-001", atmLog, LogVerifier(atmStorage, atmSigner));
        report("SERVER", serverLog, LogVerifier(serverStorage, serverSigner));
        if (const auto latest = checkpoints.latest("ATM-001")) std::cout << "ATM-001: last_checkpoint_seq=" << latest->seqNo << "\n";

        Statement account(db, "INSERT INTO accounts (account_id, owner_name, balance_kop) VALUES ('ACC-1', 'Demo', 1000000)");
        account.run();
        cassettes.replace("ATM-001", { { 100, 50 }, { 200, 50 }, { 500, 50 }, { 1000, 50 } });
        txs.insertHeld("ATM-001", "demo-session", "ACC-1", 50000, 1, clock.nowUnix());

        DispenseReport dispensed;
        dispensed.atmId = "ATM-001";
        dispensed.sessionId = "demo-session";
        dispensed.sequence = 1;
        dispensed.result = DispenseResult::Ok;
        dispensed.cassetteCounts = { { 100, 50 }, { 200, 50 }, { 500, 49 }, { 1000, 50 } };
        dispensed.timestamp = clock.nowUnix();
        link.reportDispense(dispensed);

        const auto tx = txs.findBySeq("ATM-001", 1);
        std::cout << "ATM-001: demo_withdrawal=" << (tx ? txStatusToString(tx->status) : "missing") << " balance_kop=" << accounts.balance("ACC-1").value_or(0) << " pending_reports=" << queue.size()
                  << "\n";
        ok = ok && tx && tx->status == TxStatus::Committed && queue.empty();

        return ok ? 0 : 2;
    }
    catch (const std::exception& e)
    {
        std::cerr << "fatal: " << e.what() << "\n";
        return 3;
    }
}
