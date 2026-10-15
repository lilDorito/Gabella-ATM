#include <array>
#include <exception>
#include <iostream>
#include <sodium.h>
#include <string>

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

namespace {

const std::string kMasterKey = "0123456789ABCDEF";
const std::string kEncKey = "FEDCBA9876543210";
const std::string kMacKey = "1111222233334444";
const std::string kAuditKey = "AAAABBBBCCCCDDDD";
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
    for (auto [type, key] : { std::pair{ KeyType::Encryption, kEncKey },
                              std::pair{ KeyType::Mac, kMacKey },
                              std::pair{ KeyType::Audit, kAuditKey } })
    {
        auto blob = CryptoCore::aesCbcEncrypt(kMasterKey, key);
        if (!blob || !atm.updateWorkingKey(type, *blob)) return false;
    }
    return atm.state() == AtmHsmState::Operational;
}

void report(const std::string& name, const AuditLogger& log, const LogVerifier& verifier)
{
    VerifyResult r = verifier.verifyChain();
    std::cout << name << ": state=" << loggerStateToString(log.state())
              << " entries=" << r.entryCount
              << " chain=" << (r.ok ? "ok" : verifyErrorToString(r.reason)) << "\n";
}

}

int main()
{
    try
    {
        if (!CryptoCore::init())
        {
            std::cerr << "libsodium initialization failed\n";
            return 1;
        }

        std::array<unsigned char, 32> signPub{};
        std::array<unsigned char, 64> signSecret{};
        std::array<unsigned char, 32> boxPub{};
        std::array<unsigned char, 32> boxSecret{};
        crypto_sign_seed_keypair(signPub.data(), signSecret.data(), demoSeed('S').data());
        crypto_box_seed_keypair(boxPub.data(), boxSecret.data(), demoSeed('B').data());

        SystemClock clock;

        BankHsm bankHsm(kMasterKey, kEncKey, kMacKey, kAuditKey, kPinKey,
            signPub, signSecret, boxPub, boxSecret);
        BankHsmAuditSigner serverSigner(bankHsm);
        FileLogStorage serverStorage("logs/server.log");
        FileAnchorStore serverAnchors("logs/server.anchor");
        InMemoryCheckpointSink serverCheckpoints;
        AuditLogger serverLog("SERVER", serverStorage, serverAnchors, serverSigner, serverCheckpoints, clock);
        serverLog.init();

        AtmHsm atmHsm(bankHsm.signPublicKey(), bankHsm.boxPublicKey());
        if (!bringUp(atmHsm))
        {
            std::cerr << "AtmHsm key ceremony failed\n";
            return 1;
        }
        AtmHsmAuditSigner atmSigner(atmHsm);
        FileLogStorage atmStorage("logs/atm-001.log");
        FileAnchorStore atmAnchors("logs/atm-001.anchor");
        InMemoryCheckpointSink atmCheckpoints;
        AuditLogger atmLog("ATM-001", atmStorage, atmAnchors, atmSigner, atmCheckpoints, clock);
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
        report("SERVER ", serverLog, LogVerifier(serverStorage, serverSigner));
        if (!atmCheckpoints.items().empty())
            std::cout << "last ATM checkpoint: seq=" << atmCheckpoints.items().back().seqNo << "\n";

        return ok ? 0 : 2;
    }
    catch (const std::exception& e)
    {
        std::cerr << "fatal: " << e.what() << "\n";
        return 3;
    }
}
