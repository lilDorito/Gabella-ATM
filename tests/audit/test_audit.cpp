#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "Check.h"
#include "HsmFixture.h"

#include "audit/AnchorStore.h"
#include "audit/AuditLogger.h"
#include "audit/CheckpointPayload.h"
#include "audit/DataPolicy.h"
#include "audit/FakeAuditSink.h"
#include "audit/HsmAuditSigners.h"
#include "audit/InMemoryCheckpointSink.h"
#include "audit/LogFormat.h"
#include "audit/LogStorage.h"
#include "audit/LogVerifier.h"
#include "common/Clock.h"
#include "common/PanMask.h"

using gabella_test::check;
using gabella_test::section;

namespace {

const std::string kPan = "5432101234567890";

LogEvent sampleEvent(int i)
{
    LogEvent e;
    e.type = EventType::AUTH_REQUESTED;
    e.outcome = Outcome::Info;
    e.sessionId = "S-" + std::to_string(i);
    e.actorRole = Role::Client;
    e.maskedPan = maskPan(kPan);
    e.amount = Money::fromKop(50000);
    e.details = "req=" + std::to_string(i);
    return e;
}

struct Rig
{
    InMemoryLogStorage storage;
    InMemoryAnchorStore anchors;
    InMemoryCheckpointSink sink;
    FakeClock clock;
    AtmHsmAuditSigner signer;
    AuditLogger logger;

    explicit Rig(const AtmHsm& hsm, std::uint32_t interval = AuditLogger::kDefaultCheckpointInterval)
        : signer(hsm),
        logger("ATM-001", storage, anchors, signer, sink, clock, interval)
    {}

    bool fill(int n, int offset = 0)
    {
        bool ok = true;
        for (int i = 0; i < n; ++i)
        {
            clock.advance(1);
            ok = logger.record(sampleEvent(offset + i)) && ok;
        }
        return ok;
    }
};

std::string rewriteEntry(const std::string& line, std::int64_t newAmountKop, bool recomputeHash)
{
    auto entry = parseEntry(line);
    if (!entry) return line;

    LogEvent ev = entry->getEvent();
    ev.amount = Money::fromKop(newAmountKop);

    std::string hash = entry->getHash();
    if (recomputeHash)
        hash = computeEntryHash(entry->getPrevHash(),
            serializeEntry(entry->getSeqNo(), entry->getTimestamp(), ev));

    return formatEntryLine(LogEntry(entry->getSeqNo(), entry->getTimestamp(), ev,
        entry->getPrevHash(), hash));
}

std::filesystem::path makeTempDir()
{
    auto suffix = CryptoCore::randomBytes(6);
    std::string name = "gabella_audit_test_";
    for (unsigned char c : *suffix) name += "0123456789abcdef"[c & 0x0F];
    auto dir = std::filesystem::temp_directory_path() / name;
    std::filesystem::create_directories(dir);
    return dir;
}

void testFormat()
{
    section("Entry format (serializeEntry / parseEntry)");

    check(genesisHash() == std::string(64, '0'), "genesis hash is 64 zeros");

    LogEvent e = sampleEvent(1);
    e.details = std::string("pipe ") + kLogFieldSeparator + " backslash \\ newline \n cr \r end \\s";
    e.actorId = "E-07";
    e.actorRole = Role::ServiceEngineer;

    std::string canonical = serializeEntry(42, 1700000042, e);
    std::string hash = computeEntryHash(genesisHash(), canonical);
    check(isHashHex(hash), "computeEntryHash yields 64 lowercase hex chars");
    check(hash == computeEntryHash(genesisHash(), canonical), "hash is deterministic");
    check(hash != computeEntryHash(std::string(63, '0') + "1", canonical), "hash depends on prevHash");

    LogEntry entry(42, 1700000042, e, genesisHash(), hash);
    std::string line = formatEntryLine(entry);
    check(line.find('\n') == std::string::npos, "formatted line has no raw newline");

    auto back = parseEntry(line);
    check(back.has_value(), "U26: parseEntry accepts formatted line");
    if (back)
    {
        const LogEvent& b = back->getEvent();
        check(back->getSeqNo() == 42 && back->getTimestamp() == 1700000042, "U26: seq and timestamp preserved");
        check(b.details == e.details, "U26: details with separator, backslash, newline preserved");
        check(b.type == e.type && b.outcome == e.outcome && b.actorRole == e.actorRole,
            "U26: enums preserved");
        check(b.sessionId == e.sessionId && b.actorId == e.actorId && b.maskedPan == e.maskedPan,
            "U26: string fields preserved");
        check(b.amount.has_value() && b.amount->kop() == 50000, "U26: amount preserved");
        check(back->getPrevHash() == genesisHash() && back->getHash() == hash, "U26: hashes preserved");
    }

    LogEvent noAmount;
    noAmount.type = EventType::LOG_STARTED;
    auto na = parseEntry(formatEntryLine(LogEntry(1, 0, noAmount, genesisHash(),
        computeEntryHash(genesisHash(), serializeEntry(1, 0, noAmount)))));
    check(na.has_value() && !na->getEvent().amount.has_value(), "empty amount roundtrips as nullopt");

    check(!parseEntry("0" + line).has_value(), "non-canonical number rejected");
    check(!parseEntry(line + kLogFieldSeparator + "x").has_value(), "extra field rejected");
    check(!parseEntry("").has_value(), "empty line rejected");
    check(!parseEntry("garbage").has_value(), "garbage rejected");

    std::string badType = line;
    auto pos = badType.find("AUTH_REQUESTED");
    badType.replace(pos, 14, "AUTH_REQUESTEX");
    check(!parseEntry(badType).has_value(), "unknown event type rejected");

    std::string badEscape = line;
    auto bs = badEscape.find("\\\\");
    badEscape.replace(bs, 2, "\\x");
    check(!parseEntry(badEscape).has_value(), "invalid escape rejected");
}

void testMaskAndPolicy(const AtmHsm& hsm)
{
    section("PAN masking and data policy");

    check(maskPan(kPan) == "************7890", "U28: maskPan keeps only last 4 digits");
    check(maskPan("12") == "**", "maskPan of very short input reveals nothing");
    check(isMaskedPan("************7890"), "isMaskedPan accepts masked PAN");
    check(!isMaskedPan(kPan), "isMaskedPan rejects full PAN");

    LogEvent ok = sampleEvent(1);
    ok.details = "ts=1700000000 amount=50000 cassettes=100:50,200:40";
    check(isLoggable(ok), "ordinary event is loggable");

    LogEvent fullPan = sampleEvent(1);
    fullPan.maskedPan = kPan;
    check(!isLoggable(fullPan), "unmasked PAN in maskedPan is refused");

    LogEvent panInDetails = sampleEvent(1);
    panInDetails.details = "card " + kPan;
    check(!isLoggable(panInDetails), "PAN-like digit run in details is refused");

    Rig rig(hsm);
    rig.logger.init();
    std::uint64_t before = rig.logger.lastSeqNo();
    check(!rig.logger.record(fullPan), "logger refuses event violating policy");
    check(rig.logger.lastSeqNo() == before, "refused event does not consume a sequence number");
    check(rig.logger.state() == LoggerState::Ready, "policy refusal does not break the logger");
}

void testChain(HsmFixture& fx)
{
    section("Hash chain and checkpoints");

    Rig rig(*fx.atm);
    check(rig.logger.init() == LoggerState::Ready, "init on empty storage -> Ready");
    check(rig.logger.lastSeqNo() == 1, "LOG_STARTED written as entry 1");
    check(rig.fill(99), "99 records succeed");
    check(rig.logger.lastSeqNo() == 100, "sequence reached 100");

    LogVerifier verifier(rig.storage, rig.signer);
    VerifyResult r = verifier.verifyChain();
    check(r.ok && r.entryCount == 100, "U21: verifyChain ok on 100 entries");
    check(r.tailHash == rig.logger.lastHash(), "verifier tail matches logger state");

    check(rig.sink.items().size() == 2, "checkpoint every 50 entries (50 and 100)");
    Checkpoint cp = rig.sink.items().back();
    check(cp.seqNo == 100 && cp.hash == rig.logger.lastHash() && cp.logId == "ATM-001",
        "checkpoint carries log id, last seq and hash");
    auto anchor = rig.anchors.load();
    check(anchor && anchor->seqNo == 100 && anchor->mac == cp.mac, "local anchor updated with checkpoint");
    check(verifier.verifyAgainstCheckpoint(cp).ok, "intact log matches its checkpoint");

    auto range = verifier.readEntries(10, 12);
    check(range.size() == 3 && range.front().getSeqNo() == 10 && range.back().getSeqNo() == 12,
        "readEntries returns requested range");

    const std::vector<std::string> pristine = rig.storage.lines();

    rig.storage.lines()[41] = rewriteEntry(pristine[41], 99900, false);
    r = verifier.verifyChain();
    check(!r.ok && r.reason == VerifyError::HashMismatch && r.firstBadSeq == 42u,
        "U22: altered amount in entry 42 -> HashMismatch at 42");

    rig.storage.lines() = pristine;
    rig.storage.lines()[41] = rewriteEntry(pristine[41], 99900, true);
    r = verifier.verifyChain();
    check(!r.ok && r.reason == VerifyError::ChainBroken && r.firstBadSeq == 43u,
        "altered entry 42 with recomputed hash -> chain breaks at 43");

    rig.storage.lines() = pristine;
    rig.storage.lines().erase(rig.storage.lines().begin() + 49);
    r = verifier.verifyChain();
    check(!r.ok && r.reason == VerifyError::SeqGap && r.firstBadSeq == 50u,
        "U23: deleted entry 50 -> SeqGap at 50");

    rig.storage.lines() = pristine;
    std::swap(rig.storage.lines()[20], rig.storage.lines()[21]);
    r = verifier.verifyChain();
    check(!r.ok && r.reason == VerifyError::SeqGap && r.firstBadSeq == 21u,
        "swapped entries 21/22 -> SeqGap at 21");

    rig.storage.lines() = pristine;
    rig.storage.lines().resize(90);
    r = verifier.verifyChain();
    VerifyResult rc = verifier.verifyAgainstCheckpoint(cp);
    check(r.ok, "U24: truncated log still has a valid chain");
    check(!rc.ok && rc.reason == VerifyError::CheckpointMissingEntry,
        "U24: truncation detected by checkpoint (CheckpointMissingEntry)");

    Rig forger(*fx.atm);
    forger.logger.init();
    for (int i = 0; i < 99; ++i)
    {
        LogEvent e = sampleEvent(i);
        e.amount = Money::fromKop(10000);
        forger.clock.advance(1);
        (void)forger.logger.record(e);
    }
    rig.storage.lines() = forger.storage.lines();
    r = verifier.verifyChain();
    rc = verifier.verifyAgainstCheckpoint(cp);
    check(r.ok, "U25: fully rewritten log has a valid chain");
    check(!rc.ok && rc.reason == VerifyError::CheckpointHashMismatch,
        "U25: full rewrite detected by checkpoint (CheckpointHashMismatch)");

    rig.storage.lines() = pristine;
    Checkpoint forged = cp;
    forged.seqNo = 90;
    forged.hash = parseEntry(pristine[89])->getHash();
    rc = verifier.verifyAgainstCheckpoint(forged);
    check(!rc.ok && rc.reason == VerifyError::CheckpointBadMac, "checkpoint with altered fields -> bad MAC");

    HsmFixture other(std::string("ZZZZYYYYXXXXWWWW"));
    AtmHsmAuditSigner otherSigner(*other.atm);
    Checkpoint foreign = cp;
    foreign.mac = *otherSigner.sign(checkpointPayload(cp));
    check(!verifier.verifyAgainstCheckpoint(foreign).ok, "checkpoint MACed with another auditKey rejected");
}

void testFailures(HsmFixture& fx)
{
    section("Write failures and guarantees");

    {
        Rig rig(*fx.atm);
        check(!rig.logger.record(sampleEvent(0)), "record before init -> false");
        check(rig.logger.state() == LoggerState::Uninitialized, "state Uninitialized before init");
    }

    {
        Rig rig(*fx.atm);
        rig.logger.init();
        rig.fill(5);
        std::uint64_t seq = rig.logger.lastSeqNo();
        std::string hash = rig.logger.lastHash();

        rig.storage.setFailAppends(true);
        check(!rig.logger.record(sampleEvent(100)), "U27: record returns false on storage failure");
        check(rig.logger.lastSeqNo() == seq && rig.logger.lastHash() == hash,
            "U27: sequence and hash in memory unchanged");
        check(rig.logger.state() == LoggerState::Failed, "logger moves to Failed");

        rig.storage.setFailAppends(false);
        check(!rig.logger.record(sampleEvent(101)), "Failed is sticky until re-init");
        check(!rig.logger.sealCheckpoint(), "no checkpoint while Failed");

        check(rig.logger.init() == LoggerState::Ready, "re-init after storage recovers -> Ready");
        check(rig.logger.lastSeqNo() == seq + 1, "re-init continues the chain");
        check(LogVerifier(rig.storage, rig.signer).verifyChain().ok, "chain intact after failure and re-init");
    }

    {
        Rig rig(*fx.atm);
        rig.logger.init();
        rig.sink.setFail(true);
        check(rig.logger.record(sampleEvent(1)), "record works while checkpoint sink is down");
        check(!rig.logger.sealCheckpoint(), "sealCheckpoint reports undelivered checkpoint");
        check(rig.anchors.load().has_value(), "anchor still saved locally");
    }

    {
        FakeAuditSink fake;
        IAuditSink& sink = fake;
        check(sink.record(sampleEvent(1)) && fake.events().size() == 1, "FakeAuditSink stores events");
        fake.setFail(true);
        check(!sink.record(sampleEvent(2)) && fake.events().size() == 1, "FakeAuditSink can simulate failure");
    }
}

void testInit(HsmFixture& fx)
{
    section("init(): restart, torn writes, tampering");

    {
        Rig rig(*fx.atm);
        rig.logger.init();
        rig.fill(10);
        std::uint64_t last = rig.logger.lastSeqNo();

        AuditLogger restarted("ATM-001", rig.storage, rig.anchors, rig.signer, rig.sink, rig.clock);
        check(restarted.init() == LoggerState::Ready, "restart on intact log -> Ready");
        check(restarted.lastSeqNo() == last + 1, "restart continues sequence with LOG_STARTED");
        check(LogVerifier(rig.storage, rig.signer).verifyChain().ok, "chain valid across restart");
    }

    {
        Rig rig(*fx.atm);
        rig.logger.init();
        rig.fill(10);
        std::string half = rig.storage.lines().back().substr(0, 40);
        rig.storage.lines().push_back(half);

        AuditLogger restarted("ATM-001", rig.storage, rig.anchors, rig.signer, rig.sink, rig.clock);
        check(restarted.init() == LoggerState::Ready, "torn last line -> Ready (power loss is not tampering)");
        check(restarted.startupCheck().reason == VerifyError::TornTail, "startup check reports TornTail");

        auto entries = LogVerifier(rig.storage, rig.signer).readEntries(12, 12);
        check(entries.size() == 1 && entries[0].getEvent().type == EventType::LOG_INTEGRITY_FAILURE,
            "torn line is recorded by LOG_INTEGRITY_FAILURE");

        VerifyResult r = LogVerifier(rig.storage, rig.signer).verifyChain();
        check(r.ok && r.recoveredTornEntries == 1, "chain valid with one documented torn entry");
        check(rig.storage.lines()[11] == half, "torn line is kept, not repaired");
    }

    {
        Rig rig(*fx.atm);
        rig.logger.init();
        rig.fill(10);
        rig.storage.lines().insert(rig.storage.lines().begin() + 5, "junk");
        VerifyResult r = LogVerifier(rig.storage, rig.signer).verifyChain();
        check(!r.ok && r.reason == VerifyError::MalformedEntry && r.firstBadSeq == 6u,
            "junk line in the middle -> MalformedEntry");
    }

    {
        Rig rig(*fx.atm);
        rig.logger.init();
        rig.fill(10);
        rig.storage.lines()[4] = rewriteEntry(rig.storage.lines()[4], 1, false);

        AuditLogger restarted("ATM-001", rig.storage, rig.anchors, rig.signer, rig.sink, rig.clock);
        check(restarted.init() == LoggerState::Compromised, "tampered log -> Compromised");
        check(restarted.record(sampleEvent(1)), "Compromised logger still records evidence");

        VerifyResult r = LogVerifier(rig.storage, rig.signer).verifyChain();
        check(!r.ok && r.firstBadSeq == 5u, "original damage still reported, not hidden");

        auto entries = LogVerifier(rig.storage, rig.signer).readEntries(12, 12);
        check(entries.size() == 1
            && entries[0].getEvent().type == EventType::LOG_INTEGRITY_FAILURE
            && entries[0].getEvent().details.find("HashMismatch") != std::string::npos,
            "LOG_INTEGRITY_FAILURE names the damage");
    }

    {
        Rig rig(*fx.atm);
        rig.logger.init();
        rig.fill(59);
        check(rig.anchors.load() && rig.anchors.load()->seqNo == 50, "anchor at 50");
        rig.storage.lines().resize(40);

        AuditLogger restarted("ATM-001", rig.storage, rig.anchors, rig.signer, rig.sink, rig.clock);
        check(restarted.init() == LoggerState::Compromised, "truncation below local anchor -> Compromised");
        check(restarted.startupCheck().reason == VerifyError::CheckpointMissingEntry,
            "startup check reports CheckpointMissingEntry");
    }
}

void testHsmIntegration(HsmFixture& fx)
{
    section("HSM integration");

    Rig rig(*fx.atm);
    rig.logger.init();
    rig.fill(3);
    check(rig.logger.sealCheckpoint(), "sealCheckpoint at end of session");
    Checkpoint cp = rig.sink.items().back();

    BankHsmAuditSigner bankSigner(*fx.bank);
    check(verifyCheckpointMac(cp, bankSigner), "BankHsm accepts ATM checkpoint MAC");
    check(fx.bank->verifyAudit(checkpointPayload(cp), cp.mac), "BankHsm::verifyAudit on payload works directly");

    Checkpoint moved = cp;
    moved.logId = "ATM-002";
    check(!verifyCheckpointMac(moved, bankSigner), "checkpoint bound to its log id");

    InMemoryLogStorage serverStorage;
    InMemoryAnchorStore serverAnchors;
    InMemoryCheckpointSink serverSink;
    FakeClock clock;
    AuditLogger serverLog("SERVER", serverStorage, serverAnchors, bankSigner, serverSink, clock, 5);
    check(serverLog.init() == LoggerState::Ready, "server logger uses BankHsm signer");
    for (int i = 0; i < 4; ++i) (void)serverLog.record(sampleEvent(i));
    check(serverSink.items().size() == 1 && verifyCheckpointMac(serverSink.items()[0], bankSigner),
        "server checkpoints MACed by BankHsm");

    HsmFixture tamperFx;
    Rig tamperRig(*tamperFx.atm);
    tamperRig.logger.init();
    tamperFx.atm->reportTamper();
    LogEvent tamper;
    tamper.type = EventType::TAMPER_DETECTED;
    tamper.outcome = Outcome::Failure;
    check(tamperRig.logger.record(tamper), "TAMPER_DETECTED still recorded after keys wiped");
    check(!tamperRig.logger.sealCheckpoint(), "no checkpoint possible without auditKey");
    check(LogVerifier(tamperRig.storage, tamperRig.signer).verifyChain().ok, "hash chain needs no key");
}

void testFiles(HsmFixture& fx)
{
    section("File storage");

    auto dir = makeTempDir();
    auto logPath = dir / "atm.log";
    auto anchorPath = dir / "atm.anchor";
    AtmHsmAuditSigner signer(*fx.atm);
    InMemoryCheckpointSink sink;
    FakeClock clock;

    {
        FileLogStorage storage(logPath);
        FileAnchorStore anchors(anchorPath);
        check(storage.isOpen(), "log file opened");
        AuditLogger logger("ATM-001", storage, anchors, signer, sink, clock);
        check(logger.init() == LoggerState::Ready, "init on new file");
        for (int i = 0; i < 5; ++i) (void)logger.record(sampleEvent(i));
        check(logger.sealCheckpoint(), "checkpoint saved to anchor file");
    }

    {
        FileAnchorStore anchors(anchorPath);
        auto cp = anchors.load();
        check(cp && cp->seqNo == 6 && cp->logId == "ATM-001" && cp->mac.size() == 32,
            "anchor file roundtrip");
    }

    {
        FileLogStorage storage(logPath);
        FileAnchorStore anchors(anchorPath);
        AuditLogger logger("ATM-001", storage, anchors, signer, sink, clock);
        check(logger.init() == LoggerState::Ready, "reopen existing log -> Ready");
        check(logger.lastSeqNo() == 7, "sequence continues after reopen");
    }

    {
        std::ofstream raw(logPath, std::ios::app | std::ios::binary);
        raw << "8" << kLogFieldSeparator << "17000";
    }

    {
        FileLogStorage storage(logPath);
        FileAnchorStore anchors(anchorPath);
        AuditLogger logger("ATM-001", storage, anchors, signer, sink, clock);
        check(logger.init() == LoggerState::Ready, "torn write on disk -> Ready");
        check(logger.startupCheck().reason == VerifyError::TornTail, "torn write detected");
        VerifyResult r = LogVerifier(storage, signer).verifyChain();
        check(r.ok && r.entryCount == 9 && r.recoveredTornEntries == 1, "file chain valid after torn write");
    }

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

void testConcurrency(HsmFixture& fx)
{
    section("Concurrent writers");

    Rig rig(*fx.atm);
    rig.logger.init();
    auto worker = [&rig](int base) {
        for (int i = 0; i < 200; ++i) (void)rig.logger.record(sampleEvent(base + i));
    };
    std::thread a(worker, 0);
    std::thread b(worker, 1000);
    a.join();
    b.join();

    VerifyResult r = LogVerifier(rig.storage, rig.signer).verifyChain();
    check(r.ok && r.entryCount == 401, "two threads x 200 records -> valid chain of 401");
}

}

int main()
{
    std::cout << "Module 3 test suite\n";
    std::cout << "===================\n";

    if (!CryptoCore::init())
    {
        std::cerr << "FATAL: libsodium initialization failed\n";
        return 1;
    }

    HsmFixture fx;
    check(fx.operational, "setup: AtmHsm operational");

    testFormat();
    testMaskAndPolicy(*fx.atm);
    testChain(fx);
    testFailures(fx);
    testInit(fx);
    testHsmIntegration(fx);
    testFiles(fx);
    testConcurrency(fx);

    return gabella_test::summary();
}
