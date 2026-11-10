#include <iostream>
#include <string>

#include "Check.h"
#include "ServerRig.h"
#include "audit/CheckpointPayload.h"
#include "audit/InMemoryCheckpointSink.h"
#include "audit/IntentRecovery.h"
#include "server/db/DbError.h"

using gabella_test::check;
using gabella_test::section;

namespace
{
Checkpoint atmCheckpoint(ServerRig& r, std::uint64_t seq, const std::string& hash, const std::string& atmId = kRigAtm)
{
    Checkpoint cp;
    cp.logId = atmId;
    cp.seqNo = seq;
    cp.hash = hash;
    cp.timestamp = r.clock.nowUnix();
    cp.mac = *r.fx.atm->macAudit(checkpointPayload(cp));
    return cp;
}

std::size_t countDetails(ServerRig& r, const std::string& needle)
{
    std::size_t n = 0;
    for (const auto& entry : LogVerifier(r.logStorage, r.logSigner).readEntries(1, 1000000))
        if (entry.getEvent().details.find(needle) != std::string::npos) ++n;
    return n;
}

LogEvent intentEvent(EventType type, const std::string& opId)
{
    LogEvent e;
    e.type = type;
    e.outcome = Outcome::Info;
    e.actorId = kRigAtm;
    e.opId = opId;
    return e;
}

bool rejectedUpdate(ServerRig& r)
{
    try
    {
        r.db.exec("UPDATE atm_checkpoints SET hash = 'x'");
        return false;
    }
    catch (const DbError&)
    {
        return true;
    }
}

bool rejectedDelete(ServerRig& r)
{
    try
    {
        r.db.exec("DELETE FROM atm_checkpoints");
        return false;
    }
    catch (const DbError&)
    {
        return true;
    }
}

void serverLogTests()
{
    section("The server's own log");

    ServerRig r;
    check(r.log.sealCheckpoint(), "the server log seals a checkpoint");
    const auto cp = r.checkpoints.latest(kServerLogId);
    check(cp && cp->seqNo == r.log.lastSeqNo(), "its checkpoints are stored under the SERVER log id");
    check(cp && r.fx.bank->verifyServerAudit(checkpointPayload(*cp), cp->mac), "they are MACed with the server audit key");
    check(cp && !r.fx.bank->verifyAudit(kRigAtm, checkpointPayload(*cp), cp->mac), "the ATM audit key does not verify them");
    check(r.checkpointService.submit(kServerLogId, *cp) == CheckpointVerdict::UnknownAtm, "nobody can submit into the server's log");
}

void submitTests()
{
    section("Checkpoint submission");

    ServerRig r;
    InMemoryLogStorage atmStorage;
    InMemoryAnchorStore atmAnchors;
    InMemoryCheckpointSink atmSink;
    AtmHsmAuditSigner atmSigner(*r.fx.atm);
    AuditLogger atmLog(kRigAtm, atmStorage, atmAnchors, atmSigner, atmSink, r.clock, 50);
    (void)atmLog.init();
    check(atmLog.sealCheckpoint() && !atmSink.items().empty(), "the ATM log produces a real checkpoint");
    const Checkpoint real = atmSink.items().back();

    check(r.checkpointService.submit(kRigAtm, real) == CheckpointVerdict::Accepted, "a genuine ATM checkpoint is accepted");
    check(r.checkpoints.find(kRigAtm, real.seqNo).has_value(), "it is stored");
    check(r.count(EventType::CHECKPOINT_ACCEPTED) == 2, "acceptance is logged as an intent and a result");
    check(LogVerifier(r.logStorage, r.logSigner).openIntents().empty(), "no intent is left open");
    check(r.checkpointService.submit(kRigAtm, real) == CheckpointVerdict::AlreadyKnown, "a resent checkpoint is recognised");
    check(r.count(EventType::CHECKPOINT_ACCEPTED) == 2, "a resend is not stored or logged twice");

    const Checkpoint later = atmCheckpoint(r, real.seqNo + 50, "hash-b");
    check(r.checkpointService.submit(kRigAtm, later) == CheckpointVerdict::Accepted, "a later checkpoint is accepted");
    check(r.checkpointService.submit(kRigAtm, real) == CheckpointVerdict::AlreadyKnown, "an older stored checkpoint is still recognised");

    check(r.checkpointService.submit("ATM-404", atmCheckpoint(r, 500, "h", "ATM-404")) == CheckpointVerdict::UnknownAtm, "an unknown ATM is refused");
    r.atms.insert("ATM-002");
    check(r.checkpointService.submit("ATM-002", atmCheckpoint(r, 500, "h")) == CheckpointVerdict::WrongLog, "an ATM cannot submit another ATM's log");

    Checkpoint forged = atmCheckpoint(r, 500, "h");
    forged.hash = "other";
    check(r.checkpointService.submit(kRigAtm, forged) == CheckpointVerdict::BadMac, "a checkpoint changed after MACing is refused");
    Checkpoint zero = atmCheckpoint(r, 0, "h");
    check(r.checkpointService.submit(kRigAtm, zero) == CheckpointVerdict::BadMac, "sequence 0 is refused");

    r.clock.advance(3600);
    Checkpoint future = atmCheckpoint(r, 500, "h");
    r.clock.advance(-3600);
    check(r.checkpointService.submit(kRigAtm, future) == CheckpointVerdict::FromTheFuture, "a checkpoint from the future is refused");
    check(r.count(EventType::CHECKPOINT_REJECTED) == 5, "each refusal is logged");
    check(!r.checkpoints.find(kRigAtm, 500).has_value(), "nothing refused is stored");

    check(rejectedUpdate(r), "stored checkpoints cannot be changed");
    check(rejectedDelete(r), "stored checkpoints cannot be deleted");
}

void rollbackTests()
{
    section("Rollback detection");

    ServerRig r;
    check(r.checkpointService.submit(kRigAtm, atmCheckpoint(r, 100, "hash-100")) == CheckpointVerdict::Accepted, "a baseline checkpoint is accepted");
    check(!r.atms.find(kRigAtm)->logReviewRequired, "the ATM starts without a review flag");

    check(r.checkpointService.submit(kRigAtm, atmCheckpoint(r, 100, "rewritten")) == CheckpointVerdict::Rollback, "the same position with a different hash is a rollback");
    check(countDetails(r, "kind=rewrite") == 1, "it is logged as a rewrite");
    check(r.checkpointService.submit(kRigAtm, atmCheckpoint(r, 60, "hash-60")) == CheckpointVerdict::Rollback, "an earlier position never seen before is a rollback");
    check(countDetails(r, "kind=truncation") == 1, "it is logged as a truncation");
    check(r.count(EventType::LOG_ROLLBACK_DETECTED) == 2, "both are logged as LOG_ROLLBACK_DETECTED");
    check(r.atms.find(kRigAtm)->logReviewRequired, "the ATM is flagged for log review");
    check(r.atms.find(kRigAtm)->status == AtmStatus::Active, "the ATM is not taken out of service automatically");
    check(r.checkpoints.latest(kRigAtm)->hash == "hash-100", "the stored history is unchanged");
}

void failureTests()
{
    section("Write failures");

    ServerRig r;
    r.logStorage.setFailAppends(true);
    check(r.checkpointService.submit(kRigAtm, atmCheckpoint(r, 10, "h")) == CheckpointVerdict::LogUnavailable, "without a working log nothing is accepted");
    check(!r.checkpoints.find(kRigAtm, 10).has_value(), "nothing is stored before it is logged");
}

void facadeTests()
{
    section("Checkpoints through the facade");

    ServerRig r;
    const Checkpoint cp = atmCheckpoint(r, 50, "hash-50");
    check(r.server.submitCheckpoint(r.header(ApiCall::SubmitCheckpoint, cp.payload()), cp), "a checkpoint with a valid envelope is accepted");
    Checkpoint swapped = atmCheckpoint(r, 100, "hash-100");
    check(!r.server.submitCheckpoint(r.header(ApiCall::SubmitCheckpoint, cp.payload()), swapped), "an envelope for one checkpoint cannot carry another");
    check(!r.checkpoints.find(kRigAtm, 100).has_value(), "the swapped checkpoint is not stored");

    const std::string auditor = r.tokens.issue("AU-01", Role::Auditor, kRigAtm);
    const RequestHeader h = r.header(ApiCall::LatestCheckpoint, ApiBody::latestCheckpoint(auditor));
    const auto reply = r.server.latestCheckpoint(h, auditor);
    check(reply && reply->checkpoint.seqNo == 50 && reply->requestNonce == h.nonce, "an auditor gets the latest checkpoint with the request nonce echoed");
    check(reply && r.fx.atm->verifyServer(SignDomain::Checkpoint, reply->signedPayload(), reply->signature), "the ATM verifies the server's signature");
    check(reply && !r.fx.atm->verifyServer(SignDomain::Response, reply->signedPayload(), reply->signature), "the signature is bound to the checkpoint domain");
    check(r.count(EventType::AUDIT_ACCESS) == 1, "the access is logged");

    const std::size_t deniedBefore = r.count(EventType::ACCESS_DENIED);
    const std::string engineer = r.tokens.issue("E-01", Role::ServiceEngineer, kRigAtm);
    check(!r.server.latestCheckpoint(r.header(ApiCall::LatestCheckpoint, ApiBody::latestCheckpoint(engineer)), engineer), "an engineer cannot read checkpoints");
    const std::string elsewhere = r.tokens.issue("AU-02", Role::Auditor, "ATM-002");
    check(!r.server.latestCheckpoint(r.header(ApiCall::LatestCheckpoint, ApiBody::latestCheckpoint(elsewhere)), elsewhere), "an auditor signed in at another ATM is refused");
    check(r.count(EventType::ACCESS_DENIED) == deniedBefore + 2, "refusals are logged");

    r.atms.insert("ATM-002");
    const std::string fresh = r.tokens.issue("AU-03", Role::Auditor, "ATM-002");
    check(!r.server.latestCheckpoint(r.header(ApiCall::LatestCheckpoint, ApiBody::latestCheckpoint(fresh), "ATM-002"), fresh), "an ATM without checkpoints gets none");
}

void recoveryTests()
{
    section("Intent recovery after a crash");

    ServerRig r;
    const Checkpoint stored = atmCheckpoint(r, 20, "hash-20");
    r.checkpoints.append(stored, r.clock.nowUnix());
    const Checkpoint lost = atmCheckpoint(r, 30, "hash-30");
    check(r.log.record(intentEvent(EventType::CHECKPOINT_ACCEPTED, CheckpointService::opIdFor(stored))), "an intent whose write landed");
    check(r.log.record(intentEvent(EventType::CHECKPOINT_ACCEPTED, CheckpointService::opIdFor(lost))), "an intent whose write was lost");
    check(r.log.record(intentEvent(EventType::DISPENSE_REQUESTED, "tx/ATM-001/7")), "an intent nobody owns yet");

    const LogVerifier verifier(r.logStorage, r.logSigner);
    check(verifier.openIntents().size() == 3, "three intents are open after the crash");

    IntentRecovery recovery(verifier, r.log);
    const RecoveryReport first = recovery.run({ &r.checkpointService });
    check(first.open == 3 && first.resolved == 2 && first.unowned == 1 && first.failed == 0, "owned intents are resolved, the rest are counted");
    check(countDetails(r, "recovered=committed") == 1, "a stored checkpoint is recorded as committed");
    check(countDetails(r, "recovered=absent") == 1, "a missing one is recorded as absent");
    check(countDetails(r, "reason=unowned_intents count=1") == 1, "unowned intents are reported once");
    check(verifier.openIntents().size() == 1, "only the unowned intent stays open");

    const RecoveryReport second = recovery.run({ &r.checkpointService });
    check(second.resolved == 0 && countDetails(r, "recovered=") == 2, "running recovery again changes nothing");
    check(verifier.verifyChain().ok, "the log stays intact through recovery");
}
}

int main()
{
    gabella_test::banner("Server audit test suite");
    if (!CryptoCore::init())
    {
        std::cerr << "fatal: libsodium initialization failed\n";
        return 1;
    }

    serverLogTests();
    submitTests();
    rollbackTests();
    failureTests();
    facadeTests();
    recoveryTests();

    return gabella_test::summary();
}
