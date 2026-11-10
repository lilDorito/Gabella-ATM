#include <iostream>
#include <map>
#include <set>
#include <string>

#include "Check.h"
#include "ReconRig.h"
#include "ServerRig.h"
#include "audit/IntentRecovery.h"
#include "server/db/Statement.h"
#include "server/repo/AccountRepository.h"
#include "server/repo/CassetteRepository.h"
#include "server/repo/TxRepository.h"
#include "server/services/ReconciliationService.h"

using gabella_test::check;
using gabella_test::section;

namespace
{
void dispenseReportTests()
{
    section("Dispense reports");

    ReconRig ok;
    ok.hold(1);
    check(ok.txs.reservedTotal("ACC-1") == 50000, "a hold reserves the money without touching the balance");
    const DispenseReport paid = ok.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 49, 50));
    check(ok.recon.onDispenseReport(paid), "a report that matches the cassette counters is accepted");
    check(ok.status(1) == TxStatus::Committed, "the transaction is committed");
    check(ok.balance() == 1000000 - 50000 && ok.txs.reservedTotal("ACC-1") == 0, "the balance is debited exactly once and the hold is gone");
    check(ok.expected() == counts(50, 50, 49, 50), "the expected cassette counters follow the dispense");
    check(ok.events(EventType::TX_COMMITTED, Outcome::Info) == 1 && ok.events(EventType::TX_COMMITTED, Outcome::Success) == 1, "the commit is logged first as an intent and then as a result");
    check(ok.recon.onDispenseReport(paid) && ok.balance() == 950000 && ok.events(EventType::TX_COMMITTED, Outcome::Success) == 1, "a repeated report is accepted without a second debit");
    check(ok.txs.findBySeq(kRigAtm, 1)->resolvedBy == "reconciliation" && !ok.txs.findBySeq(kRigAtm, 1)->reason.empty(), "who decided and why is stored");

    ReconRig failed;
    failed.hold(1);
    check(failed.recon.onDispenseReport(failed.dispenseReport(1, DispenseResult::HardwareFault, kFull)), "a failure report with untouched counters is accepted");
    check(failed.status(1) == TxStatus::Reversed && failed.balance() == 1000000, "the hold is released and the balance is untouched");
    check(failed.txs.reservedTotal("ACC-1") == 0 && failed.expected() == kFull, "nothing stays reserved and the counters are unchanged");
    check(failed.recon.onDispenseReport(failed.dispenseReport(1, DispenseResult::HardwareFault, kFull)) && failed.events(EventType::TX_REVERSED, Outcome::Success) == 1,
        "a repeated failure report is idempotent");

    ReconRig liar;
    liar.hold(1);
    check(liar.recon.onDispenseReport(liar.dispenseReport(1, DispenseResult::Ok, kFull)) && liar.status(1) == TxStatus::Uncertain, "a dispensed claim with unchanged counters is not trusted");
    check(liar.balance() == 1000000 && liar.txs.reservedTotal("ACC-1") == 50000, "an uncertain transaction keeps its money reserved");

    ReconRig hidden;
    hidden.hold(1);
    check(hidden.recon.onDispenseReport(hidden.dispenseReport(1, DispenseResult::HardwareFault, counts(50, 50, 49, 50))) && hidden.status(1) == TxStatus::Uncertain,
        "a failure claim while notes left the machine is not trusted");

    ReconRig wrongAmount;
    wrongAmount.hold(1);
    check(wrongAmount.recon.onDispenseReport(wrongAmount.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 48, 50))) && wrongAmount.status(1) == TxStatus::Uncertain,
        "counters that fell by a different amount leave the transaction uncertain");
    check(wrongAmount.expected() == kFull && wrongAmount.events(EventType::AUTH_DECISION, Outcome::Failure) == 1, "the mismatch is logged and the expected counters stay");

    ReconRig more;
    more.hold(1);
    check(more.recon.onDispenseReport(more.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 51, 50))) && more.status(1) == TxStatus::Uncertain, "counters that grew are inconclusive");

    ReconRig refused;
    refused.hold(1);
    check(!refused.recon.onDispenseReport(refused.dispenseReport(9, DispenseResult::Ok, kFull)), "a report for a command the server never issued is refused");
    DispenseReport otherSession = refused.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 49, 50));
    otherSession.sessionId = "someone-else";
    check(!refused.recon.onDispenseReport(otherSession) && refused.status(1) == TxStatus::Held, "a report for another session is refused");
    check(!refused.recon.onDispenseReport(refused.dispenseReport(1, DispenseResult::Ok, { { 50, 1 } })), "an unknown denomination is refused");
    check(!refused.recon.onDispenseReport(refused.dispenseReport(1, DispenseResult::Ok, { { 100, -1 } })), "a negative count is refused");
    check(refused.status(1) == TxStatus::Held && refused.balance() == 1000000, "refused reports change nothing");

    ReconRig contradictLate;
    contradictLate.hold(1);
    (void)contradictLate.recon.onDispenseReport(contradictLate.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 49, 50)));
    check(!contradictLate.recon.onDispenseReport(contradictLate.dispenseReport(1, DispenseResult::HardwareFault, counts(50, 50, 49, 50))), "a failure report after a commit is refused");
    check(contradictLate.status(1) == TxStatus::Committed && contradictLate.balance() == 950000, "a committed transaction is final");

    ReconRig reversedLate;
    reversedLate.hold(1);
    (void)reversedLate.recon.onDispenseReport(reversedLate.dispenseReport(1, DispenseResult::HardwareFault, kFull));
    check(!reversedLate.recon.onDispenseReport(reversedLate.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 49, 50))), "a dispensed report after a reversal is refused");
    check(reversedLate.status(1) == TxStatus::Reversed && reversedLate.events(EventType::TX_REVERSED, Outcome::Failure) == 1, "a reversed transaction is final and the contradiction is logged");

    ReconRig broke;
    broke.hold(1);
    Statement drain(broke.db, "UPDATE accounts SET balance_kop = 100 WHERE account_id = 'ACC-1'");
    drain.run();
    check(!broke.recon.onDispenseReport(broke.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 49, 50))), "a commit the account cannot cover is not accepted");
    check(broke.status(1) == TxStatus::Held && broke.balance() == 100 && broke.expected() == kFull, "nothing changes when the debit fails");
    check(broke.events(EventType::TX_COMMITTED, Outcome::Failure) == 1, "the failed commit is logged");

    ReconRig blind;
    blind.hold(1);
    blind.logStorage.setFailAppends(true);
    check(!blind.recon.onDispenseReport(blind.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 49, 50))), "without the write-ahead log record nothing is decided");
    check(blind.status(1) == TxStatus::Held && blind.balance() == 1000000, "the transaction is untouched when the log is unavailable");
}

void timeoutTests()
{
    section("Missing reports");

    ReconRig r;
    r.hold(1);
    r.clock.advance(119);
    check(r.recon.tick() == 0 && r.status(1) == TxStatus::Held, "119 seconds without a report is still fine");
    r.clock.advance(1);
    check(r.recon.tick() == 1 && r.status(1) == TxStatus::Uncertain, "after 120 seconds the transaction becomes uncertain");
    check(r.recon.tick() == 0, "an uncertain transaction is not moved again");
    check(r.txs.reservedTotal("ACC-1") == 50000 && r.balance() == 1000000, "the money stays reserved");
    check(r.recon.hasUnresolved(kRigAtm), "the ATM is held back until the transaction is settled");
    check(r.events(EventType::TX_UNCERTAIN, Outcome::Info) == 1 && r.events(EventType::TX_UNCERTAIN, Outcome::Success) == 1, "the timeout is logged");
    check(r.txs.findBySeq(kRigAtm, 1)->reason == "no_report_in_time", "the reason is stored");

    ReconRig late;
    late.hold(1, 50000, 130);
    check(late.recon.onDispenseReport(late.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 49, 50))), "a late report is accepted");
    check(late.status(1) == TxStatus::Committed && late.events(EventType::TX_UNCERTAIN, Outcome::Success) == 1, "a late report first shows the transaction was uncertain, then settles it");
    check(!late.recon.hasUnresolved(kRigAtm), "nothing is left open");

    ReconRig fresh;
    fresh.hold(1);
    check(fresh.recon.hasUnresolved(kRigAtm), "a held transaction counts as unresolved");
    (void)fresh.recon.onDispenseReport(fresh.dispenseReport(1, DispenseResult::HardwareFault, kFull));
    check(!fresh.recon.hasUnresolved(kRigAtm), "a settled transaction does not");
    check(!fresh.recon.hasUnresolved("ATM-OTHER"), "another ATM is not affected");
}

void reconnectTests()
{
    section("Reconnect reports");

    ReconRig paid;
    paid.hold(1);
    check(paid.recon.onStatusReport(paid.statusReport(StatusReason::Reconnect, 1, counts(50, 50, 49, 50))), "a reconnect report is accepted");
    check(paid.status(1) == TxStatus::Committed && paid.balance() == 950000, "notes that left the cassettes commit the transaction");
    check(paid.expected() == counts(50, 50, 49, 50), "the expected counters follow");

    ReconRig same;
    same.hold(1);
    check(same.recon.onStatusReport(same.statusReport(StatusReason::Reconnect, 1, kFull)), "a reconnect with unchanged counters is accepted");
    check(same.status(1) == TxStatus::Reversed && same.balance() == 1000000, "unchanged counters reverse a command that was reached");

    ReconRig never;
    never.hold(2);
    check(never.recon.onStatusReport(never.statusReport(StatusReason::Reconnect, 1, kFull)) && never.status(2) == TxStatus::Held, "a command that may still be valid is not reversed yet");
    never.clock.advance(121);
    check(never.recon.onStatusReport(never.statusReport(StatusReason::Reconnect, 1, kFull)) && never.status(2) == TxStatus::Reversed,
        "once the command has expired and the sequence was not reached it is reversed");
    check(never.txs.findBySeq(kRigAtm, 2)->reason == "sequence_not_reached", "the reason is stored");

    ReconRig two;
    two.hold(1, 50000);
    two.hold(2, 20000);
    check(two.recon.onStatusReport(two.statusReport(StatusReason::Reconnect, 2, counts(50, 49, 49, 50))), "two open transactions are settled together");
    check(two.status(1) == TxStatus::Committed && two.status(2) == TxStatus::Committed && two.balance() == 1000000 - 70000, "a total that matches both commits both");

    ReconRig unclear;
    unclear.hold(1, 50000);
    unclear.hold(2, 20000);
    check(unclear.recon.onStatusReport(unclear.statusReport(StatusReason::Reconnect, 2, counts(50, 50, 49, 50))), "a total that matches neither is still accepted");
    check(unclear.status(1) == TxStatus::Uncertain && unclear.status(2) == TxStatus::Uncertain && unclear.balance() == 1000000, "inconclusive counters leave both uncertain and the money reserved");
    check(unclear.expected() == kFull, "inconclusive counters do not move the expectation");

    ReconRig mismatch;
    check(mismatch.recon.onStatusReport(mismatch.statusReport(StatusReason::Reconnect, 0, counts(50, 50, 49, 50))), "a reconnect with nothing open is accepted");
    check(mismatch.expected() == kFull && mismatch.events(EventType::AUTH_DECISION, Outcome::Failure) == 1, "a difference without open transactions is logged, not adopted");

    ReconRig quiet;
    check(quiet.recon.onStatusReport(quiet.statusReport(StatusReason::Reconnect, 0, kFull)) && quiet.events(EventType::AUTH_DECISION, Outcome::Failure) == 0, "matching counters are silent");
    check(!quiet.recon.onStatusReport(quiet.statusReport(StatusReason::Reconnect, 0, { { 100, -5 } })), "invalid counters are refused");
}

void staffReportTests()
{
    section("Cassette reports from staff");

    ReconRig load;
    check(load.recon.onStatusReport(load.statusReport(StatusReason::CashLoaded, 0, counts(60, 60, 60, 60), "tok-eng")), "an engineer's load report is accepted");
    check(load.expected() == counts(60, 60, 60, 60), "the expected counters become the reported ones");
    check(load.events(EventType::AUDIT_ACCESS, Outcome::Info) == 1, "the load is logged");

    ReconRig forged;
    check(!forged.recon.onStatusReport(forged.statusReport(StatusReason::CashLoaded, 0, counts(99, 99, 99, 99), "tok-col")), "a collector cannot report a load");
    check(!forged.recon.onStatusReport(forged.statusReport(StatusReason::CashLoaded, 0, counts(99, 99, 99, 99), "")), "a load report without a token is refused");
    check(!forged.recon.onStatusReport(forged.statusReport(StatusReason::CashLoaded, 0, counts(99, 99, 99, 99), "tok-unknown")), "a load report with an unknown token is refused");
    check(!forged.recon.onStatusReport(forged.statusReport(StatusReason::CashCollected, 0, kFull, "tok-eng")), "an engineer cannot report a collection");
    check(forged.expected() == kFull && forged.events(EventType::ACCESS_DENIED, Outcome::Failure) == 4, "refused reports change nothing and are logged");

    ReconRig collect;
    check(collect.recon.onStatusReport(collect.statusReport(StatusReason::CashCollected, 0, kFull, "tok-col")), "a collection that matches the expectation is accepted");
    check(collect.expected() == counts(0, 0, 0, 0) && collect.events(EventType::AUDIT_ACCESS, Outcome::Failure) == 0, "the cassettes are expected empty and nothing is flagged");

    ReconRig short_;
    check(short_.recon.onStatusReport(short_.statusReport(StatusReason::CashCollected, 0, counts(50, 49, 50, 50), "tok-col")), "a collection with a shortfall is still recorded");
    check(short_.events(EventType::AUDIT_ACCESS, Outcome::Failure) == 1 && short_.expected() == counts(0, 0, 0, 0), "the difference is flagged in the log");

    ReconRig open;
    open.hold(1);
    check(open.recon.onStatusReport(open.statusReport(StatusReason::CashLoaded, 0, counts(60, 60, 60, 60), "tok-eng")), "an engineer's report is accepted while a transaction is open");
    check(open.status(1) == TxStatus::Held && open.expected() == counts(60, 60, 60, 60), "the open transaction is left for later");

    ReconRig blind;
    blind.logStorage.setFailAppends(true);
    check(!blind.recon.onStatusReport(blind.statusReport(StatusReason::CashLoaded, 0, counts(60, 60, 60, 60), "tok-eng")) && blind.expected() == kFull,
        "without a log record the expectation is not changed");
}

void serverPathTests()
{
    section("Through the server facade");

    ReconRig r;
    r.hold(1);
    const DispenseReport rep = r.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 49, 50));
    const RequestHeader header = r.header(ApiCall::ReportDispense, rep.payload());
    check(r.reconServer.reportDispense(header, rep) && r.status(1) == TxStatus::Committed, "a MACed dispense report reaches the service");
    check(!r.reconServer.reportDispense(header, rep), "the same header cannot be used twice");

    r.hold(2);
    DispenseReport tampered = r.dispenseReport(2, DispenseResult::HardwareFault, counts(50, 50, 49, 50));
    const RequestHeader forgedHeader = r.header(ApiCall::ReportDispense, tampered.payload());
    tampered.result = DispenseResult::Ok;
    check(!r.reconServer.reportDispense(forgedHeader, tampered) && r.status(2) == TxStatus::Held, "a report altered after it was MACed is refused");

    r.clock.advance(300);
    const DispenseReport stale = r.dispenseReport(2, DispenseResult::HardwareFault, counts(50, 50, 49, 50));
    RequestHeader old = r.header(ApiCall::ReportDispense, stale.payload());
    old.timestamp -= 300;
    check(!r.reconServer.reportDispense(old, stale) && r.status(2) == TxStatus::Held, "a stale request is refused before it reaches the service");
    check(r.recon.tick() == 1 && r.status(2) == TxStatus::Uncertain, "the unreported hold becomes uncertain on the next tick");

    const StatusReport sync = r.statusReport(StatusReason::Reconnect, 2, counts(50, 50, 49, 50));
    check(r.reconServer.syncStatus(r.header(ApiCall::SyncStatus, sync.payload()), sync), "a MACed reconnect report is accepted");
    check(r.status(2) == TxStatus::Reversed, "the reconnect report settles the uncertain transaction by its counters");

    ReconRig other;
    other.hold(1);
    const DispenseReport foreign = other.dispenseReport(1, DispenseResult::Ok, counts(50, 50, 49, 50));
    RequestHeader wrongAtm = other.header(ApiCall::ReportDispense, foreign.payload());
    wrongAtm.atmId = "ATM-OTHER";
    check(!other.reconServer.reportDispense(wrongAtm, foreign) && other.status(1) == TxStatus::Held, "a header for another ATM is refused");
}

void recoveryTests()
{
    section("Recovery after a crash");

    ReconRig r;
    const std::int64_t id = r.hold(1);
    LogEvent intent;
    intent.type = EventType::TX_COMMITTED;
    intent.outcome = Outcome::Info;
    intent.actorRole = Role::System;
    intent.actorId = kRigAtm;
    intent.details = "tx=" + std::to_string(id) + " seq=1 by=reconciliation reason=test";
    intent.opId = ReconciliationService::opIdFor(id, TxStatus::Committed);
    check(r.log.record(intent), "an intent without a result is on the log");

    LogVerifier verifier(r.logStorage, r.logSigner);
    IntentRecovery recovery(verifier, r.log);
    const RecoveryReport first = recovery.run({ &r.recon });
    check(first.open == 1 && first.resolved == 1 && first.unowned == 0, "recovery finds the intent and resolves it");
    check(r.events(EventType::TX_COMMITTED, Outcome::Failure) == 1, "an intent whose change never reached the database is closed as failed");

    ReconRig applied;
    const std::int64_t id2 = applied.hold(1);
    LogEvent intent2 = intent;
    intent2.details = "tx=" + std::to_string(id2) + " seq=1 by=reconciliation reason=test";
    intent2.opId = ReconciliationService::opIdFor(id2, TxStatus::Committed);
    check(applied.log.record(intent2), "a second intent is logged");
    check(applied.txs.setStatus(id2, TxStatus::Committed, applied.clock.nowUnix(), "reconciliation", "test"), "its change did reach the database");
    LogVerifier verifier2(applied.logStorage, applied.logSigner);
    IntentRecovery recovery2(verifier2, applied.log);
    const RecoveryReport second = recovery2.run({ &applied.recon });
    check(second.resolved == 1 && applied.events(EventType::TX_COMMITTED, Outcome::Success) == 1, "an intent whose change was applied is closed as successful");

    const RecoveryReport again = recovery2.run({ &applied.recon });
    check(again.open == 0, "nothing is left to recover");
    check(ReconciliationService::opIdFor(7, TxStatus::Reversed) == "tx/7/REVERSED", "operation ids have a fixed shape");
}
}

int main()
{
    gabella_test::banner("Reconciliation service test suite");
    if (!CryptoCore::init())
    {
        std::cerr << "fatal: libsodium initialization failed\n";
        return 1;
    }

    dispenseReportTests();
    timeoutTests();
    reconnectTests();
    staffReportTests();
    serverPathTests();
    recoveryTests();

    return gabella_test::summary();
}
