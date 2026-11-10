#include <cstdint>
#include <functional>
#include <iostream>
#include <string>

#include "Check.h"
#include "ServerRig.h"
#include "audit/IntentRecovery.h"
#include "common/Card.h"
#include "crypto/KeyWrap.h"
#include "crypto/PinModule.h"
#include "server/repo/AccountRepository.h"
#include "server/repo/CardRepository.h"
#include "server/db/Statement.h"
#include "server/repo/TransactionRepository.h"
#include "server/services/AuthorizationService.h"

using gabella_test::check;
using gabella_test::section;

namespace
{
constexpr std::int64_t uah(std::int64_t n) { return n * 100; }

const std::string kPan = "5432101234567890";
const std::string kPin = "1234";

class HookSink final : public IAuditSink
{
public:
    IAuditSink& inner;
    std::function<void(const LogEvent&)> onRecord;
    bool failIntents = false;
    bool failAll = false;

    explicit HookSink(IAuditSink& target) : inner(target) {}

    bool record(const LogEvent& e) override
    {
        if (onRecord) onRecord(e);
        if (failAll) return false;
        if (failIntents && e.outcome == Outcome::Info && !e.opId.empty()) return false;
        return inner.record(e);
    }
};

struct AuthRig
{
    ServerRig r;
    CardRepository cards{ r.db };
    AccountRepository accounts{ r.db };
    TransactionRepository txs{ r.db };
    HookSink sink{ r.log };
    AuthorizationService service{ *r.fx.bank, r.db, r.atms, cards, accounts, txs, sink, r.clock, r.config };
    BankServer server{ *r.fx.bank, r.log, r.gate, r.atms, r.checkpointService, ServerParts{ service, r.unavailable, r.unavailable, r.unavailable, r.unavailable } };
    PinModule pinModule{ *r.fx.atm };

    AuthRig() { addCard(kPan, "ACC-1", uah(50000), 12, 2030, kPin); }

    void addCard(const std::string& pan, const std::string& accountId, std::int64_t balanceKop, int expMonth, int expYear, const std::string& pin)
    {
        if (!accounts.find(accountId)) accounts.insert(AccountRecord{ accountId, "Test Owner", balanceKop });
        CardRecord card;
        card.pan = pan;
        card.accountId = accountId;
        card.expMonth = expMonth;
        card.expYear = expYear;
        card.pinVerifyValue = *r.fx.bank->computePinVerifyValue(pan, pin);
        cards.insert(card);
    }

    AuthRequest request(Action action, std::int64_t amountKop, const std::string& pin = kPin, const std::string& pan = kPan, const std::string& session = "S-1")
    {
        return *pinModule.processPin(Card(pan, 12, 2030), pin, action, amountKop, session, kRigAtm, r.clock.nowUnix());
    }

    AuthResponse ask(Action action, std::int64_t amountKop, const std::string& pin = kPin, const std::string& pan = kPan)
    {
        return server.authorize(request(action, amountKop, pin, pan));
    }

    std::int64_t balance(const std::string& accountId = "ACC-1") { return accounts.find(accountId)->balanceKop; }
    std::uint32_t attempts(const std::string& pan = kPan) { return cards.find(pan)->failedPinAttempts; }
    std::uint64_t lastSeq(const std::string& atmId = kRigAtm) { return r.atms.find(atmId)->lastDispenseSeq; }
    bool takeSequence(std::uint64_t expected)
    {
        Statement s(r.db, "UPDATE atms SET last_dispense_seq = last_dispense_seq + 1 WHERE atm_id = ? AND last_dispense_seq = ?");
        s.bind(1, kRigAtm).bind(2, static_cast<std::int64_t>(expected)).run();
        return r.db.changes() == 1;
    }
    std::size_t openIntents() { return LogVerifier(r.logStorage, r.logSigner).openIntents().size(); }

    std::size_t logged(const std::string& needle)
    {
        std::size_t n = 0;
        for (const auto& entry : LogVerifier(r.logStorage, r.logSigner).readEntries(1, 1000000))
            if (entry.getEvent().details.find(needle) != std::string::npos) ++n;
        return n;
    }
};

bool bringUp(AtmHsm& atm, const AtmKeySet& k)
{
    bool ok = atm.installMasterKey(k.masterKey);
    ok = ok && atm.updateWorkingKey(KeyType::Encryption, *wrapWorkingKey(k.masterKey, KeyType::Encryption, k.encKey));
    ok = ok && atm.updateWorkingKey(KeyType::Mac, *wrapWorkingKey(k.masterKey, KeyType::Mac, k.macKey));
    ok = ok && atm.updateWorkingKey(KeyType::Audit, *wrapWorkingKey(k.masterKey, KeyType::Audit, k.auditKey));
    return ok && atm.state() == AtmHsmState::Operational;
}

void balanceAndWithdrawalTests()
{
    section("Authorization: balance and withdrawal");

    AuthRig a;
    const AuthResponse bal = a.ask(Action::CheckBalance, 0);
    check(bal.status == AuthStatus::Approved && bal.balance && bal.balance->kop() == uah(50000) && !bal.command, "a balance request is approved and shows the balance");
    check(a.r.fx.atm->verifyServer(SignDomain::Response, bal.signedPayload(), bal.signature), "the answer is signed by the bank");
    check(a.balance() == uah(50000) && a.lastSeq() == 0, "a balance request moves nothing");

    const AuthResponse first = a.ask(Action::Withdraw, uah(500));
    check(first.status == AuthStatus::Approved && first.command.has_value(), "a withdrawal is approved with a dispense command");
    if (!first.command) return;
    const DispenseCommand& cmd = *first.command;
    check(cmd.atmId == kRigAtm && cmd.sessionId == "S-1" && cmd.amountKop == uah(500) && cmd.sequence == 1, "the command names the ATM, session, amount and sequence 1");
    check(cmd.expiresAt == a.r.clock.nowUnix() + a.r.config.dispenseCommandLifetimeSeconds, "the command lives for the configured lifetime");
    check(a.r.fx.atm->verifyServer(SignDomain::Dispense, cmd.signedPayload(), cmd.signature), "the command is signed in the dispense domain");
    check(!a.r.fx.atm->verifyServer(SignDomain::Command, cmd.signedPayload(), cmd.signature), "and cannot pass as a service command");
    check(a.r.fx.atm->verifyServer(SignDomain::Response, first.signedPayload(), first.signature), "the whole answer is signed too");

    check(a.balance() == uah(50000) - uah(500), "the money is taken from the account");
    const auto tx = a.txs.find(kRigAtm, 1);
    check(tx && tx->status == "HELD" && tx->amountKop == uah(500) && tx->sessionId == "S-1" && tx->accountId == "ACC-1", "it is held in a transaction");
    check(a.lastSeq() == 1, "the ATM's dispense sequence moved on");
    check(a.openIntents() == 0 && a.r.count(EventType::AUTH_DECISION) == 3, "the withdrawal is logged as an intent and a result, and none is left open");

    const AuthResponse second = a.ask(Action::Withdraw, uah(200));
    check(second.command && second.command->sequence == 2 && a.lastSeq() == 2, "the next withdrawal gets the next sequence");
    check(a.balance() == uah(50000) - uah(700), "and the balance follows");
}

void pinTests()
{
    section("Authorization: PIN attempts");

    AuthRig a;
    const AuthResponse wrong = a.ask(Action::Withdraw, uah(500), "0000");
    check(wrong.status == AuthStatus::WrongPin && !wrong.command, "a wrong PIN is refused without a command");
    check(a.attempts() == 1 && a.balance() == uah(50000) && a.lastSeq() == 0, "it is counted and nothing moves");
    check(a.logged("op=pin_failure") == 1 && a.logged("reason=wrong_pin attempts=1") == 1 && a.openIntents() == 0, "the count is logged as an intent and a result, and none is left open");

    check(a.ask(Action::Withdraw, uah(500)).status == AuthStatus::Approved, "the right PIN works afterwards");
    check(a.attempts() == 0, "and resets the counter");
    check(a.logged("op=pin_reset") == 1 && a.logged("status=Reset attempts=0") == 1 && a.openIntents() == 0, "the reset is logged as an intent and a result too");

    check(a.ask(Action::CheckBalance, 0, "1111").status == AuthStatus::WrongPin, "a wrong PIN on a balance request counts too");
    check(a.ask(Action::Withdraw, uah(500), "2222").status == AuthStatus::WrongPin, "second failure");
    const AuthResponse third = a.ask(Action::Withdraw, uah(500), "3333");
    check(third.status == AuthStatus::CardBlocked && !third.command, "the third failure blocks the card");
    check(a.cards.find(kPan)->blocked && a.attempts() == 3, "the block is stored");

    const std::int64_t before = a.balance();
    const AuthResponse afterBlock = a.ask(Action::Withdraw, uah(500));
    check(afterBlock.status == AuthStatus::CardBlocked && !afterBlock.command && a.balance() == before, "even the right PIN gets nothing from a blocked card");
    check(a.attempts() == 3, "a blocked card is not checked again");
}

void limitTests()
{
    section("Authorization: limits and funds");

    AuthRig a;
    check(a.ask(Action::Withdraw, uah(10100)).status == AuthStatus::LimitExceeded, "more than the per-withdrawal limit is refused");
    check(a.ask(Action::Withdraw, uah(150)).status == AuthStatus::LimitExceeded, "an amount that is not a multiple of the step is refused");
    check(a.balance() == uah(50000) && a.lastSeq() == 0 && !a.txs.find(kRigAtm, 1), "refusals leave no trace in the money tables");
    check(a.attempts() == 0, "and a right PIN is not punished");

    check(a.ask(Action::Withdraw, uah(10000)).status == AuthStatus::Approved, "the per-withdrawal limit itself is allowed");
    check(a.ask(Action::Withdraw, uah(10000)).status == AuthStatus::Approved, "a second one reaches the daily limit");
    check(a.ask(Action::Withdraw, uah(100)).status == AuthStatus::LimitExceeded, "nothing more fits into the daily limit");
    a.r.clock.advance(24 * 60 * 60 + 1);
    const AuthResponse nextDay = a.ask(Action::Withdraw, uah(100));
    check(nextDay.status == AuthStatus::Approved && nextDay.command && nextDay.command->sequence == 3, "a day later the limit has room again");

    a.addCard("5432109876543210", "ACC-2", uah(300), 12, 2030, "4321");
    const AuthResponse poor = a.ask(Action::Withdraw, uah(500), "4321", "5432109876543210");
    check(poor.status == AuthStatus::InsufficientFunds && !poor.command && a.balance("ACC-2") == uah(300), "more than the balance is refused");
    const AuthResponse exact = a.ask(Action::Withdraw, uah(300), "4321", "5432109876543210");
    check(exact.status == AuthStatus::Approved && a.balance("ACC-2") == 0, "the whole balance can be withdrawn");

    AuthRig reversed;
    check(reversed.ask(Action::Withdraw, uah(10000)).status == AuthStatus::Approved, "setup: a withdrawal");
    {
        Statement s(reversed.r.db, "UPDATE transactions SET status = 'REVERSED' WHERE dispense_seq = 1");
        s.run();
    }
    check(reversed.ask(Action::Withdraw, uah(10000)).status == AuthStatus::Approved && reversed.ask(Action::Withdraw, uah(10000)).status == AuthStatus::Approved,
        "a reversed withdrawal does not count against the daily limit");
}

void refusalTests()
{
    section("Authorization: cards and requests that are refused outright");

    AuthRig a;
    a.addCard("5432100000000001", "ACC-3", uah(5000), 1, 2020, "1234");
    const AuthResponse expired = a.ask(Action::Withdraw, uah(500), "1234", "5432100000000001");
    check(expired.status == AuthStatus::Declined && !expired.command, "an expired card is declined by the server too");
    check(a.attempts("5432100000000001") == 0 && a.balance("ACC-3") == uah(5000), "without counting a PIN attempt or moving money");

    check(a.ask(Action::Withdraw, uah(500), "1234", "5432100000009999").status == AuthStatus::Declined, "an unknown card is declined");
    check(a.ask(Action::LoadCash, 0).status == AuthStatus::Declined, "an action that is not a customer action is declined");
    check(a.ask(Action::CheckBalance, uah(100)).status == AuthStatus::Declined, "a balance request cannot carry an amount");
    check(a.ask(Action::Withdraw, 0).status == AuthStatus::Declined, "a withdrawal of nothing is declined");
    check(a.attempts() == 0 && a.balance() == uah(50000), "none of this touches the real card");
    check(a.logged("reason=card_expired") == 1 && a.logged("reason=unknown_card") == 1, "each refusal is logged with its reason");

    check(a.server.endSession(a.r.header(ApiCall::EndSession, ApiBody::endSession("S-1")), "S-1"), "ending a session of a known ATM is acknowledged");
}

void attackTests()
{
    section("Authorization: replay and other ATMs");

    AuthRig a;
    const AuthRequest captured = a.request(Action::Withdraw, uah(500));
    check(a.server.authorize(captured).status == AuthStatus::Approved, "setup: the withdrawal goes through once");
    const AuthResponse replay = a.server.authorize(captured);
    check(replay.status != AuthStatus::Approved && !replay.command && replay.signature.empty(), "the same request sent again is not approved");
    check(a.balance() == uah(50000) - uah(500) && a.lastSeq() == 1, "so the money moves only once");

    const AtmKeySet keys2{ "2222222222222221", "2222222222222222", "2222222222222223", "2222222222222224" };
    check(a.r.fx.bank->provisionAtm("ATM-002", keys2), "setup: a second ATM with its own keys");
    a.r.atms.insert("ATM-002");
    AtmHsm atm2(a.r.fx.signPub, a.r.fx.boxPub);
    check(bringUp(atm2, keys2), "setup: its HSM is operational");
    PinModule pin2(atm2);

    const AuthRequest fromTwo = *pin2.processPin(Card(kPan, 12, 2030), kPin, Action::Withdraw, uah(500), "S-9", "ATM-002", a.r.clock.nowUnix());
    const AuthResponse ok = a.server.authorize(fromTwo);
    check(ok.status == AuthStatus::Approved && ok.command && ok.command->atmId == "ATM-002" && ok.command->sequence == 1, "the second ATM works and counts its own sequence");
    check(a.lastSeq("ATM-002") == 1 && a.lastSeq() == 1, "each ATM keeps its own sequence");
    check(ok.command && atm2.verifyServer(SignDomain::Dispense, ok.command->signedPayload(), ok.command->signature), "its command verifies on its own HSM");

    const AuthRequest passingOff = *pin2.processPin(Card(kPan, 12, 2030), kPin, Action::Withdraw, uah(500), "S-10", kRigAtm, a.r.clock.nowUnix());
    const std::int64_t before = a.balance();
    const AuthResponse refused = a.server.authorize(passingOff);
    check(refused.status != AuthStatus::Approved && !refused.command && a.balance() == before, "a request MACed by one ATM but naming another is refused at the gate");
    check(a.service.authorize(passingOff).status == AuthStatus::WrongPin, "and a PIN sealed under another ATM's key does not verify even without the gate");
}

void failClosedTests()
{
    section("Authorization: log failures and races");

    {
        AuthRig a;
        a.sink.failIntents = true;
        const AuthResponse blocked = a.ask(Action::Withdraw, uah(500));
        check(blocked.status == AuthStatus::Error && !blocked.command, "a withdrawal whose intent cannot be logged is refused");
        check(a.balance() == uah(50000) && a.lastSeq() == 0 && !a.txs.find(kRigAtm, 1), "no money moves and no sequence is used");
        a.sink.failIntents = false;
        const AuthResponse retry = a.ask(Action::Withdraw, uah(500));
        check(retry.command && retry.command->sequence == 1, "with the log back, the first sequence is still free");
    }
    {
        AuthRig a;
        a.sink.failAll = true;
        check(a.ask(Action::Withdraw, uah(500), "0000").status == AuthStatus::Error && a.attempts() == 0, "with the log down a wrong PIN is not counted and gets no verdict");
        check(a.ask(Action::Withdraw, uah(500)).status == AuthStatus::Error && a.balance() == uah(50000), "and the right PIN gets nothing, so the answer does not tell them apart");
        check(a.ask(Action::CheckBalance, 0).status == AuthStatus::Error, "not even a balance is shown");
    }
    {
        AuthRig a;
        check(a.ask(Action::CheckBalance, 0, "0000").status == AuthStatus::WrongPin && a.attempts() == 1, "setup: one failed attempt");
        a.sink.failIntents = true;
        check(a.ask(Action::Withdraw, uah(500)).status == AuthStatus::Error && a.attempts() == 1 && a.balance() == uah(50000), "if the reset cannot be logged the counter stays and nothing is paid");
        check(a.ask(Action::Withdraw, uah(500), "0000").status == AuthStatus::Error && a.attempts() == 1, "and a failure that cannot be logged is not counted");
        a.sink.failIntents = false;
        check(a.ask(Action::Withdraw, uah(500)).status == AuthStatus::Approved && a.attempts() == 0, "with the log back everything works");
    }
    {
        AuthRig a;
        Statement guard(a.r.db, "CREATE TRIGGER no_pin_count BEFORE UPDATE OF failed_pin_attempts ON cards BEGIN SELECT RAISE(ABORT, 'locked'); END");
        guard.run();
        check(a.ask(Action::Withdraw, uah(500), "0000").status == AuthStatus::Error && a.attempts() == 0, "a failed PIN count that the database refuses gives an error");
        check(a.logged("reason=storage_failure") == 1 && a.openIntents() == 0, "and its intent is closed as a failure");
    }
    {
        AuthRig a;
        Statement conflict(a.r.db, "CREATE TRIGGER no_hold BEFORE INSERT ON transactions BEGIN SELECT RAISE(ABORT, 'locked'); END");
        conflict.run();
        const AuthResponse failed = a.ask(Action::Withdraw, uah(500));
        check(failed.status == AuthStatus::Error && !failed.command, "a reservation the database refuses gives an error");
        check(a.balance() == uah(50000) && a.lastSeq() == 0, "the debit and the sequence are rolled back");
        check(a.logged("reason=storage_failure") == 1 && a.openIntents() == 0, "and the intent is closed as a failure");
    }
    {
        AuthRig a;
        a.sink.onRecord = [&](const LogEvent& e)
        {
            if (e.outcome != Outcome::Info || e.opId.empty()) return;
            a.sink.onRecord = nullptr;
            check(a.takeSequence(0), "setup: another request takes the sequence while this one is logged");
        };
        const AuthResponse raced = a.ask(Action::Withdraw, uah(500));
        check(raced.status == AuthStatus::Error && !raced.command && a.balance() == uah(50000) && !a.txs.find(kRigAtm, 1), "a sequence taken in between stops the reservation");
        check(a.openIntents() == 0 && a.logged("reason=state_changed") == 1, "the intent is closed as a failure with its reason");
    }
    {
        AuthRig a;
        a.sink.onRecord = [&](const LogEvent& e)
        {
            if (e.outcome != Outcome::Info || e.opId.empty()) return;
            a.sink.onRecord = nullptr;
            check(a.accounts.debit("ACC-1", uah(50000) - uah(100)), "setup: the balance is spent while this request is logged");
        };
        const AuthResponse drained = a.ask(Action::Withdraw, uah(500));
        check(drained.status == AuthStatus::InsufficientFunds && !drained.command && a.balance() == uah(100) && a.lastSeq() == 0, "the balance is checked again when the money is taken");
        check(a.openIntents() == 0, "and the intent is closed");
    }
    {
        AuthRig a;
        a.sink.onRecord = [&](const LogEvent& e)
        {
            if (e.outcome != Outcome::Info || e.opId.empty()) return;
            a.sink.onRecord = nullptr;
            (void)a.cards.recordFailedPin(kPan, 1);
        };
        const AuthResponse blockedMeanwhile = a.ask(Action::Withdraw, uah(500));
        check(blockedMeanwhile.status == AuthStatus::CardBlocked && !blockedMeanwhile.command && a.balance() == uah(50000), "a card blocked in between gets no money");
    }
}

void recoveryTests()
{
    section("Authorization: recovery after a crash");

    AuthRig a;
    check(a.ask(Action::Withdraw, uah(500)).status == AuthStatus::Approved, "setup: one real reservation with sequence 1");

    LogEvent committed;
    committed.type = EventType::AUTH_DECISION;
    committed.outcome = Outcome::Info;
    committed.actorId = kRigAtm;
    committed.details = "action=Withdraw status=Reserving seq=1";
    committed.opId = "auth/ATM-001/1";
    LogEvent absent = committed;
    absent.details = "action=Withdraw status=Reserving seq=7";
    absent.opId = "auth/ATM-001/7";
    LogEvent pinOp = committed;
    pinOp.details = "action=Withdraw op=pin_failure";
    pinOp.opId = "pin/ATM-001/1700000000-1";
    check(a.r.log.record(committed) && a.r.log.record(absent) && a.r.log.record(pinOp), "setup: three intents whose results were lost in a crash");

    const LogVerifier verifier(a.r.logStorage, a.r.logSigner);
    check(verifier.openIntents().size() == 3, "all are open");
    IntentRecovery recovery(verifier, a.r.log);
    const RecoveryReport report = recovery.run({ &a.service });
    check(report.open == 3 && report.resolved == 3 && report.unowned == 0 && report.failed == 0, "the service owns and resolves all of them");
    check(a.logged("recovered=committed") == 1 && a.logged("recovered=absent") == 1, "a stored reservation is closed as committed, a missing one as absent");
    check(a.logged("recovered=unverified") == 1, "a lost PIN count is closed as unverified, not guessed");
    check(verifier.openIntents().empty() && verifier.verifyChain().ok, "no intent stays open and the log is intact");
}
}

int main()
{
    gabella_test::banner("Authorization service test suite");
    if (!CryptoCore::init())
    {
        std::cerr << "fatal: libsodium initialization failed\n";
        return 1;
    }

    balanceAndWithdrawalTests();
    pinTests();
    limitTests();
    refusalTests();
    attackTests();
    failClosedTests();
    recoveryTests();

    return gabella_test::summary();
}
