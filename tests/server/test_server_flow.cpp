#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <string>

#include "Check.h"
#include "ReconRig.h"
#include "common/Card.h"
#include "crypto/KeyWrap.h"
#include "crypto/PinModule.h"
#include "server/repo/CardRepository.h"
#include "server/services/AuthorizationService.h"

using gabella_test::check;
using gabella_test::section;

namespace
{
constexpr std::int64_t uah(std::int64_t n) { return n * 100; }

const std::string kPan = "5432101234567890";
const std::string kPin = "1234";

struct FlowRig : ReconRig
{
    CardRepository cards{ db };
    SessionRegistry clientSessions{ clock };
    AuthorizationService authorization{ *fx.bank, db, atms, cards, accounts, txs, clientSessions, log, clock, config };
    BankServer bank{ *fx.bank, log, gate, atms, checkpointService, ServerParts{ authorization, recon, unavailable, decider, unavailable } };
    PinModule pinModule{ *fx.atm };
    std::map<std::string, std::unique_ptr<AtmHsm>> extraHsms;
    std::map<std::string, std::unique_ptr<PinModule>> extraPins;
    int sessions = 0;

    FlowRig()
    {
        CardRecord card;
        card.pan = kPan;
        card.accountId = "ACC-1";
        card.expMonth = 12;
        card.expYear = 2030;
        card.pinVerifyValue = *fx.bank->computePinVerifyValue(kPan, kPin);
        cards.insert(card);
    }

    AuthResponse withdraw(std::int64_t amountKop)
    {
        const std::string session = "S-" + std::to_string(++sessions);
        return bank.authorize(*pinModule.processPin(Card(kPan, 12, 2030), kPin, Action::Withdraw, amountKop, session, kRigAtm, clock.nowUnix()));
    }

    bool addAtm(const std::string& atmId)
    {
        const std::string tag = atmId.substr(atmId.size() - 1);
        const AtmKeySet keys{ std::string(15, 'M') + tag, std::string(15, 'E') + tag, std::string(15, 'C') + tag, std::string(15, 'A') + tag };
        auto hsm = std::make_unique<AtmHsm>(fx.signPub, fx.boxPub);
        bool ok = fx.bank->provisionAtm(atmId, keys) && hsm->installMasterKey(keys.masterKey);
        ok = ok && hsm->updateWorkingKey(KeyType::Encryption, *wrapWorkingKey(keys.masterKey, KeyType::Encryption, keys.encKey));
        ok = ok && hsm->updateWorkingKey(KeyType::Mac, *wrapWorkingKey(keys.masterKey, KeyType::Mac, keys.macKey));
        ok = ok && hsm->updateWorkingKey(KeyType::Audit, *wrapWorkingKey(keys.masterKey, KeyType::Audit, keys.auditKey));
        if (!ok) return false;
        atms.insert(atmId);
        extraPins[atmId] = std::make_unique<PinModule>(*hsm);
        extraHsms[atmId] = std::move(hsm);
        return true;
    }

    AuthResponse withdrawAt(const std::string& atmId, std::int64_t amountKop)
    {
        const std::string session = "S-" + std::to_string(++sessions);
        return bank.authorize(*extraPins.at(atmId)->processPin(Card(kPan, 12, 2030), kPin, Action::Withdraw, amountKop, session, atmId, clock.nowUnix()));
    }

    std::int64_t balanceIn(const std::string& session)
    {
        const AuthResponse r = bank.authorize(*pinModule.processPin(Card(kPan, 12, 2030), kPin, Action::CheckBalance, 0, session, kRigAtm, clock.nowUnix()));
        return r.balance ? r.balance->kop() : -1;
    }

    std::int64_t available()
    {
        const AuthResponse r = bank.authorize(*pinModule.processPin(Card(kPan, 12, 2030), kPin, Action::CheckBalance, 0, "S-B" + std::to_string(++sessions), kRigAtm, clock.nowUnix()));
        return r.balance ? r.balance->kop() : -1;
    }

    bool report(const AuthResponse& approved, DispenseResult result, const Counts& cassetteCounts)
    {
        DispenseReport r = dispenseReport(approved.command->sequence, result, cassetteCounts);
        r.sessionId = approved.command->sessionId;
        return bank.reportDispense(header(ApiCall::ReportDispense, r.payload()), r);
    }

    bool reconnect(std::uint64_t lastSeq, const Counts& cassetteCounts)
    {
        const StatusReport r = statusReport(StatusReason::Reconnect, lastSeq, cassetteCounts);
        return bank.syncStatus(header(ApiCall::SyncStatus, r.payload()), r);
    }
};

void dispensedTests()
{
    section("A dispensed withdrawal is paid exactly once");

    FlowRig r;
    const AuthResponse approved = r.withdraw(uah(500));
    check(approved.status == AuthStatus::Approved && approved.command, "the withdrawal is approved");
    check(r.balance() == uah(10000) && r.available() == uah(9500), "approval reserves the money without taking it");
    check(r.status(1) == TxStatus::Held, "the transaction is held");

    check(r.report(approved, DispenseResult::Ok, counts(50, 50, 49, 50)), "the dispense report is accepted");
    check(r.status(1) == TxStatus::Committed, "the transaction is committed");
    check(r.balance() == uah(9500), "the account is debited once");
    check(r.available() == uah(9500), "and the reservation is gone, so nothing is counted twice");
    check(r.report(approved, DispenseResult::Ok, counts(50, 50, 49, 50)) && r.balance() == uah(9500), "a repeated report does not debit again");
}

void failedTests()
{
    section("A failed withdrawal costs nothing");

    FlowRig r;
    const AuthResponse approved = r.withdraw(uah(500));
    check(r.report(approved, DispenseResult::HardwareFault, kFull), "the failure report is accepted");
    check(r.status(1) == TxStatus::Reversed, "the transaction is reversed");
    check(r.balance() == uah(10000) && r.available() == uah(10000), "the full balance is available again");
}

void uncertainTests()
{
    section("A withdrawal with no report");

    FlowRig r;
    const AuthResponse approved = r.withdraw(uah(500));
    check(approved.status == AuthStatus::Approved, "the withdrawal is approved");
    r.clock.advance(r.config.uncertainAfterSeconds + 1);
    (void)r.recon.tick();
    check(r.status(1) == TxStatus::Uncertain, "without a report it becomes uncertain");
    check(r.balance() == uah(10000) && r.available() == uah(9500), "the money stays reserved while nobody knows");
    check(r.reconnect(1, kFull), "the ATM reconnects with unchanged cassettes");
    check(r.status(1) == TxStatus::Reversed && r.available() == uah(10000), "the reservation is released");

    FlowRig paid;
    const AuthResponse second = paid.withdraw(uah(500));
    check(second.status == AuthStatus::Approved, "another withdrawal is approved");
    paid.clock.advance(paid.config.uncertainAfterSeconds + 1);
    (void)paid.recon.tick();
    check(paid.reconnect(1, counts(50, 50, 49, 50)), "the ATM reconnects with one note fewer");
    check(paid.status(1) == TxStatus::Committed && paid.balance() == uah(9500) && paid.available() == uah(9500), "the money is debited once");
}

void reservationTests()
{
    section("Reservations count against the balance and the limit");

    FlowRig r;
    Statement poorer(r.db, "UPDATE accounts SET balance_kop = 70000 WHERE account_id = 'ACC-1'");
    poorer.run();
    const AuthResponse first = r.withdraw(uah(500));
    check(first.status == AuthStatus::Approved, "500 of 700 UAH is approved");
    check(r.addAtm("ATM-002"), "a second ATM joins");
    check(r.withdrawAt("ATM-002", uah(500)).status == AuthStatus::InsufficientFunds, "another 500 elsewhere is refused while the first is reserved");
    check(r.withdrawAt("ATM-002", uah(200)).status == AuthStatus::Approved, "the remaining 200 can still be taken");
    check(r.available() == 0, "nothing is left to spend");

    FlowRig rich;
    Statement richer(rich.db, "UPDATE accounts SET balance_kop = 10000000 WHERE account_id = 'ACC-1'");
    richer.run();
    check(rich.withdraw(rich.config.maxWithdrawalKop).status == AuthStatus::Approved, "a full withdrawal is approved");
    check(rich.addAtm("ATM-002") && rich.withdrawAt("ATM-002", rich.config.maxWithdrawalKop).status == AuthStatus::Approved, "a second one elsewhere reaches the daily limit");
    check(rich.addAtm("ATM-003") && rich.withdrawAt("ATM-003", uah(100)).status == AuthStatus::LimitExceeded, "held withdrawals count toward the daily limit");
}

void unsettledTests()
{
    section("An ATM settles one withdrawal before the next");

    FlowRig r;
    const AuthResponse first = r.withdraw(uah(500));
    check(first.status == AuthStatus::Approved, "the first withdrawal is approved");
    const AuthResponse early = r.withdraw(uah(200));
    check(early.status == AuthStatus::Declined && !early.command, "the next one waits until the first is settled");
    check(!r.txs.findBySeq(kRigAtm, 2), "and nothing is reserved for it");
    check(r.available() == uah(9500), "a balance check is still answered");
    check(r.report(first, DispenseResult::Ok, counts(50, 50, 49, 50)), "the first is reported");
    check(r.withdraw(uah(200)).status == AuthStatus::Approved, "then the next one goes through");

    FlowRig lost;
    const AuthResponse unreported = lost.withdraw(uah(500));
    lost.clock.advance(lost.config.uncertainAfterSeconds + 1);
    (void)lost.recon.tick();
    check(lost.status(1) == TxStatus::Uncertain && lost.withdraw(uah(200)).status == AuthStatus::Declined, "an uncertain withdrawal blocks the ATM too");
    check(unreported.status == AuthStatus::Approved && lost.reconnect(1, kFull) && lost.withdraw(uah(200)).status == AuthStatus::Approved, "until the ATM reconnects and its counters settle it");
}

void sessionTests()
{
    section("Client sessions");

    FlowRig r;
    const std::string session = "S-FIXED";
    check(r.balanceIn(session) == uah(10000), "a session is opened by its first approved request");
    check(r.clientSessions.isOpen(session), "the server knows it");
    check(r.bank.endSession(r.header(ApiCall::EndSession, ApiBody::endSession(session)), session), "the ATM ends it");
    check(!r.clientSessions.isOpen(session), "it is closed");
    check(r.balanceIn(session) == -1, "a request in a closed session is refused");
    check(r.balanceIn("S-NEW") == uah(10000), "a new session works");
    r.clock.advance(r.config.clientSessionSeconds + 1);
    check(!r.clientSessions.isOpen("S-NEW"), "an idle session expires");
}
}

int main()
{
    gabella_test::banner("Server money flow test suite");
    if (!CryptoCore::init())
    {
        std::cerr << "fatal: libsodium initialization failed\n";
        return 1;
    }

    dispensedTests();
    failedTests();
    uncertainTests();
    reservationTests();
    unsettledTests();
    sessionTests();

    return gabella_test::summary();
}
