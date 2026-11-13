#include <cstdint>
#include <iostream>
#include <string>

#include "Check.h"
#include "ReconRig.h"
#include "common/Card.h"
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
    AuthorizationService authorization{ *fx.bank, db, atms, cards, accounts, txs, log, clock, config };
    BankServer bank{ *fx.bank, log, gate, atms, checkpointService, ServerParts{ authorization, recon, unavailable, decider, unavailable } };
    PinModule pinModule{ *fx.atm };
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
    check(r.withdraw(uah(500)).status == AuthStatus::Approved, "500 of 700 UAH is approved");
    check(r.withdraw(uah(500)).status == AuthStatus::InsufficientFunds, "another 500 is refused while the first is reserved");
    check(r.withdraw(uah(200)).status == AuthStatus::Approved, "the remaining 200 can still be taken");
    check(r.available() == 0, "nothing is left to spend");

    FlowRig rich;
    Statement richer(rich.db, "UPDATE accounts SET balance_kop = 10000000 WHERE account_id = 'ACC-1'");
    richer.run();
    check(rich.withdraw(rich.config.maxWithdrawalKop).status == AuthStatus::Approved, "a full withdrawal is approved");
    check(rich.withdraw(rich.config.maxWithdrawalKop).status == AuthStatus::Approved, "a second one reaches the daily limit");
    check(rich.withdraw(uah(100)).status == AuthStatus::LimitExceeded, "held withdrawals count toward the daily limit");
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

    return gabella_test::summary();
}
