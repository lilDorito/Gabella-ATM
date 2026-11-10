#include <iostream>
#include <string>

#include "Check.h"
#include "DemoData.h"
#include "ServerRig.h"
#include "common/Card.h"
#include "crypto/PinModule.h"
#include "server/db/DbError.h"
#include "server/db/Statement.h"
#include "server/repo/AccountRepository.h"
#include "server/repo/CardRepository.h"
#include "server/repo/TransactionRepository.h"
#include "server/services/AuthorizationService.h"

using gabella_test::check;
using gabella_test::section;

namespace
{
std::int64_t count(Database& db, const std::string& table)
{
    const std::string sql = "SELECT count(*) FROM " + table;
    Statement s(db, sql.c_str());
    return s.step() ? s.columnInt64(0) : -1;
}

void contentTests()
{
    section("seed_db: what gets written");

    ServerRig r;
    seedDatabase(r.db, *r.fx.bank);
    check(count(r.db, "accounts") == 5 && count(r.db, "cards") == 5 && count(r.db, "staff") == 6, "accounts, cards and staff are written");
    check(count(r.db, "atms") == 2 && count(r.db, "atm_cassettes") == 8, "both ATMs get four cassettes, and the ATM that already existed is kept");
    check(count(r.db, "transactions") == 0, "no transactions yet");

    bool luhn = true;
    for (const DemoCard& card : demoCards()) luhn = luhn && Card(card.pan, card.expMonth, card.expYear).isValidLuhn();
    check(luhn, "every demo card number passes the Luhn check the ATM applies");

    bool hashes = true;
    {
        Statement s(r.db, "SELECT password_hash FROM staff");
        while (s.step()) hashes = hashes && CryptoCore::verifyPassword(s.columnText(0), kDemoStaffPassword);
    }
    check(hashes, "every staff password is stored as an argon2id hash of the demo password");

    CardRepository cards(r.db);
    const auto blocked = cards.find(demoCards()[2].pan);
    const auto risky = cards.find(demoCards()[4].pan);
    check(blocked && blocked->blocked && risky && !risky->blocked && risky->failedPinAttempts == 2, "the blocked and almost-blocked cards are in those states");

    check(std::string(kDemoPinKey) == HsmFixture::kPinKey, "the seed tool's default PIN key is the one the app and tests use");

    const std::int64_t accountsBefore = count(r.db, "accounts");
    bool refused = false;
    try
    {
        seedDatabase(r.db, *r.fx.bank);
    }
    catch (const DbError&)
    {
        refused = true;
    }
    check(refused && count(r.db, "accounts") == accountsBefore && count(r.db, "staff") == 6, "seeding twice fails and leaves the data as it was");
}

void usableTests()
{
    section("seed_db: the data works end to end");

    ServerRig r;
    seedDatabase(r.db, *r.fx.bank);
    CardRepository cards(r.db);
    AccountRepository accounts(r.db);
    TransactionRepository txs(r.db);
    AuthorizationService service(*r.fx.bank, r.db, r.atms, cards, accounts, txs, r.log, r.clock, r.config);
    BankServer server(*r.fx.bank, r.log, r.gate, r.atms, r.checkpointService, ServerParts{ service, r.unavailable, r.unavailable, r.unavailable, r.unavailable });
    PinModule pinModule(*r.fx.atm);

    auto ask = [&](const DemoCard& card, const std::string& pin, Action action, std::int64_t amount)
    {
        return server.authorize(*pinModule.processPin(Card(card.pan, card.expMonth, card.expYear), pin, action, amount, "S-1", kRigAtm, r.clock.nowUnix()));
    };

    const auto& all = demoCards();
    const AuthResponse rich = ask(all[0], all[0].pin, Action::Withdraw, 50000);
    check(rich.status == AuthStatus::Approved && rich.command, "the normal card withdraws with its PIN");
    check(ask(all[0], all[0].pin, Action::CheckBalance, 0).balance->kop() == all[0].balanceKop - 50000, "and its balance shows the withdrawal");
    check(ask(all[1], all[1].pin, Action::Withdraw, 50000).status == AuthStatus::InsufficientFunds, "the low-balance card runs out of money");
    check(ask(all[2], all[2].pin, Action::Withdraw, 10000).status == AuthStatus::CardBlocked, "the blocked card is blocked");
    check(ask(all[3], all[3].pin, Action::Withdraw, 10000).status == AuthStatus::Declined, "the expired card is declined");
    check(ask(all[4], "0000", Action::Withdraw, 10000).status == AuthStatus::CardBlocked, "one more wrong PIN blocks the almost-blocked card");
}
}

int main()
{
    gabella_test::banner("Seed data test suite");
    if (!CryptoCore::init())
    {
        std::cerr << "fatal: libsodium initialization failed\n";
        return 1;
    }

    contentTests();
    usableTests();

    return gabella_test::summary();
}
