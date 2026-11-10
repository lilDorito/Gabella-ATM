#include "DemoData.h"

#include <stdexcept>

#include "crypto/CryptoCore.h"
#include "server/db/Statement.h"
#include "server/db/Transaction.h"
#include "server/repo/AccountRepository.h"
#include "server/repo/AtmRepository.h"
#include "server/repo/CardRepository.h"

namespace
{
constexpr std::int64_t uah(std::int64_t n) { return n * 100; }

char luhnCheckDigit(const std::string& body)
{
    int sum = 0;
    bool doubled = true;
    for (auto it = body.rbegin(); it != body.rend(); ++it)
    {
        int digit = *it - '0';
        if (doubled)
        {
            digit *= 2;
            if (digit > 9) digit -= 9;
        }
        sum += digit;
        doubled = !doubled;
    }
    return static_cast<char>('0' + (10 - sum % 10) % 10);
}

std::string demoPan(int number)
{
    std::string body = "54321000000000" + std::to_string(number);
    return body + luhnCheckDigit(body);
}

std::vector<DemoCard> buildCards()
{
    std::vector<DemoCard> cards;
    cards.push_back({ demoPan(1), "1234", "ACC-0001", "Olena Tester", uah(100000), 12, 2030, 0, false, "normal card with a large balance" });
    cards.push_back({ demoPan(2), "4321", "ACC-0002", "Taras Tester", uah(300), 12, 2030, 0, false, "low balance, for insufficient funds" });
    cards.push_back({ demoPan(3), "1111", "ACC-0003", "Iryna Tester", uah(5000), 12, 2030, 3, true, "blocked card" });
    cards.push_back({ demoPan(4), "2222", "ACC-0004", "Maksym Tester", uah(5000), 1, 2020, 0, false, "expired card" });
    cards.push_back({ demoPan(5), "3333", "ACC-0005", "Sofiia Tester", uah(5000), 12, 2030, 2, false, "one wrong PIN away from being blocked" });
    return cards;
}

void insertStaff(Database& db, const DemoStaff& staff, const std::string& hash)
{
    Statement s(db, "INSERT INTO staff (staff_id, role, password_hash, status) VALUES (?, ?, ?, 'ACTIVE')");
    s.bind(1, staff.id).bind(2, std::string(roleToString(staff.role))).bind(3, hash).run();
}

void setCassette(Database& db, const std::string& atmId, int denomination, int count)
{
    Statement s(db, "INSERT OR REPLACE INTO atm_cassettes (atm_id, denomination, expected_count) VALUES (?, ?, ?)");
    s.bind(1, atmId).bind(2, static_cast<std::int64_t>(denomination)).bind(3, static_cast<std::int64_t>(count)).run();
}
}

const std::vector<DemoCard>& demoCards()
{
    static const std::vector<DemoCard> cards = buildCards();
    return cards;
}

const std::vector<DemoStaff>& demoStaff()
{
    static const std::vector<DemoStaff> staff = {
        { "E-01", Role::ServiceEngineer },
        { "C-01", Role::CashCollector },
        { "AU-01", Role::Auditor },
        { "A-01", Role::Admin },
        { "A-02", Role::Admin },
        { "A-03", Role::Admin },
    };
    return staff;
}

const std::vector<std::string>& demoAtms()
{
    static const std::vector<std::string> atms = { "ATM-001", "ATM-002" };
    return atms;
}

const std::map<int, int>& demoCassettes()
{
    static const std::map<int, int> cassettes = { { 100, 50 }, { 200, 50 }, { 500, 50 }, { 1000, 50 } };
    return cassettes;
}

void seedDatabase(Database& db, const BankHsm& hsm)
{
    std::vector<std::string> pinVerifyValues;
    for (const DemoCard& card : demoCards())
    {
        auto value = hsm.computePinVerifyValue(card.pan, card.pin);
        if (!value) throw std::runtime_error("cannot compute a PIN verify value");
        pinVerifyValues.push_back(std::move(*value));
    }

    std::vector<std::string> passwordHashes;
    for (std::size_t i = 0; i < demoStaff().size(); ++i)
    {
        auto hash = CryptoCore::hashPassword(kDemoStaffPassword);
        if (!hash) throw std::runtime_error("cannot hash a staff password");
        passwordHashes.push_back(std::move(*hash));
    }

    AccountRepository accounts(db);
    CardRepository cards(db);
    AtmRepository atms(db);

    Transaction tx(db);
    for (std::size_t i = 0; i < demoCards().size(); ++i)
    {
        const DemoCard& card = demoCards()[i];
        accounts.insert(AccountRecord{ card.accountId, card.owner, card.balanceKop });

        CardRecord record;
        record.pan = card.pan;
        record.accountId = card.accountId;
        record.expMonth = card.expMonth;
        record.expYear = card.expYear;
        record.pinVerifyValue = pinVerifyValues[i];
        record.failedPinAttempts = card.failedPinAttempts;
        record.blocked = card.blocked;
        cards.insert(record);
    }

    for (std::size_t i = 0; i < demoStaff().size(); ++i) insertStaff(db, demoStaff()[i], passwordHashes[i]);

    for (const std::string& atmId : demoAtms())
    {
        if (!atms.find(atmId)) atms.insert(atmId);
        for (const auto& [denomination, count] : demoCassettes()) setCassette(db, atmId, denomination, count);
    }
    tx.commit();
}
