#include "server/repo/AccountRepository.h"

#include "server/db/Statement.h"

void AccountRepository::insert(const AccountRecord& account)
{
    Statement s(_db, "INSERT INTO accounts (account_id, owner_name, balance_kop) VALUES (?, ?, ?)");
    s.bind(1, account.accountId).bind(2, account.ownerName).bind(3, account.balanceKop).run();
}

std::optional<AccountRecord> AccountRepository::find(const std::string& accountId) const
{
    Statement s(_db, "SELECT account_id, owner_name, balance_kop FROM accounts WHERE account_id = ?");
    s.bind(1, accountId);
    if (!s.step()) return std::nullopt;

    AccountRecord account;
    account.accountId = s.columnText(0);
    account.ownerName = s.columnText(1);
    account.balanceKop = s.columnInt64(2);
    return account;
}

bool AccountRepository::debit(const std::string& accountId, std::int64_t amountKop)
{
    if (amountKop <= 0) return false;
    Statement s(_db, "UPDATE accounts SET balance_kop = balance_kop - ? WHERE account_id = ? AND balance_kop >= ?");
    s.bind(1, amountKop).bind(2, accountId).bind(3, amountKop).run();
    return _db.changes() == 1;
}
