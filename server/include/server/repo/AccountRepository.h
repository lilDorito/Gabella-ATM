#include "server/repo/AccountRepository.h"

#include "server/db/Statement.h"

std::optional<std::int64_t> AccountRepository::balance(const std::string& accountId) const
{
    Statement s(_db, "SELECT balance_kop FROM accounts WHERE account_id = ?");
    s.bind(1, accountId);
    if (!s.step()) return std::nullopt;
    return s.columnInt64(0);
}

bool AccountRepository::debit(const std::string& accountId, std::int64_t amountKop)
{
    if (amountKop <= 0) return false;

    Statement s(_db, "UPDATE accounts SET balance_kop = balance_kop - ? WHERE account_id = ? AND balance_kop >= ?");
    s.bind(1, amountKop).bind(2, accountId).bind(3, amountKop).run();
    return _db.changes() == 1;
}
