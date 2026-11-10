#include "server/repo/TransactionRepository.h"

#include "server/db/Statement.h"

std::int64_t TransactionRepository::insertHeld(const std::string& atmId, const std::string& sessionId, const std::string& accountId, std::int64_t amountKop, std::uint64_t dispenseSeq, std::int64_t createdAt)
{
    Statement s(_db, "INSERT INTO transactions (atm_id, session_id, account_id, amount_kop, dispense_seq, status, created_at) VALUES (?, ?, ?, ?, ?, 'HELD', ?)");
    s.bind(1, atmId).bind(2, sessionId).bind(3, accountId).bind(4, amountKop).bind(5, static_cast<std::int64_t>(dispenseSeq)).bind(6, createdAt).run();
    return _db.lastInsertRowId();
}

std::optional<TransactionRecord> TransactionRepository::find(const std::string& atmId, std::uint64_t dispenseSeq) const
{
    Statement s(_db, "SELECT tx_id, atm_id, session_id, account_id, amount_kop, dispense_seq, status, created_at FROM transactions WHERE atm_id = ? AND dispense_seq = ?");
    s.bind(1, atmId).bind(2, static_cast<std::int64_t>(dispenseSeq));
    if (!s.step()) return std::nullopt;

    TransactionRecord t;
    t.txId = s.columnInt64(0);
    t.atmId = s.columnText(1);
    t.sessionId = s.columnText(2);
    t.accountId = s.columnText(3);
    t.amountKop = s.columnInt64(4);
    t.dispenseSeq = static_cast<std::uint64_t>(s.columnInt64(5));
    t.status = s.columnText(6);
    t.createdAt = s.columnInt64(7);
    return t;
}

std::int64_t TransactionRepository::withdrawnSince(const std::string& accountId, std::int64_t since) const
{
    Statement s(_db, "SELECT COALESCE(SUM(amount_kop), 0) FROM transactions WHERE account_id = ? AND created_at >= ? AND status <> 'REVERSED'");
    s.bind(1, accountId).bind(2, since);
    if (!s.step()) return 0;
    return s.columnInt64(0);
}
