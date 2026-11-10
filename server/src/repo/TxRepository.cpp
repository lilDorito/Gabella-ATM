#include "server/repo/TxRepository.h"

#include "server/db/DbError.h"
#include "server/db/Statement.h"

namespace
{
const char* kColumns = "tx_id, atm_id, session_id, account_id, amount_kop, dispense_seq, status, created_at, resolved_at, resolved_by, reason";

TxRecord read(const Statement& s)
{
    TxRecord r;
    r.id = s.columnInt64(0);
    r.atmId = s.columnText(1);
    r.sessionId = s.columnText(2);
    r.accountId = s.columnText(3);
    r.amountKop = s.columnInt64(4);
    r.dispenseSeq = static_cast<std::uint64_t>(s.columnInt64(5));
    r.status = txStatusFromString(s.columnText(6)).value_or(TxStatus::Held);
    r.createdAt = s.columnInt64(7);
    if (!s.columnIsNull(8)) r.resolvedAt = s.columnInt64(8);
    r.resolvedBy = s.columnText(9);
    r.reason = s.columnText(10);
    return r;
}

std::vector<TxRecord> readAll(Statement& s)
{
    std::vector<TxRecord> out;
    while (s.step()) out.push_back(read(s));
    return out;
}
}

const char* txStatusToString(TxStatus status)
{
    switch (status)
    {
    case TxStatus::Held: return "HELD";
    case TxStatus::Uncertain: return "UNCERTAIN";
    case TxStatus::Committed: return "COMMITTED";
    case TxStatus::Reversed: return "REVERSED";
    }
    return "";
}

std::optional<TxStatus> txStatusFromString(const std::string& text)
{
    if (text == "HELD") return TxStatus::Held;
    if (text == "UNCERTAIN") return TxStatus::Uncertain;
    if (text == "COMMITTED") return TxStatus::Committed;
    if (text == "REVERSED") return TxStatus::Reversed;
    return std::nullopt;
}

std::int64_t TxRepository::insertHeld(const std::string& atmId, const std::string& sessionId, const std::string& accountId, std::int64_t amountKop, std::uint64_t dispenseSeq, std::int64_t createdAt)
{
    Statement s(_db, "INSERT INTO transactions (atm_id, session_id, account_id, amount_kop, dispense_seq, status, created_at) VALUES (?, ?, ?, ?, ?, 'HELD', ?)");
    s.bind(1, atmId).bind(2, sessionId).bind(3, accountId).bind(4, amountKop).bind(5, static_cast<std::int64_t>(dispenseSeq)).bind(6, createdAt).run();
    return _db.lastInsertRowId();
}

std::optional<TxRecord> TxRepository::findById(std::int64_t id) const
{
    Statement s(_db, (std::string("SELECT ") + kColumns + " FROM transactions WHERE tx_id = ?").c_str());
    s.bind(1, id);
    if (!s.step()) return std::nullopt;
    return read(s);
}

std::optional<TxRecord> TxRepository::findBySeq(const std::string& atmId, std::uint64_t dispenseSeq) const
{
    Statement s(_db, (std::string("SELECT ") + kColumns + " FROM transactions WHERE atm_id = ? AND dispense_seq = ?").c_str());
    s.bind(1, atmId).bind(2, static_cast<std::int64_t>(dispenseSeq));
    if (!s.step()) return std::nullopt;
    return read(s);
}

std::vector<TxRecord> TxRepository::findOpenByAtm(const std::string& atmId) const
{
    Statement s(_db, (std::string("SELECT ") + kColumns + " FROM transactions WHERE atm_id = ? AND status IN ('HELD', 'UNCERTAIN') ORDER BY dispense_seq").c_str());
    s.bind(1, atmId);
    return readAll(s);
}

std::vector<TxRecord> TxRepository::findHeldOlderThan(std::int64_t cutoff) const
{
    Statement s(_db, (std::string("SELECT ") + kColumns + " FROM transactions WHERE status = 'HELD' AND created_at <= ? ORDER BY tx_id").c_str());
    s.bind(1, cutoff);
    return readAll(s);
}

std::vector<TxRecord> TxRepository::findUncertainOlderThan(std::int64_t cutoff) const
{
    Statement s(_db, (std::string("SELECT ") + kColumns + " FROM transactions WHERE status = 'UNCERTAIN' AND created_at <= ? ORDER BY tx_id").c_str());
    s.bind(1, cutoff);
    return readAll(s);
}

bool TxRepository::setStatus(std::int64_t id, TxStatus to, std::int64_t now, const std::string& by, const std::string& reason)
{
    if (to == TxStatus::Held) return false;

    if (to == TxStatus::Uncertain)
    {
        Statement s(_db, "UPDATE transactions SET status = 'UNCERTAIN', resolved_by = ?, reason = ? WHERE tx_id = ? AND status = 'HELD'");
        s.bind(1, by).bind(2, reason).bind(3, id).run();
        return _db.changes() == 1;
    }

    Statement s(_db, "UPDATE transactions SET status = ?, resolved_at = ?, resolved_by = ?, reason = ? WHERE tx_id = ? AND status IN ('HELD', 'UNCERTAIN')");
    s.bind(1, std::string(txStatusToString(to))).bind(2, now).bind(3, by).bind(4, reason).bind(5, id).run();
    return _db.changes() == 1;
}

std::int64_t TxRepository::reservedTotal(const std::string& accountId) const
{
    Statement s(_db, "SELECT COALESCE(SUM(amount_kop), 0) FROM transactions WHERE account_id = ? AND status IN ('HELD', 'UNCERTAIN')");
    s.bind(1, accountId);
    return s.step() ? s.columnInt64(0) : 0;
}

std::int64_t TxRepository::dailyTotal(const std::string& accountId, std::int64_t since) const
{
    Statement s(_db, "SELECT COALESCE(SUM(amount_kop), 0) FROM transactions WHERE account_id = ? AND status != 'REVERSED' AND created_at >= ?");
    s.bind(1, accountId).bind(2, since);
    return s.step() ? s.columnInt64(0) : 0;
}
