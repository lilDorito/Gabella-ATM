#include "server/repo/CheckpointRepository.h"

#include "common/Hex.h"
#include "server/db/DbError.h"
#include "server/db/Statement.h"

namespace
{
Checkpoint readRow(const Statement& s)
{
    Checkpoint cp;
    cp.logId = s.columnText(0);
    cp.seqNo = static_cast<std::uint64_t>(s.columnInt64(1));
    cp.hash = s.columnText(2);
    cp.timestamp = s.columnInt64(3);
    auto mac = fromHex(s.columnText(4));
    if (!mac) throw DbError(0, "stored checkpoint MAC is not hex");
    cp.mac = std::move(*mac);
    return cp;
}
}

void CheckpointRepository::append(const Checkpoint& cp, std::int64_t receivedAt)
{
    Statement s(_db, "INSERT INTO atm_checkpoints (log_id, seq_no, hash, created_at, mac, received_at) VALUES (?, ?, ?, ?, ?, ?)");
    s.bind(1, cp.logId).bind(2, static_cast<std::int64_t>(cp.seqNo)).bind(3, cp.hash).bind(4, cp.timestamp).bind(5, toHex(cp.mac)).bind(6, receivedAt).run();
}

std::optional<Checkpoint> CheckpointRepository::latest(const std::string& logId) const
{
    Statement s(_db, "SELECT log_id, seq_no, hash, created_at, mac FROM atm_checkpoints WHERE log_id = ? ORDER BY seq_no DESC LIMIT 1");
    s.bind(1, logId);
    if (!s.step()) return std::nullopt;
    return readRow(s);
}

std::optional<Checkpoint> CheckpointRepository::find(const std::string& logId, std::uint64_t seqNo) const
{
    Statement s(_db, "SELECT log_id, seq_no, hash, created_at, mac FROM atm_checkpoints WHERE log_id = ? AND seq_no = ?");
    s.bind(1, logId).bind(2, static_cast<std::int64_t>(seqNo));
    if (!s.step()) return std::nullopt;
    return readRow(s);
}
