#include "server/repo/NonceRepository.h"

#include "server/db/Statement.h"

bool NonceRepository::insertIfNew(const std::string& nonce, const std::string& atmId, std::int64_t receivedAt)
{
    Statement s(_db, "INSERT OR IGNORE INTO seen_nonces (nonce, atm_id, received_at) VALUES (?, ?, ?)");
    s.bind(1, nonce).bind(2, atmId).bind(3, receivedAt).run();
    return _db.changes() == 1;
}

void NonceRepository::purgeOlderThan(std::int64_t cutoff)
{
    Statement s(_db, "DELETE FROM seen_nonces WHERE received_at < ?");
    s.bind(1, cutoff).run();
}
