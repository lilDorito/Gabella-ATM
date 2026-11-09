#pragma once
#include <cstdint>
#include <string>

#include "server/db/Database.h"

class NonceRepository
{
private:
    Database& _db;

public:
    explicit NonceRepository(Database& db) : _db(db) {}

    [[nodiscard]] bool insertIfNew(const std::string& nonce, const std::string& atmId, std::int64_t receivedAt);
    void purgeOlderThan(std::int64_t cutoff);
};
