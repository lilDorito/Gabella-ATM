#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "server/db/Database.h"

struct TransactionRecord
{
    std::int64_t txId = 0;
    std::string atmId;
    std::string sessionId;
    std::string accountId;
    std::int64_t amountKop = 0;
    std::uint64_t dispenseSeq = 0;
    std::string status;
    std::int64_t createdAt = 0;
};

class TransactionRepository
{
private:
    Database& _db;

public:
    explicit TransactionRepository(Database& db) : _db(db) {}

    std::int64_t insertHeld(const std::string& atmId, const std::string& sessionId, const std::string& accountId, std::int64_t amountKop, std::uint64_t dispenseSeq, std::int64_t createdAt);
    std::optional<TransactionRecord> find(const std::string& atmId, std::uint64_t dispenseSeq) const;
    std::int64_t withdrawnSince(const std::string& accountId, std::int64_t since) const;
};
