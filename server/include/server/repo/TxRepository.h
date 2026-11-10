#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "server/db/Database.h"

enum class TxStatus
{
    Held,
    Uncertain,
    Committed,
    Reversed
};

const char* txStatusToString(TxStatus status);
std::optional<TxStatus> txStatusFromString(const std::string& text);

struct TxRecord
{
    std::int64_t id = 0;
    std::string atmId;
    std::string sessionId;
    std::string accountId;
    std::int64_t amountKop = 0;
    std::uint64_t dispenseSeq = 0;
    TxStatus status = TxStatus::Held;
    std::int64_t createdAt = 0;
    std::optional<std::int64_t> resolvedAt;
    std::string resolvedBy;
    std::string reason;
};

class TxRepository
{
private:
    Database& _db;

public:
    explicit TxRepository(Database& db) : _db(db) {}

    std::int64_t insertHeld(const std::string& atmId, const std::string& sessionId, const std::string& accountId, std::int64_t amountKop, std::uint64_t dispenseSeq, std::int64_t createdAt);
    std::optional<TxRecord> findById(std::int64_t id) const;
    std::optional<TxRecord> findBySeq(const std::string& atmId, std::uint64_t dispenseSeq) const;
    std::vector<TxRecord> findOpenByAtm(const std::string& atmId) const;
    std::vector<TxRecord> findHeldOlderThan(std::int64_t cutoff) const;
    std::vector<TxRecord> findUncertainOlderThan(std::int64_t cutoff) const;
    [[nodiscard]] bool setStatus(std::int64_t id, TxStatus to, std::int64_t now, const std::string& by, const std::string& reason);
    std::int64_t reservedTotal(const std::string& accountId) const;
    std::int64_t dailyTotal(const std::string& accountId, std::int64_t since) const;
};
