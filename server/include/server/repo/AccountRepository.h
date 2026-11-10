#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "server/db/Database.h"

struct AccountRecord
{
    std::string accountId;
    std::string ownerName;
    std::int64_t balanceKop = 0;
};

class AccountRepository
{
private:
    Database& _db;

public:
    explicit AccountRepository(Database& db) : _db(db) {}

    void insert(const AccountRecord& account);
    std::optional<AccountRecord> find(const std::string& accountId) const;
    [[nodiscard]] bool debit(const std::string& accountId, std::int64_t amountKop);
};
