#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "server/db/Database.h"

struct CardRecord
{
    std::string pan;
    std::string accountId;
    int expMonth = 0;
    int expYear = 0;
    std::string pinVerifyValue;
    std::uint32_t failedPinAttempts = 0;
    bool blocked = false;
};

struct PinFailure
{
    std::uint32_t attempts = 0;
    bool blocked = false;
};

class CardRepository
{
private:
    Database& _db;

public:
    explicit CardRepository(Database& db) : _db(db) {}

    void insert(const CardRecord& card);
    std::optional<CardRecord> find(const std::string& pan) const;
    PinFailure recordFailedPin(const std::string& pan, std::uint32_t maxWrongPins);
    void resetFailedPins(const std::string& pan);
};
