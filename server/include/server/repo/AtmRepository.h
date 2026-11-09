#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "server/db/Database.h"

enum class AtmStatus
{
    Active,
    OutOfService
};

const char* atmStatusToString(AtmStatus status);

struct AtmRecord
{
    std::string atmId;
    AtmStatus status = AtmStatus::Active;
    std::uint64_t lastDispenseSeq = 0;
    std::uint64_t lastCommandSeq = 0;
    bool logReviewRequired = false;
};

class AtmRepository
{
private:
    Database& _db;

public:
    explicit AtmRepository(Database& db) : _db(db) {}

    void insert(const std::string& atmId);
    std::optional<AtmRecord> find(const std::string& atmId) const;
    [[nodiscard]] bool setStatus(const std::string& atmId, AtmStatus status);
    [[nodiscard]] bool flagLogReview(const std::string& atmId);
};
