#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "common/Checkpoint.h"
#include "server/db/Database.h"

class CheckpointRepository
{
private:
    Database& _db;

public:
    explicit CheckpointRepository(Database& db) : _db(db) {}

    void append(const Checkpoint& cp, std::int64_t receivedAt);
    std::optional<Checkpoint> latest(const std::string& logId) const;
    std::optional<Checkpoint> find(const std::string& logId, std::uint64_t seqNo) const;
};
