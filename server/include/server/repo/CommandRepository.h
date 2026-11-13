#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "common/Action.h"
#include "server/db/Database.h"

enum class CommandStatus
{
    Queued,
    Succeeded,
    Failed
};

const char* commandStatusToString(CommandStatus status);
std::optional<CommandStatus> commandStatusFromString(const std::string& text);

struct CommandRecord
{
    std::string atmId;
    std::uint64_t seq = 0;
    Action action = Action::RestoreFromOutOfService;
    std::string params;
    std::int64_t expiresAt = 0;
    std::string signature;
    std::string requestId;
    CommandStatus status = CommandStatus::Queued;
};

class CommandRepository
{
private:
    Database& _db;

public:
    explicit CommandRepository(Database& db) : _db(db) {}

    [[nodiscard]] std::optional<std::uint64_t> reserveSeq(const std::string& atmId);
    void insert(const CommandRecord& command);

    std::optional<CommandRecord> find(const std::string& atmId, std::uint64_t seq) const;
    std::optional<CommandRecord> findByRequest(const std::string& requestId) const;
    std::vector<CommandRecord> queued(const std::string& atmId) const;
    std::vector<CommandRecord> queuedExpired(std::int64_t now) const;
    [[nodiscard]] bool setStatus(const std::string& atmId, std::uint64_t seq, CommandStatus to);
};
