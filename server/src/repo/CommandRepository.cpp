#include "server/repo/CommandRepository.h"

#include "common/Hex.h"
#include "server/ActionNames.h"
#include "server/db/DbError.h"
#include "server/db/Statement.h"

namespace
{
const char* kColumns = "atm_id, command_seq, action, params, expires_at, signature, request_id, status";

CommandRecord read(const Statement& s)
{
    const auto action = actionFromString(s.columnText(2));
    const auto params = fromHex(s.columnText(3));
    const auto signature = fromHex(s.columnText(5));
    const auto status = commandStatusFromString(s.columnText(7));
    if (!action || !params || !signature || !status) throw DbError(0, "stored ATM command is not valid");

    CommandRecord c;
    c.atmId = s.columnText(0);
    c.seq = static_cast<std::uint64_t>(s.columnInt64(1));
    c.action = *action;
    c.params = *params;
    c.expiresAt = s.columnInt64(4);
    c.signature = *signature;
    c.requestId = s.columnText(6);
    c.status = *status;
    return c;
}

std::vector<CommandRecord> readAll(Statement& s)
{
    std::vector<CommandRecord> out;
    while (s.step()) out.push_back(read(s));
    return out;
}
}

const char* commandStatusToString(CommandStatus status)
{
    switch (status)
    {
    case CommandStatus::Queued: return "QUEUED";
    case CommandStatus::Succeeded: return "SUCCEEDED";
    case CommandStatus::Failed: return "FAILED";
    }
    return "";
}

std::optional<CommandStatus> commandStatusFromString(const std::string& text)
{
    if (text == "QUEUED") return CommandStatus::Queued;
    if (text == "SUCCEEDED") return CommandStatus::Succeeded;
    if (text == "FAILED") return CommandStatus::Failed;
    return std::nullopt;
}

std::optional<std::uint64_t> CommandRepository::reserveSeq(const std::string& atmId)
{
    {
        Statement update(_db, "UPDATE atms SET last_command_seq = last_command_seq + 1 WHERE atm_id = ?");
        update.bind(1, atmId).run();
    }
    if (_db.changes() != 1) return std::nullopt;

    Statement read(_db, "SELECT last_command_seq FROM atms WHERE atm_id = ?");
    read.bind(1, atmId);
    if (!read.step()) return std::nullopt;
    return static_cast<std::uint64_t>(read.columnInt64(0));
}

void CommandRepository::insert(const CommandRecord& c)
{
    Statement s(_db, "INSERT INTO atm_commands (atm_id, command_seq, action, params, expires_at, signature, request_id, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    s.bind(1, c.atmId)
        .bind(2, static_cast<std::int64_t>(c.seq))
        .bind(3, std::string(actionToString(c.action)))
        .bind(4, toHex(c.params))
        .bind(5, c.expiresAt)
        .bind(6, toHex(c.signature))
        .bind(7, c.requestId)
        .bind(8, std::string(commandStatusToString(c.status)))
        .run();
}

std::optional<CommandRecord> CommandRepository::find(const std::string& atmId, std::uint64_t seq) const
{
    Statement s(_db, (std::string("SELECT ") + kColumns + " FROM atm_commands WHERE atm_id = ? AND command_seq = ?").c_str());
    s.bind(1, atmId).bind(2, static_cast<std::int64_t>(seq));
    if (!s.step()) return std::nullopt;
    return read(s);
}

std::optional<CommandRecord> CommandRepository::findByRequest(const std::string& requestId) const
{
    Statement s(_db, (std::string("SELECT ") + kColumns + " FROM atm_commands WHERE request_id = ?").c_str());
    s.bind(1, requestId);
    if (!s.step()) return std::nullopt;
    return read(s);
}

std::vector<CommandRecord> CommandRepository::queued(const std::string& atmId) const
{
    Statement s(_db, (std::string("SELECT ") + kColumns + " FROM atm_commands WHERE atm_id = ? AND status = 'QUEUED' ORDER BY command_seq").c_str());
    s.bind(1, atmId);
    return readAll(s);
}

std::vector<CommandRecord> CommandRepository::queuedExpired(std::int64_t now) const
{
    Statement s(_db, (std::string("SELECT ") + kColumns + " FROM atm_commands WHERE status = 'QUEUED' AND expires_at <= ? ORDER BY atm_id, command_seq").c_str());
    s.bind(1, now);
    return readAll(s);
}

bool CommandRepository::setStatus(const std::string& atmId, std::uint64_t seq, CommandStatus to)
{
    if (to == CommandStatus::Queued) return false;
    Statement s(_db, "UPDATE atm_commands SET status = ? WHERE atm_id = ? AND command_seq = ? AND status = 'QUEUED'");
    s.bind(1, std::string(commandStatusToString(to))).bind(2, atmId).bind(3, static_cast<std::int64_t>(seq)).run();
    return _db.changes() == 1;
}
