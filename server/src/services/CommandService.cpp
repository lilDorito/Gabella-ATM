#include "server/services/CommandService.h"

#include <charconv>
#include <exception>
#include <type_traits>
#include <utility>

#include "crypto/SignDomain.h"
#include "server/db/DbError.h"
#include "server/db/Transaction.h"
#include "server/services/CommandParams.h"
#include "server/services/LogHelpers.h"

namespace
{
constexpr const char* kEnqueuePrefix = "cmd/";
constexpr const char* kResultPrefix = "cmdres/";
constexpr const char* kExpiryPrefix = "cmdexp/";

// SignedCommand carries expiresAt when the signed payload includes it. Writing it through a trait keeps
// this file compiling either way and puts the same value into the stored row and the signature.
template <typename T, typename = void>
struct HasExpiresAt : std::false_type
{
};

template <typename T>
struct HasExpiresAt<T, std::void_t<decltype(std::declval<T&>().expiresAt)>> : std::true_type
{
};

template <typename T>
void setExpiresAt(T& command, std::int64_t value)
{
    if constexpr (HasExpiresAt<T>::value) command.expiresAt = static_cast<decltype(command.expiresAt)>(value);
}

bool isAtmCommand(Action action) { return action == Action::RestoreFromOutOfService || action == Action::UpdateWorkingKey; }

std::optional<KeyType> keyTypeFromName(const std::string& name)
{
    if (name == "Encryption") return KeyType::Encryption;
    if (name == "Mac") return KeyType::Mac;
    if (name == "Audit") return KeyType::Audit;
    return std::nullopt;
}

// params of a stored UpdateWorkingKey command are "<type>|<blob>".
std::optional<KeyType> keyTypeOf(const CommandRecord& command)
{
    if (command.action != Action::UpdateWorkingKey) return std::nullopt;
    const std::size_t bar = command.params.find('|');
    if (bar == std::string::npos) return std::nullopt;
    return keyTypeFromName(command.params.substr(0, bar));
}

LogEvent commandEvent(EventType type, Outcome outcome, const std::string& atmId, std::string details)
{
    LogEvent e;
    e.type = type;
    e.outcome = outcome;
    e.actorRole = Role::System;
    e.actorId = atmId;
    e.details = std::move(details);
    return e;
}

std::string describe(const CommandRecord& c)
{
    return "atm=" + c.atmId + " seq=" + std::to_string(c.seq) + " action=" + actionToString(c.action) + " id=" + c.requestId;
}

std::optional<std::pair<std::string, std::uint64_t>> parseCommandOpId(const std::string& opId, const std::string& prefix)
{
    if (opId.compare(0, prefix.size(), prefix) != 0) return std::nullopt;
    const std::size_t slash = opId.rfind('/');
    if (slash == std::string::npos || slash < prefix.size() || slash + 1 >= opId.size()) return std::nullopt;

    std::uint64_t seq = 0;
    const char* first = opId.data() + slash + 1;
    const char* last = opId.data() + opId.size();
    auto [ptr, ec] = std::from_chars(first, last, seq);
    if (ec != std::errc() || ptr != last) return std::nullopt;
    return std::make_pair(opId.substr(prefix.size(), slash - prefix.size()), seq);
}
}

const char* enqueueResultToString(EnqueueResult result)
{
    switch (result)
    {
    case EnqueueResult::Queued: return "Queued";
    case EnqueueResult::AlreadyQueued: return "AlreadyQueued";
    case EnqueueResult::NotApproved: return "NotApproved";
    case EnqueueResult::NotACommand: return "NotACommand";
    case EnqueueResult::BadParams: return "BadParams";
    case EnqueueResult::UnknownAtm: return "UnknownAtm";
    case EnqueueResult::KeyUnavailable: return "KeyUnavailable";
    case EnqueueResult::SigningFailed: return "SigningFailed";
    case EnqueueResult::LogUnavailable: return "LogUnavailable";
    case EnqueueResult::StorageFailure: return "StorageFailure";
    }
    return "";
}

CommandService::CommandService(BankHsm& hsm,
    Database& db,
    AtmRepository& atms,
    CommandRepository& commands,
    DualControlManager& dual,
    DualControlRepository& requests,
    IAuditSink& log,
    const IClock& clock,
    const SystemConfig& config)
    : _hsm(hsm),
      _db(db),
      _atms(atms),
      _commands(commands),
      _dual(dual),
      _requests(requests),
      _log(log),
      _clock(clock),
      _config(config)
{
}

std::string CommandService::enqueueOpId(const std::string& requestId) { return std::string(kEnqueuePrefix) + requestId; }

std::string CommandService::resultOpId(const std::string& atmId, std::uint64_t seq) { return std::string(kResultPrefix) + atmId + "/" + std::to_string(seq); }

void CommandService::closeIntent(const LogEvent& intent, Outcome outcome, const std::string& details)
{
    LogEvent result = intent;
    result.outcome = outcome;
    result.details = details;
    (void)_log.record(result);
}

EnqueueResult CommandService::closeEnqueue(const LogEvent& intent, EnqueueResult result, const std::string& details)
{
    closeIntent(intent, result == EnqueueResult::Queued ? Outcome::Success : Outcome::Failure, details);
    return result;
}

EnqueueResult CommandService::enqueueApproved(const std::string& requestId)
{
    try
    {
        const auto request = _dual.get(requestId);
        if (!request || request->status != RequestStatus::Approved) return EnqueueResult::NotApproved;
        if (!isAtmCommand(request->action)) return EnqueueResult::NotACommand;
        if (_commands.findByRequest(requestId)) return EnqueueResult::AlreadyQueued;

        const auto target = parseCommandParams(request->params);
        if (!target) return EnqueueResult::BadParams;
        if (!_atms.find(target->atmId)) return EnqueueResult::UnknownAtm;

        std::optional<KeyType> keyType;
        std::string keyName;
        if (request->action == Action::UpdateWorkingKey)
        {
            keyName = target->extra;
            keyType = keyTypeFromName(keyName);
            if (!keyType) return EnqueueResult::BadParams;
        }

        const std::string where = "op=enqueue_command id=" + requestId + " action=" + actionToString(request->action) + " atm=" + target->atmId;
        LogEvent intent = commandEvent(EventType::DUAL_CONTROL_APPROVED, Outcome::Info, target->atmId, where);
        intent.opId = enqueueOpId(requestId);
        if (!_log.record(intent)) return EnqueueResult::LogUnavailable;

        std::string params;
        if (keyType)
        {
            // The new key is created inside the HSM and leaves it only encrypted. The bank keeps it pending
            // until the ATM confirms that it has switched.
            const auto blob = _hsm.prepareWorkingKey(*keyType);
            if (!blob) return closeEnqueue(intent, EnqueueResult::KeyUnavailable, where + " reason=key_unavailable");
            params = keyName + "|" + *blob;
        }

        CommandRecord command;
        command.atmId = target->atmId;
        command.action = request->action;
        command.params = params;
        command.requestId = requestId;
        command.expiresAt = _clock.nowUnix() + _config.dualControlTtlSeconds;

        try
        {
            Transaction tx(_db);
            const auto seq = _commands.reserveSeq(command.atmId);
            if (!seq) throw DbError(0, "ATM vanished while queueing a command");
            command.seq = *seq;

            SignedCommand signedCommand;
            signedCommand.atmId = command.atmId;
            signedCommand.commandSeq = command.seq;
            signedCommand.action = command.action;
            signedCommand.params = command.params;
            setExpiresAt(signedCommand, command.expiresAt);
            const auto signature = _hsm.sign(SignDomain::Command, signedCommand.signedPayload());
            if (!signature)
            {
                if (keyType) (void)_hsm.cancelPendingWorkingKey(*keyType);
                closeIntent(intent, Outcome::Failure, where + " reason=signing_failed");
                return EnqueueResult::SigningFailed;
            }
            command.signature = *signature;

            _commands.insert(command);
            tx.commit();
        }
        catch (const std::exception&)
        {
            if (keyType) (void)_hsm.cancelPendingWorkingKey(*keyType);
            return closeEnqueue(intent, EnqueueResult::StorageFailure, where + " reason=storage_failure");
        }

        return closeEnqueue(intent, EnqueueResult::Queued, where + " seq=" + std::to_string(command.seq));
    }
    catch (const std::exception&)
    {
        return EnqueueResult::StorageFailure;
    }
}

std::vector<SignedCommand> CommandService::pollCommands(const std::string& atmId)
{
    std::vector<SignedCommand> out;
    const std::int64_t now = _clock.nowUnix();
    for (const CommandRecord& record : _commands.queued(atmId))
    {
        if (record.expiresAt <= now) continue;

        SignedCommand c;
        c.atmId = record.atmId;
        c.commandSeq = record.seq;
        c.action = record.action;
        c.params = record.params;
        setExpiresAt(c, record.expiresAt);
        c.signature = record.signature;
        out.push_back(std::move(c));
    }
    return out;
}

bool CommandService::reportCommandResult(const std::string& atmId, std::uint64_t commandSeq, bool ok)
{
    const auto command = _commands.find(atmId, commandSeq);
    if (!command || command->status != CommandStatus::Queued)
    {
        // Unknown or already reported: a replayed or invented result changes nothing.
        (void)recordBestEffort(_log, commandEvent(EventType::ACCESS_DENIED, Outcome::Failure, atmId, "call=CommandResult reason=unknown_command seq=" + std::to_string(commandSeq)));
        return false;
    }

    const std::string where = "op=command_result ok=" + std::string(ok ? "1" : "0") + " " + describe(*command);
    LogEvent intent = commandEvent(EventType::DUAL_CONTROL_EXECUTED, Outcome::Info, atmId, where);
    intent.opId = resultOpId(atmId, commandSeq);
    if (!_log.record(intent)) return false;

    bool stored = false;
    std::string reason;
    try
    {
        Transaction tx(_db);
        if (!_commands.setStatus(atmId, commandSeq, ok ? CommandStatus::Succeeded : CommandStatus::Failed))
            reason = "reason=state_changed";
        else if (ok && command->action == Action::RestoreFromOutOfService && !_atms.setStatus(atmId, AtmStatus::Active))
            reason = "reason=atm_missing";
        else
        {
            tx.commit();
            stored = true;
        }
    }
    catch (const std::exception&)
    {
        reason = "reason=storage_failure";
    }
    if (!stored)
    {
        closeIntent(intent, Outcome::Failure, where + " " + reason);
        return false;
    }

    // The HSM key and the request status are not part of the SQL transaction; they follow the stored result.
    std::string notes;
    bool clean = true;
    if (const auto keyType = keyTypeOf(*command))
    {
        const bool done = ok ? _hsm.commitWorkingKey(*keyType) : _hsm.cancelPendingWorkingKey(*keyType);
        if (!done)
        {
            notes += " reason=pending_key_missing";
            clean = false;
        }
        else if (ok)
            (void)_log.record(commandEvent(EventType::KEY_UPDATED, Outcome::Success, atmId, "atm=" + atmId + " seq=" + std::to_string(commandSeq) + " key=" + command->params.substr(0, command->params.find('|'))));
    }
    if (ok && !_dual.markExecuted(command->requestId))
    {
        notes += " reason=request_not_closed";
        clean = false;
    }

    closeIntent(intent, ok && clean ? Outcome::Success : Outcome::Failure, where + notes);
    return true;
}

bool CommandService::expire(const CommandRecord& command)
{
    const std::string where = "op=expire_command " + describe(command);
    LogEvent intent = commandEvent(EventType::DUAL_CONTROL_EXECUTED, Outcome::Info, command.atmId, where);
    intent.opId = std::string(kExpiryPrefix) + command.atmId + "/" + std::to_string(command.seq);
    if (!_log.record(intent)) return false;

    bool stored = false;
    try
    {
        stored = _commands.setStatus(command.atmId, command.seq, CommandStatus::Failed);
    }
    catch (const std::exception&)
    {
        stored = false;
    }
    if (stored)
    {
        if (const auto keyType = keyTypeOf(command)) (void)_hsm.cancelPendingWorkingKey(*keyType);
    }
    closeIntent(intent, Outcome::Failure, where + (stored ? " reason=expired" : " reason=storage_failure"));
    return stored;
}

std::size_t CommandService::tick()
{
    std::size_t changed = 0;
    try
    {
        for (const CommandRecord& command : _commands.queuedExpired(_clock.nowUnix()))
            if (expire(command)) ++changed;

        for (const CriticalRequest& request : _requests.listApproved())
            if (enqueueApproved(request.requestId) == EnqueueResult::Queued) ++changed;
    }
    catch (const std::exception&)
    {
    }
    return changed;
}

bool CommandService::owns(const LogEntry& intent) const
{
    const LogEvent& e = intent.getEvent();
    if (e.type == EventType::DUAL_CONTROL_APPROVED) return e.opId.compare(0, std::string(kEnqueuePrefix).size(), kEnqueuePrefix) == 0;
    if (e.type == EventType::DUAL_CONTROL_EXECUTED)
        return parseCommandOpId(e.opId, kResultPrefix).has_value() || parseCommandOpId(e.opId, kExpiryPrefix).has_value();
    return false;
}

std::optional<LogEvent> CommandService::resolve(const LogEntry& intent)
{
    LogEvent result = intent.getEvent();

    if (result.type == EventType::DUAL_CONTROL_APPROVED)
    {
        const std::string requestId = result.opId.substr(std::string(kEnqueuePrefix).size());
        const bool stored = _commands.findByRequest(requestId).has_value();
        result.outcome = stored ? Outcome::Success : Outcome::Failure;
        result.details += stored ? " recovered=committed" : " recovered=absent";
        return result;
    }

    auto target = parseCommandOpId(result.opId, kResultPrefix);
    if (!target) target = parseCommandOpId(result.opId, kExpiryPrefix);
    if (!target) return std::nullopt;

    const auto command = _commands.find(target->first, target->second);
    const bool settled = command && command->status != CommandStatus::Queued;
    result.outcome = settled ? Outcome::Success : Outcome::Failure;
    result.details += settled ? " recovered=committed" : " recovered=absent";
    return result;
}
