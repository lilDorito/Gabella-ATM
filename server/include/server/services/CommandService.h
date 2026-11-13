#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "access/DualControlManager.h"
#include "audit/IAuditSink.h"
#include "audit/IntentRecovery.h"
#include "common/Clock.h"
#include "crypto/BankHsm.h"
#include "server/SystemConfig.h"
#include "server/db/Database.h"
#include "server/repo/AtmRepository.h"
#include "server/repo/CommandRepository.h"
#include "server/repo/DualControlRepository.h"
#include "server/services/ServerServices.h"

enum class EnqueueResult
{
    Queued,
    AlreadyQueued,
    NotApproved,
    NotACommand,
    BadParams,
    UnknownAtm,
    KeyUnavailable,
    SigningFailed,
    LogUnavailable,
    StorageFailure
};

const char* enqueueResultToString(EnqueueResult result);

class CommandService final : public ICommandService, public IIntentResolver
{
private:
    BankHsm& _hsm;
    Database& _db;
    AtmRepository& _atms;
    CommandRepository& _commands;
    DualControlManager& _dual;
    DualControlRepository& _requests;
    IAuditSink& _log;
    const IClock& _clock;
    const SystemConfig& _config;

    EnqueueResult closeEnqueue(const LogEvent& intent, EnqueueResult result, const std::string& details);
    void closeIntent(const LogEvent& intent, Outcome outcome, const std::string& details);
    bool expire(const CommandRecord& command);

public:
    CommandService(BankHsm& hsm,
        Database& db,
        AtmRepository& atms,
        CommandRepository& commands,
        DualControlManager& dual,
        DualControlRepository& requests,
        IAuditSink& log,
        const IClock& clock,
        const SystemConfig& config);

    [[nodiscard]] EnqueueResult enqueueApproved(const std::string& requestId);

    [[nodiscard]] std::vector<SignedCommand> pollCommands(const std::string& atmId) override;
    [[nodiscard]] bool reportCommandResult(const std::string& atmId, std::uint64_t commandSeq, bool ok) override;

    std::size_t tick();

    bool owns(const LogEntry& intent) const override;
    std::optional<LogEvent> resolve(const LogEntry& intent) override;

    static std::string enqueueOpId(const std::string& requestId);
    static std::string resultOpId(const std::string& atmId, std::uint64_t seq);
};
