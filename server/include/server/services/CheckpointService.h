#pragma once
#include <optional>
#include <string>

#include "access/StaffTokenStore.h"
#include "audit/IAuditSink.h"
#include "audit/ICheckpointSink.h"
#include "audit/IntentRecovery.h"
#include "common/Clock.h"
#include "common/ServerMessages.h"
#include "crypto/BankHsm.h"
#include "server/SystemConfig.h"
#include "server/repo/AtmRepository.h"
#include "server/repo/CheckpointRepository.h"

inline constexpr const char* kServerLogId = "SERVER";

enum class CheckpointVerdict
{
    Accepted,
    AlreadyKnown,
    UnknownAtm,
    WrongLog,
    BadMac,
    FromTheFuture,
    Rollback,
    LogUnavailable,
    StorageFailure
};

const char* checkpointVerdictToString(CheckpointVerdict verdict);

class CheckpointService final : public IIntentResolver
{
private:
    const BankHsm& _hsm;
    CheckpointRepository& _checkpoints;
    AtmRepository& _atms;
    StaffTokenStore& _tokens;
    IAuditSink& _log;
    const IClock& _clock;
    const SystemConfig& _config;

    CheckpointVerdict reject(CheckpointVerdict verdict, const std::string& atmId, const Checkpoint& cp);
    CheckpointVerdict rollback(const std::string& atmId, const Checkpoint& cp, const Checkpoint& latest);

public:
    CheckpointService(const BankHsm& hsm, CheckpointRepository& checkpoints, AtmRepository& atms, StaffTokenStore& tokens, IAuditSink& log, const IClock& clock, const SystemConfig& config);

    [[nodiscard]] CheckpointVerdict submit(const std::string& atmId, const Checkpoint& cp);
    [[nodiscard]] std::optional<SignedCheckpoint> latestFor(const std::string& atmId, const std::string& auditorToken, const std::string& nonce);

    static std::string opIdFor(const Checkpoint& cp);

    bool owns(const LogEntry& intent) const override;
    std::optional<LogEvent> resolve(const LogEntry& intent) override;
};

class ServerCheckpointSink final : public ICheckpointSink
{
private:
    CheckpointRepository& _checkpoints;
    const IClock& _clock;

public:
    ServerCheckpointSink(CheckpointRepository& checkpoints, const IClock& clock) : _checkpoints(checkpoints), _clock(clock) {}

    [[nodiscard]] bool submit(const Checkpoint& cp) override;
};
