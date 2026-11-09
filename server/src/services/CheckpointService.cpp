#include "server/services/CheckpointService.h"

#include <charconv>
#include <exception>

#include "audit/CheckpointPayload.h"
#include "server/db/DbError.h"

namespace
{
constexpr const char* kOpPrefix = "ckpt/";

std::string where(const Checkpoint& cp) { return "log_id=" + cp.logId + " seq=" + std::to_string(cp.seqNo); }

LogEvent checkpointEvent(EventType type, Outcome outcome, const std::string& atmId, std::string details)
{
    LogEvent e;
    e.type = type;
    e.outcome = outcome;
    e.actorRole = Role::System;
    e.actorId = atmId;
    e.details = std::move(details);
    return e;
}

std::optional<std::pair<std::string, std::uint64_t>> parseOpId(const std::string& opId)
{
    const std::string prefix = kOpPrefix;
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

const char* checkpointVerdictToString(CheckpointVerdict verdict)
{
    switch (verdict)
    {
    case CheckpointVerdict::Accepted: return "Accepted";
    case CheckpointVerdict::AlreadyKnown: return "AlreadyKnown";
    case CheckpointVerdict::UnknownAtm: return "UnknownAtm";
    case CheckpointVerdict::WrongLog: return "WrongLog";
    case CheckpointVerdict::BadMac: return "BadMac";
    case CheckpointVerdict::FromTheFuture: return "FromTheFuture";
    case CheckpointVerdict::Rollback: return "Rollback";
    case CheckpointVerdict::LogUnavailable: return "LogUnavailable";
    case CheckpointVerdict::StorageFailure: return "StorageFailure";
    }
    return "";
}

CheckpointService::CheckpointService(const BankHsm& hsm,
    CheckpointRepository& checkpoints,
    AtmRepository& atms,
    StaffTokenStore& tokens,
    IAuditSink& log,
    const IClock& clock,
    const SystemConfig& config)
    : _hsm(hsm),
      _checkpoints(checkpoints),
      _atms(atms),
      _tokens(tokens),
      _log(log),
      _clock(clock),
      _config(config)
{
}

std::string CheckpointService::opIdFor(const Checkpoint& cp) { return std::string(kOpPrefix) + cp.logId + "/" + std::to_string(cp.seqNo); }

CheckpointVerdict CheckpointService::submit(const std::string& atmId, const Checkpoint& cp)
{
    if (!_atms.find(atmId)) return reject(CheckpointVerdict::UnknownAtm, atmId, cp);
    if (cp.logId != atmId || atmId == kServerLogId) return reject(CheckpointVerdict::WrongLog, atmId, cp);
    if (cp.seqNo == 0 || !_hsm.verifyAudit(checkpointPayload(cp), cp.mac)) return reject(CheckpointVerdict::BadMac, atmId, cp);
    if (cp.timestamp > _clock.nowUnix() + _config.requestWindowSeconds) return reject(CheckpointVerdict::FromTheFuture, atmId, cp);

    if (const auto latest = _checkpoints.latest(atmId))
    {
        if (cp.seqNo <= latest->seqNo)
        {
            const auto stored = _checkpoints.find(atmId, cp.seqNo);
            if (stored && stored->hash == cp.hash) return CheckpointVerdict::AlreadyKnown;
            return rollback(atmId, cp, *latest);
        }
    }

    LogEvent intent = checkpointEvent(EventType::CHECKPOINT_ACCEPTED, Outcome::Info, atmId, where(cp));
    intent.opId = opIdFor(cp);
    if (!_log.record(intent)) return CheckpointVerdict::LogUnavailable;

    LogEvent result = intent;
    try
    {
        _checkpoints.append(cp, _clock.nowUnix());
    }
    catch (const DbError&)
    {
        result.outcome = Outcome::Failure;
        result.details += " reason=storage_failure";
        (void)_log.record(result);
        return CheckpointVerdict::StorageFailure;
    }
    result.outcome = Outcome::Success;
    (void)_log.record(result);
    return CheckpointVerdict::Accepted;
}

CheckpointVerdict CheckpointService::reject(CheckpointVerdict verdict, const std::string& atmId, const Checkpoint& cp)
{
    LogEvent e = checkpointEvent(EventType::CHECKPOINT_REJECTED, Outcome::Failure, atmId, std::string("reason=") + checkpointVerdictToString(verdict) + " " + where(cp));
    if (!_log.record(e))
    {
        e.actorId.clear();
        e.details = std::string("reason=") + checkpointVerdictToString(verdict) + " actor_id=withheld";
        (void)_log.record(e);
    }
    return verdict;
}

CheckpointVerdict CheckpointService::rollback(const std::string& atmId, const Checkpoint& cp, const Checkpoint& latest)
{
    (void)_atms.flagLogReview(atmId);
    const std::string details = where(cp) + " latest_seq=" + std::to_string(latest.seqNo) + (cp.seqNo == latest.seqNo ? " kind=rewrite" : " kind=truncation");
    (void)_log.record(checkpointEvent(EventType::LOG_ROLLBACK_DETECTED, Outcome::Failure, atmId, details));
    return CheckpointVerdict::Rollback;
}

std::optional<SignedCheckpoint> CheckpointService::latestFor(const std::string& atmId, const std::string& auditorToken, const std::string& nonce)
{
    const auto who = _tokens.resolve(auditorToken);
    if (!who || who->role != Role::Auditor || who->atmId != atmId)
    {
        (void)_log.record(checkpointEvent(EventType::ACCESS_DENIED, Outcome::Failure, atmId, "action=LatestCheckpoint reason=NotPermitted"));
        return std::nullopt;
    }

    const auto latest = _checkpoints.latest(atmId);
    if (!latest) return std::nullopt;

    SignedCheckpoint reply;
    reply.checkpoint = *latest;
    reply.requestNonce = nonce;
    auto signature = _hsm.sign(SignDomain::Checkpoint, reply.signedPayload());
    if (!signature) return std::nullopt;
    reply.signature = std::move(*signature);

    LogEvent e = checkpointEvent(EventType::AUDIT_ACCESS, Outcome::Info, who->staffId, "action=LatestCheckpoint " + where(*latest));
    e.actorRole = Role::Auditor;
    if (!_log.record(e)) return std::nullopt;
    return reply;
}

bool CheckpointService::owns(const LogEntry& intent) const { return intent.getEvent().type == EventType::CHECKPOINT_ACCEPTED && parseOpId(intent.getEvent().opId).has_value(); }

std::optional<LogEvent> CheckpointService::resolve(const LogEntry& intent)
{
    const auto target = parseOpId(intent.getEvent().opId);
    if (!target) return std::nullopt;

    LogEvent result = intent.getEvent();
    const bool stored = _checkpoints.find(target->first, target->second).has_value();
    result.outcome = stored ? Outcome::Success : Outcome::Failure;
    result.details += stored ? " recovered=committed" : " recovered=absent";
    return result;
}

bool ServerCheckpointSink::submit(const Checkpoint& cp)
{
    try
    {
        _checkpoints.append(cp, _clock.nowUnix());
        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
}
