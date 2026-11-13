#include "server/services/StaffAuthenticator.h"

#include <exception>
#include <utility>

#include "server/db/DbError.h"
#include "server/services/LogHelpers.h"

namespace
{
constexpr const char* kOpPrefix = "staff/";

LogEvent staffEvent(EventType type, Outcome outcome, const std::string& staffId, std::string details)
{
    LogEvent e;
    e.type = type;
    e.outcome = outcome;
    e.actorRole = Role::System;
    e.actorId = staffId;
    e.details = std::move(details);
    return e;
}
}

SqliteStaffAuthenticator::SqliteStaffAuthenticator(StaffRepository& staff, IAuditSink& log, const IClock& clock, const SystemConfig& config, PasswordCheckFn check, std::string dummyHash)
    : _staff(staff),
      _log(log),
      _clock(clock),
      _config(config),
      _check(std::move(check)),
      _dummyHash(std::move(dummyHash))
{
}

std::string SqliteStaffAuthenticator::nextOpId(const std::string& staffId, std::int64_t now) { return std::string(kOpPrefix) + staffId + "/" + std::to_string(now) + "-" + std::to_string(++_ops); }

void SqliteStaffAuthenticator::refuse(EventType type, const std::string& staffId, const std::string& details) { (void)recordBestEffort(_log, staffEvent(type, Outcome::Failure, staffId, details)); }

std::optional<Role> SqliteStaffAuthenticator::verify(const std::string& staffId, const std::string& password)
{
    try
    {
        const auto staff = _staff.find(staffId);
        const std::int64_t now = _clock.nowUnix();

        // One hash is computed in every case, so the answer time does not tell which ids exist.
        const bool passwordOk = _check(staff ? staff->passwordHash : _dummyHash, password);

        if (!staff)
        {
            refuse(EventType::STAFF_LOGIN, staffId, "reason=unknown_staff");
            return std::nullopt;
        }
        if (!staff->active)
        {
            refuse(EventType::STAFF_LOGIN, staffId, "reason=disabled");
            return std::nullopt;
        }
        if (staff->lockedUntil > now)
        {
            refuse(EventType::STAFF_LOCKED, staffId, "reason=locked_out until=" + std::to_string(staff->lockedUntil));
            return std::nullopt;
        }
        if (!passwordOk)
        {
            countFailure(*staff, now);
            return std::nullopt;
        }
        if ((staff->failedLogins != 0 || staff->lockedUntil != 0) && !clearFailures(*staff, now)) return std::nullopt;
        return staff->role;
    }
    catch (const std::exception&)
    {
        // A broken staff table must never read as "password accepted".
        return std::nullopt;
    }
}

void SqliteStaffAuthenticator::countFailure(const StaffRecord& staff, std::int64_t now)
{
    LogEvent intent = staffEvent(EventType::STAFF_LOGIN, Outcome::Info, staff.staffId, "op=count_failure");
    intent.opId = nextOpId(staff.staffId, now);
    if (!_log.record(intent)) return;

    LogEvent result = intent;
    LoginFailure failure;
    try
    {
        failure = _staff.recordFailure(staff.staffId, now, _config.maxFailedStaffLogins, _config.staffLockoutSeconds);
    }
    catch (const DbError&)
    {
        result.outcome = Outcome::Failure;
        result.details += " reason=storage_failure";
        (void)_log.record(result);
        return;
    }

    result.outcome = Outcome::Failure;
    result.details += " reason=wrong_password attempts=" + std::to_string(failure.attempts);
    if (failure.locked) result.details += " locked_until=" + std::to_string(failure.lockedUntil);
    (void)_log.record(result);

    if (failure.locked)
        (void)_log.record(
            staffEvent(EventType::STAFF_LOCKED, Outcome::Failure, staff.staffId, "attempts=" + std::to_string(failure.attempts) + " locked_until=" + std::to_string(failure.lockedUntil)));
}

bool SqliteStaffAuthenticator::clearFailures(const StaffRecord& staff, std::int64_t now)
{
    LogEvent intent = staffEvent(EventType::STAFF_LOGIN, Outcome::Info, staff.staffId, "op=reset_failures failed_before=" + std::to_string(staff.failedLogins));
    intent.opId = nextOpId(staff.staffId, now);
    if (!_log.record(intent)) return false;

    LogEvent result = intent;
    try
    {
        _staff.resetFailures(staff.staffId);
    }
    catch (const DbError&)
    {
        result.outcome = Outcome::Failure;
        result.details += " reason=storage_failure";
        (void)_log.record(result);
        return false;
    }
    result.outcome = Outcome::Success;
    (void)_log.record(result);
    return true;
}

bool SqliteStaffAuthenticator::owns(const LogEntry& intent) const
{
    const LogEvent& e = intent.getEvent();
    return e.type == EventType::STAFF_LOGIN && e.opId.compare(0, std::string(kOpPrefix).size(), kOpPrefix) == 0;
}

std::optional<LogEvent> SqliteStaffAuthenticator::resolve(const LogEntry& intent)
{
    // A counter change leaves no record of its own to look up, so the outcome cannot be established.
    LogEvent result = intent.getEvent();
    result.outcome = Outcome::Failure;
    result.details += " recovered=unverified";
    return result;
}
