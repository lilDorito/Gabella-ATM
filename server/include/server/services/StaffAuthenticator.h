#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "access/IStaffAuthenticator.h"
#include "audit/IAuditSink.h"
#include "audit/IntentRecovery.h"
#include "common/Clock.h"
#include "server/SystemConfig.h"
#include "server/repo/StaffRepository.h"
#include "server/services/PasswordVerifier.h"

class SqliteStaffAuthenticator final : public IStaffAuthenticator, public IIntentResolver
{
private:
    StaffRepository& _staff;
    IAuditSink& _log;
    const IClock& _clock;
    const SystemConfig& _config;
    PasswordCheckFn _check;
    std::string _dummyHash;
    std::uint64_t _ops = 0;

    std::string nextOpId(const std::string& staffId, std::int64_t now);
    void refuse(EventType type, const std::string& staffId, const std::string& details);
    void countFailure(const StaffRecord& staff, std::int64_t now);
    bool clearFailures(const StaffRecord& staff, std::int64_t now);

public:
    SqliteStaffAuthenticator(StaffRepository& staff, IAuditSink& log, const IClock& clock, const SystemConfig& config, PasswordCheckFn check, std::string dummyHash);

    [[nodiscard]] std::optional<Role> verify(const std::string& staffId, const std::string& password) override;

    bool owns(const LogEntry& intent) const override;
    std::optional<LogEvent> resolve(const LogEntry& intent) override;
};
