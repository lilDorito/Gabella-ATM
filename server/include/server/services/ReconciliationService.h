#pragma once
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "access/IAccessDecider.h"
#include "audit/IAuditSink.h"
#include "audit/IntentRecovery.h"
#include "common/Clock.h"
#include "common/ServerMessages.h"
#include "server/SystemConfig.h"
#include "server/db/Database.h"
#include "server/repo/AccountRepository.h"
#include "server/repo/CassetteRepository.h"
#include "server/repo/TxRepository.h"
#include "server/services/ServerServices.h"

enum class ManualResult
{
    Resolved,
    AlreadyResolved,
    UnknownTransaction,
    NotDisputed,
    TooEarly,
    Failed
};

const char* manualResultToString(ManualResult result);

class ReconciliationService final : public IReconciliationService, public IIntentResolver
{
private:
    Database& _db;
    TxRepository& _txs;
    AccountRepository& _accounts;
    CassetteRepository& _cassettes;
    IAccessDecider& _access;
    IAuditSink& _log;
    const IClock& _clock;
    const SystemConfig& _config;

    bool refuse(const std::string& atmId, const char* call, const std::string& reason);
    bool contradiction(const TxRecord& tx, const std::string& reason);
    bool settle(const TxRecord& tx, TxStatus to, const std::string& reason, const std::map<int, int>* newExpected, const std::string& by = "reconciliation");
    bool markUncertain(const TxRecord& tx, const std::string& reason);
    bool reconnect(const StatusReport& report);
    bool staffReport(const StatusReport& report, Action action);
    bool authorised(const std::string& atmId, const std::string& token, Action action);
    void noteMismatch(const std::string& atmId, const char* call, const std::map<int, int>& expected, const std::map<int, int>& reported);

public:
    ReconciliationService(Database& db,
        TxRepository& txs,
        AccountRepository& accounts,
        CassetteRepository& cassettes,
        IAccessDecider& access,
        IAuditSink& log,
        const IClock& clock,
        const SystemConfig& config);

    [[nodiscard]] bool onDispenseReport(const DispenseReport& report) override;
    [[nodiscard]] bool onStatusReport(const StatusReport& report) override;

    std::size_t tick();
    bool hasUnresolved(const std::string& atmId) const;
    std::vector<TxRecord> disputed() const;
    [[nodiscard]] ManualResult resolveManually(std::int64_t txId, bool commit, const std::string& by, const std::string& reason);

    bool owns(const LogEntry& intent) const override;
    std::optional<LogEvent> resolve(const LogEntry& intent) override;

    static std::string opIdFor(std::int64_t txId, TxStatus to);
};
