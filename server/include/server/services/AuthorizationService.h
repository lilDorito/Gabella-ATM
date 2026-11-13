#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "audit/IAuditSink.h"
#include "audit/IntentRecovery.h"
#include "common/Clock.h"
#include "crypto/BankHsm.h"
#include "server/SystemConfig.h"
#include "server/db/Database.h"
#include "server/repo/AccountRepository.h"
#include "server/repo/AtmRepository.h"
#include "server/repo/CardRepository.h"
#include "server/repo/TxRepository.h"
#include "server/services/ServerServices.h"

class AuthorizationService final : public IAuthorizationService, public IIntentResolver
{
private:
    struct Reservation
    {
        bool done = false;
        AuthStatus status = AuthStatus::Error;
        std::string reason;
        std::int64_t txId = 0;
    };

    const BankHsm& _hsm;
    Database& _db;
    AtmRepository& _atms;
    CardRepository& _cards;
    AccountRepository& _accounts;
    TxRepository& _transactions;
    IAuditSink& _log;
    const IClock& _clock;
    const SystemConfig& _config;
    std::uint64_t _pinOps = 0;

    AuthResponse refuse(const AuthRequest& request, AuthStatus status, const std::string& reason);
    static AuthResponse unavailable(const AuthRequest& request);
    std::string pinOpId(const std::string& atmId);
    void closeIntent(const AuthRequest& request, const LogEvent& intent, Outcome outcome, const std::string& details);
    AuthResponse wrongPin(const AuthRequest& request);
    bool resetPin(const AuthRequest& request);
    AuthResponse balance(const AuthRequest& request);
    AuthResponse withdraw(const AuthRequest& request);
    Reservation reserve(const AuthRequest& request, const DispenseCommand& command, std::int64_t now);
    std::optional<std::int64_t> availableKop(const std::string& accountId) const;
    std::optional<AuthStatus> withdrawalRefusal(const CardRecord& card, std::int64_t amountKop, std::int64_t now, std::string& reason) const;

public:
    AuthorizationService(const BankHsm& hsm,
        Database& db,
        AtmRepository& atms,
        CardRepository& cards,
        AccountRepository& accounts,
        TxRepository& transactions,
        IAuditSink& log,
        const IClock& clock,
        const SystemConfig& config);

    [[nodiscard]] AuthResponse authorize(const AuthRequest& request) override;
    [[nodiscard]] bool endSession(const std::string& atmId, const std::string& sessionId) override;

    bool owns(const LogEntry& intent) const override;
    std::optional<LogEvent> resolve(const LogEntry& intent) override;
};
