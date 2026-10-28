#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "atm/DispenseResult.h"
#include "common/Action.h"
#include "common/Money.h"
#include "common/Role.h"

enum class AuthStatus
{
    Approved,
    WrongPin,
    CardBlocked,
    InsufficientFunds,
    LimitExceeded,
    Declined,
    Error
};

struct DispenseCommand
{
    std::string atmId;
    std::string sessionId;
    std::int64_t amountKop = 0;
    std::uint64_t sequence = 0;
    std::string signature;

    std::string signedPayload() const;
};

struct AuthResponse
{
    AuthStatus status = AuthStatus::Error;
    std::string sessionId;
    std::optional<Money> balance;
    std::optional<DispenseCommand> command;
    std::string signature;
};

struct DispenseReport
{
    std::string atmId;
    std::string sessionId;
    std::uint64_t sequence = 0;
    DispenseResult result = DispenseResult::Ok;
    std::map<int, int> cassetteCounts;
    std::string nonce;
    std::int64_t timestamp = 0;
    std::string mac;
};

enum class StatusReason
{
    Reconnect,
    CashLoaded,
    CashCollected
};

struct StatusReport
{
    std::string atmId;
    StatusReason reason = StatusReason::Reconnect;
    std::string staffToken;
    std::uint64_t lastExecutedSequence = 0;
    std::map<int, int> cassetteCounts;
    std::string nonce;
    std::int64_t timestamp = 0;
    std::string mac;
};

struct SignedCommand
{
    std::string atmId;
    std::uint64_t commandSeq = 0;
    Action action = Action::RestoreFromOutOfService;
    std::string params;
    std::string signature;

    std::string signedPayload() const;
};

struct StaffLoginResult
{
    std::string token;
    Role role = Role::Client;
};

const char* authStatusToString(AuthStatus s);
