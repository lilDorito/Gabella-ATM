#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "common/Action.h"
#include "common/Checkpoint.h"
#include "common/DispenseResult.h"
#include "common/Money.h"
#include "common/Role.h"

inline constexpr std::int64_t kDispenseCommandLifetimeSeconds = 60;

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
    std::int64_t expiresAt = 0;
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

    std::string signedPayload() const;
};

struct DispenseReport
{
    std::string atmId;
    std::string sessionId;
    std::uint64_t sequence = 0;
    DispenseResult result = DispenseResult::Ok;
    std::map<int, int> cassetteCounts;
    std::int64_t timestamp = 0;

    std::string payload() const;
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
    std::int64_t timestamp = 0;

    std::string payload() const;
};

struct SignedCommand
{
    std::string atmId;
    std::uint64_t commandSeq = 0;
    Action action = Action::RestoreFromOutOfService;
    std::string params;
    std::int64_t expiresAt = 0;
    std::string signature;

    std::string signedPayload() const;
};

struct StaffLoginRequest
{
    std::string atmId;
    std::string staffId;
    std::string nonce;
    std::int64_t timestamp = 0;
    std::string sealedPassword;

    std::string binding() const;
    std::string payload() const;
};

struct StaffLoginResult
{
    std::string token;
    Role role = Role::Client;
};

const char* authStatusToString(AuthStatus s);

enum class ApiCall
{
    ReportDispense,
    SyncStatus,
    EndSession,
    StaffLogin,
    StaffLogout,
    Decide,
    SubmitCheckpoint,
    LatestCheckpoint,
    ReportTamper,
    PollCommands,
    ReportCommandResult
};

const char* apiCallToString(ApiCall call);

struct RequestHeader
{
    std::string atmId;
    std::string nonce;
    std::int64_t timestamp = 0;
    std::string mac;

    std::string macPayload(ApiCall call, const std::string& body) const;
};

namespace ApiBody
{
std::string endSession(const std::string& sessionId);
std::string staffLogout(const std::string& token);
std::string latestCheckpoint(const std::string& auditorToken);
std::string commandResult(std::uint64_t commandSeq, bool ok);
std::string empty();
}

struct SignedCheckpoint
{
    Checkpoint checkpoint;
    std::string requestNonce;
    std::string signature;

    std::string signedPayload() const;
};
