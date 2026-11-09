#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "common/AccessTypes.h"
#include "common/AuthRequest.h"
#include "common/Checkpoint.h"
#include "common/ServerMessages.h"

class IServerApi
{
public:
    virtual ~IServerApi() = default;

    [[nodiscard]] virtual AuthResponse authorize(const AuthRequest& request) = 0;
    [[nodiscard]] virtual bool reportDispense(const RequestHeader& header, const DispenseReport& report) = 0;
    [[nodiscard]] virtual bool syncStatus(const RequestHeader& header, const StatusReport& report) = 0;
    [[nodiscard]] virtual bool endSession(const RequestHeader& header, const std::string& sessionId) = 0;
    [[nodiscard]] virtual std::optional<StaffLoginResult> staffLogin(const RequestHeader& header, const StaffLoginRequest& request) = 0;
    [[nodiscard]] virtual bool staffLogout(const RequestHeader& header, const std::string& token) = 0;
    [[nodiscard]] virtual Decision decide(const RequestHeader& header, const AccessRequest& request) = 0;
    [[nodiscard]] virtual bool submitCheckpoint(const RequestHeader& header, const Checkpoint& checkpoint) = 0;
    [[nodiscard]] virtual std::optional<SignedCheckpoint> latestCheckpoint(const RequestHeader& header, const std::string& auditorToken) = 0;
    [[nodiscard]] virtual bool reportTamper(const RequestHeader& header) = 0;
    [[nodiscard]] virtual std::vector<SignedCommand> pollCommands(const RequestHeader& header) = 0;
    [[nodiscard]] virtual bool reportCommandResult(const RequestHeader& header, std::uint64_t commandSeq, bool ok) = 0;
};
