#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "atm/ServerMessages.h"
#include "common/AuthRequest.h"
#include "common/Checkpoint.h"

class IServerLink
{
public:
    virtual ~IServerLink() = default;

    [[nodiscard]] virtual std::optional<AuthResponse> authorize(const AuthRequest& request) = 0;
    virtual void reportDispense(const DispenseReport& report) = 0;
    [[nodiscard]] virtual bool flushPending() = 0;
    virtual std::vector<SignedCommand> pollCommands() = 0;
    virtual void reportCommandResult(std::uint64_t commandSeq, bool ok) = 0;
    virtual bool syncStatus(const StatusReport& report) = 0;
    virtual void endSession(const std::string& sessionId) = 0;
    virtual std::optional<StaffLoginResult> staffLogin(const std::string& staffId,
        const std::string& sealedPassword) = 0;
    virtual void staffLogout(const std::string& token) = 0;
    virtual void reportTamper() = 0;
    virtual std::optional<Checkpoint> latestCheckpoint() = 0;
};
