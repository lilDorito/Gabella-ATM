#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "access/IAccessDecider.h"
#include "common/AuthRequest.h"
#include "common/ServerMessages.h"

class IAuthorizationService
{
public:
    virtual ~IAuthorizationService() = default;

    [[nodiscard]] virtual AuthResponse authorize(const AuthRequest& request) = 0;
    [[nodiscard]] virtual bool endSession(const std::string& atmId, const std::string& sessionId) = 0;
};

class IReconciliationService
{
public:
    virtual ~IReconciliationService() = default;

    [[nodiscard]] virtual bool onDispenseReport(const DispenseReport& report) = 0;
    [[nodiscard]] virtual bool onStatusReport(const StatusReport& report) = 0;
};

class IStaffService
{
public:
    virtual ~IStaffService() = default;

    [[nodiscard]] virtual std::optional<StaffLoginResult> staffLogin(const StaffLoginRequest& request) = 0;
    virtual void staffLogout(const std::string& token) = 0;
};

class ICommandService
{
public:
    virtual ~ICommandService() = default;

    [[nodiscard]] virtual std::vector<SignedCommand> pollCommands(const std::string& atmId) = 0;
    [[nodiscard]] virtual bool reportCommandResult(const std::string& atmId, std::uint64_t commandSeq, bool ok) = 0;
};

class UnavailableServices final : public IAuthorizationService, public IReconciliationService, public IStaffService, public ICommandService, public IAccessDecider
{
public:
    AuthResponse authorize(const AuthRequest& request) override;
    bool endSession(const std::string& atmId, const std::string& sessionId) override;
    bool onDispenseReport(const DispenseReport& report) override;
    bool onStatusReport(const StatusReport& report) override;
    std::optional<StaffLoginResult> staffLogin(const StaffLoginRequest& request) override;
    void staffLogout(const std::string& token) override;
    std::vector<SignedCommand> pollCommands(const std::string& atmId) override;
    bool reportCommandResult(const std::string& atmId, std::uint64_t commandSeq, bool ok) override;
    Decision decide(const AccessRequest& request) override;
};
