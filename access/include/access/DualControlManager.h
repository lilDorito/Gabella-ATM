#pragma once
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "access/AccessTypes.h"
#include "access/ApprovalPolicy.h"
#include "access/IDualControlRepository.h"
#include "audit/IAuditSink.h"
#include "common/Clock.h"
#include "common/EventType.h"
#include "common/Outcome.h"
#include "common/Role.h"

class DualControlManager
{
public:
    using ActiveAdminsFn = std::function<std::uint32_t()>;

private:
    IDualControlRepository& _repo;
    const ApprovalPolicy& _policy;
    const IClock& _clock;
    IAuditSink& _sink;
    RandomBytesFn _rnd;
    ActiveAdminsFn _activeAdmins;

    bool log(EventType type, Outcome outcome, Role role, const std::string& actorId,
        const std::string& details);
    CriticalRequest withEffectiveStatus(CriticalRequest r) const;

public:
    DualControlManager(IDualControlRepository& repo, const ApprovalPolicy& policy,
        const IClock& clock, IAuditSink& sink, RandomBytesFn rnd, ActiveAdminsFn activeAdmins);

    DualControlManager(const DualControlManager&) = delete;
    DualControlManager& operator=(const DualControlManager&) = delete;

    bool requiresApproval(Action a) const { return _policy.isCritical(a); }

    [[nodiscard]] std::optional<std::string> open(const std::string& initiatorId, Action a,
        const std::string& params);

    [[nodiscard]] ApprovalResult approve(const std::string& requestId, const std::string& approverId);

    [[nodiscard]] bool markExecuted(const std::string& requestId);

    [[nodiscard]] std::optional<CriticalRequest> get(const std::string& requestId) const;

    [[nodiscard]] std::optional<CriticalRequest> getApproved(const std::string& requestId,
        Action a, const std::string& params) const;

    [[nodiscard]] std::vector<CriticalRequest> listPending() const;
};