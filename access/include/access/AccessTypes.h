#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "common/Action.h"
#include "common/Role.h"

inline constexpr const char* kAdminConsoleAtmId = "ADMIN-CONSOLE";

using RandomBytesFn = std::function<std::optional<std::string>(std::size_t)>;

enum class ApprovalResult
{
    Approved,
    StillPending,
    AlreadyApproved,
    NotEligible,
    Expired,
    UnknownRequest,
    AuditUnavailable
};

enum class RequestStatus
{
    Pending,
    Approved,
    Executed,
    Expired
};

struct StaffIdentity
{
    std::string staffId;
    Role role = Role::Client;
    std::string atmId;
};

struct CriticalRequest
{
    std::string requestId;
    Action action = Action::RestoreFromOutOfService;
    std::string params;
    std::string initiatorId;
    std::uint32_t requiredApprovals = 2;
    std::int64_t createdAt = 0;
    std::int64_t expiresAt = 0;
    RequestStatus status = RequestStatus::Pending;
    std::vector<std::string> approvers;
};

const char* approvalResultToString(ApprovalResult r);
const char* requestStatusToString(RequestStatus s);
