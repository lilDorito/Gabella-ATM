#include "access/DualControlManager.h"

#include <algorithm>
#include <utility>

#include "common/Hex.h"
#include "common/Invariant.h"

namespace
{
std::string formatRequestId(const std::string& eightBytes)
{
    const std::string h = toHex(eightBytes);
    return "DC-" + h.substr(0, 4) + "-" + h.substr(4, 4) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4);
}
}

DualControlManager::DualControlManager(IDualControlRepository& repo, const ApprovalPolicy& policy, const IClock& clock, IAuditSink& sink, RandomBytesFn rnd, ActiveAdminsFn activeAdmins)
    : _repo(repo),
      _policy(policy),
      _clock(clock),
      _sink(sink),
      _rnd(std::move(rnd)),
      _activeAdmins(std::move(activeAdmins))
{
    ATM_INVARIANT(static_cast<bool>(_rnd), "dual control: random source must be set");
    ATM_INVARIANT(static_cast<bool>(_activeAdmins), "dual control: admin counter must be set");
}

bool DualControlManager::log(EventType type, Outcome outcome, Role role, const std::string& actorId, const std::string& details)
{
    LogEvent e;
    e.type = type;
    e.outcome = outcome;
    e.actorRole = role;
    e.actorId = actorId;
    e.details = details;
    return _sink.record(e);
}

CriticalRequest DualControlManager::withEffectiveStatus(CriticalRequest r) const
{
    const bool open = r.status == RequestStatus::Pending || r.status == RequestStatus::Approved;
    if (open && _clock.nowUnix() >= r.expiresAt) r.status = RequestStatus::Expired;
    return r;
}

std::optional<std::string> DualControlManager::open(const std::string& initiatorId, Action a, const std::string& params)
{
    if (initiatorId.empty() || !_policy.isCritical(a)) return std::nullopt;

    const std::uint32_t admins = _activeAdmins();
    const std::uint32_t required = _policy.requiredApprovals(admins);
    if (admins < required) return std::nullopt;

    const auto bytes = _rnd(8);
    if (!bytes || bytes->size() != 8) return std::nullopt;

    const std::int64_t now = _clock.nowUnix();

    CriticalRequest r;
    r.requestId = formatRequestId(*bytes);
    r.action = a;
    r.params = params;
    r.initiatorId = initiatorId;
    r.requiredApprovals = required;
    r.createdAt = now;
    r.expiresAt = now + _policy.ttlSeconds;
    r.status = RequestStatus::Pending;

    const std::string details = "request_id=" + r.requestId + " action=" + actionToString(a) + " required=" + std::to_string(required);
    if (!log(EventType::DUAL_CONTROL_REQUESTED, Outcome::Info, Role::Admin, initiatorId, details)) return std::nullopt;

    const bool stored = _repo.inTransaction([&] { return _repo.insertRequest(r) && _repo.insertApproval(r.requestId, initiatorId, now); });
    if (!stored) return std::nullopt;

    return r.requestId;
}

ApprovalResult DualControlManager::approve(const std::string& requestId, const std::string& approverId)
{
    if (approverId.empty()) return ApprovalResult::NotEligible;

    const auto req = _repo.find(requestId);
    if (!req) return ApprovalResult::UnknownRequest;

    const std::int64_t now = _clock.nowUnix();
    const bool already = std::find(req->approvers.begin(), req->approvers.end(), approverId) != req->approvers.end();

    if (req->status == RequestStatus::Expired) return ApprovalResult::Expired;
    if (req->status == RequestStatus::Pending && now >= req->expiresAt)
    {
        (void)_repo.setStatus(requestId, RequestStatus::Pending, RequestStatus::Expired);
        return ApprovalResult::Expired;
    }
    if (req->status != RequestStatus::Pending) return already ? ApprovalResult::AlreadyApproved : ApprovalResult::NotEligible;
    if (already) return ApprovalResult::AlreadyApproved;

    const std::size_t after = req->approvers.size() + 1;
    const std::string details = "request_id=" + requestId + " approvals=" + std::to_string(after) + "/" + std::to_string(req->requiredApprovals);
    if (!log(EventType::DUAL_CONTROL_APPROVED, Outcome::Info, Role::Admin, approverId, details)) return ApprovalResult::AuditUnavailable;

    ApprovalResult result = ApprovalResult::UnknownRequest;
    const bool committed = _repo.inTransaction(
        [&]
        {
            if (!_repo.insertApproval(requestId, approverId, now))
            {
                result = ApprovalResult::AlreadyApproved;
                return false;
            }
            if (_repo.countApprovals(requestId) >= req->requiredApprovals)
            {
                if (!_repo.setStatus(requestId, RequestStatus::Pending, RequestStatus::Approved) || !_repo.setExpiresAt(requestId, now + _policy.ttlSeconds))
                {
                    result = ApprovalResult::UnknownRequest;
                    return false;
                }
                result = ApprovalResult::Approved;
            }
            else
            {
                result = ApprovalResult::StillPending;
            }
            return true;
        });

    if (!committed) return result == ApprovalResult::AlreadyApproved ? result : ApprovalResult::UnknownRequest;
    return result;
}

bool DualControlManager::markExecuted(const std::string& requestId)
{
    const auto req = _repo.find(requestId);
    if (!req || req->status != RequestStatus::Approved) return false;
    if (_clock.nowUnix() >= req->expiresAt)
    {
        (void)_repo.setStatus(requestId, RequestStatus::Approved, RequestStatus::Expired);
        return false;
    }
    if (!log(EventType::DUAL_CONTROL_EXECUTED, Outcome::Success, Role::System, "", "request_id=" + requestId)) return false;

    return _repo.setStatus(requestId, RequestStatus::Approved, RequestStatus::Executed);
}

std::optional<CriticalRequest> DualControlManager::get(const std::string& requestId) const
{
    auto r = _repo.find(requestId);
    if (!r) return std::nullopt;
    return withEffectiveStatus(std::move(*r));
}

std::optional<CriticalRequest> DualControlManager::getApproved(const std::string& requestId, Action a, const std::string& params) const
{
    auto r = _repo.find(requestId);
    if (!r) return std::nullopt;
    if (r->status != RequestStatus::Approved || r->action != a || r->params != params) return std::nullopt;
    if (_clock.nowUnix() >= r->expiresAt) return std::nullopt;
    return r;
}

std::vector<CriticalRequest> DualControlManager::listPending() const
{
    std::vector<CriticalRequest> out;
    for (auto& r : _repo.listPending())
    {
        CriticalRequest eff = withEffectiveStatus(std::move(r));
        if (eff.status == RequestStatus::Pending) out.push_back(std::move(eff));
    }
    return out;
}
