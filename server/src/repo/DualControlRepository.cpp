#include "server/repo/DualControlRepository.h"

#include <exception>

#include "server/ActionNames.h"
#include "server/db/DbError.h"
#include "server/db/Statement.h"
#include "server/db/Transaction.h"

namespace
{
const char* kColumns = "request_id, action, params, initiator_id, required_approvals, created_at, expires_at, status";

CriticalRequest read(const Statement& s)
{
    const auto action = actionFromString(s.columnText(1));
    const auto status = DualControlRepository::statusFromColumn(s.columnText(7));
    if (!action || !status) throw DbError(0, "stored dual control request is not valid");

    CriticalRequest r;
    r.requestId = s.columnText(0);
    r.action = *action;
    r.params = s.columnText(2);
    r.initiatorId = s.columnText(3);
    r.requiredApprovals = static_cast<std::uint32_t>(s.columnInt64(4));
    r.createdAt = s.columnInt64(5);
    r.expiresAt = s.columnInt64(6);
    r.status = *status;
    return r;
}
}

const char* DualControlRepository::statusToColumn(RequestStatus status)
{
    switch (status)
    {
    case RequestStatus::Pending: return "PENDING";
    case RequestStatus::Approved: return "APPROVED";
    case RequestStatus::Executed: return "EXECUTED";
    case RequestStatus::Expired: return "EXPIRED";
    }
    return "";
}

std::optional<RequestStatus> DualControlRepository::statusFromColumn(const std::string& text)
{
    if (text == "PENDING") return RequestStatus::Pending;
    if (text == "APPROVED") return RequestStatus::Approved;
    if (text == "EXECUTED") return RequestStatus::Executed;
    if (text == "EXPIRED") return RequestStatus::Expired;
    return std::nullopt;
}

std::vector<std::string> DualControlRepository::approversOf(const std::string& requestId) const
{
    Statement s(_db, "SELECT staff_id FROM dual_control_approvals WHERE request_id = ? ORDER BY approved_at, rowid");
    s.bind(1, requestId);
    std::vector<std::string> out;
    while (s.step()) out.push_back(s.columnText(0));
    return out;
}

bool DualControlRepository::insertRequest(const CriticalRequest& r)
{
    Statement s(
        _db, "INSERT OR IGNORE INTO dual_control_requests (request_id, action, params, initiator_id, required_approvals, created_at, expires_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING')");
    s.bind(1, r.requestId)
        .bind(2, std::string(actionToString(r.action)))
        .bind(3, r.params)
        .bind(4, r.initiatorId)
        .bind(5, static_cast<std::int64_t>(r.requiredApprovals))
        .bind(6, r.createdAt)
        .bind(7, r.expiresAt)
        .run();
    return _db.changes() == 1;
}

bool DualControlRepository::insertApproval(const std::string& requestId, const std::string& staffId, std::int64_t approvedAt)
{
    Statement s(_db, "INSERT OR IGNORE INTO dual_control_approvals (request_id, staff_id, approved_at) VALUES (?, ?, ?)");
    s.bind(1, requestId).bind(2, staffId).bind(3, approvedAt).run();
    return _db.changes() == 1;
}

std::uint32_t DualControlRepository::countApprovals(const std::string& requestId) const
{
    Statement s(_db, "SELECT count(*) FROM dual_control_approvals WHERE request_id = ?");
    s.bind(1, requestId);
    return s.step() ? static_cast<std::uint32_t>(s.columnInt64(0)) : 0;
}

bool DualControlRepository::setStatus(const std::string& requestId, RequestStatus from, RequestStatus to)
{
    Statement s(_db, "UPDATE dual_control_requests SET status = ? WHERE request_id = ? AND status = ?");
    s.bind(1, std::string(statusToColumn(to))).bind(2, requestId).bind(3, std::string(statusToColumn(from))).run();
    return _db.changes() == 1;
}

bool DualControlRepository::setExpiresAt(const std::string& requestId, std::int64_t expiresAt)
{
    Statement s(_db, "UPDATE dual_control_requests SET expires_at = ? WHERE request_id = ?");
    s.bind(1, expiresAt).bind(2, requestId).run();
    return _db.changes() == 1;
}

std::optional<CriticalRequest> DualControlRepository::find(const std::string& requestId) const
{
    Statement s(_db, (std::string("SELECT ") + kColumns + " FROM dual_control_requests WHERE request_id = ?").c_str());
    s.bind(1, requestId);
    if (!s.step()) return std::nullopt;

    CriticalRequest r = read(s);
    r.approvers = approversOf(r.requestId);
    return r;
}

std::vector<CriticalRequest> DualControlRepository::listPending() const
{
    std::vector<CriticalRequest> out;
    {
        Statement s(_db, (std::string("SELECT ") + kColumns + " FROM dual_control_requests WHERE status = 'PENDING' ORDER BY created_at, request_id").c_str());
        while (s.step()) out.push_back(read(s));
    }
    for (CriticalRequest& r : out) r.approvers = approversOf(r.requestId);
    return out;
}

std::vector<CriticalRequest> DualControlRepository::listApproved() const
{
    std::vector<CriticalRequest> out;
    {
        Statement s(_db, (std::string("SELECT ") + kColumns + " FROM dual_control_requests WHERE status = 'APPROVED' ORDER BY created_at, request_id").c_str());
        while (s.step()) out.push_back(read(s));
    }
    for (CriticalRequest& r : out) r.approvers = approversOf(r.requestId);
    return out;
}

bool DualControlRepository::inTransaction(const std::function<bool()>& fn)
{
    // The caller may already be inside a transaction of ours; SQLite has no nested BEGIN.
    if (_depth > 0) return fn();

    try
    {
        Transaction tx(_db);
        ++_depth;
        bool ok = false;
        try
        {
            ok = fn();
        }
        catch (...)
        {
            --_depth;
            throw;
        }
        --_depth;
        if (!ok) return false;
        tx.commit();
        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
}
