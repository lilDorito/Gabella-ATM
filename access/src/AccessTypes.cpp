#include "access/AccessTypes.h"

const char* approvalResultToString(ApprovalResult r)
{
    switch (r)
    {
    case ApprovalResult::Approved: return "Approved";
    case ApprovalResult::StillPending: return "StillPending";
    case ApprovalResult::AlreadyApproved: return "AlreadyApproved";
    case ApprovalResult::NotEligible: return "NotEligible";
    case ApprovalResult::Expired: return "Expired";
    case ApprovalResult::UnknownRequest: return "UnknownRequest";
    case ApprovalResult::AuditUnavailable: return "AuditUnavailable";
    }
    return "";
}

const char* requestStatusToString(RequestStatus s)
{
    switch (s)
    {
    case RequestStatus::Pending: return "Pending";
    case RequestStatus::Approved: return "Approved";
    case RequestStatus::Executed: return "Executed";
    case RequestStatus::Expired: return "Expired";
    }
    return "";
}
