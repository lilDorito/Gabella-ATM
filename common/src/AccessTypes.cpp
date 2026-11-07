#include "common/AccessTypes.h"

const char* verdictToString(Verdict v)
{
    switch (v)
    {
    case Verdict::Allowed: return "Allowed";
    case Verdict::Denied: return "Denied";
    case Verdict::PendingApproval: return "PendingApproval";
    }
    return "";
}

const char* denyReasonToString(DenyReason r)
{
    switch (r)
    {
    case DenyReason::None: return "None";
    case DenyReason::NoSession: return "NoSession";
    case DenyReason::NotLoggedIn: return "NotLoggedIn";
    case DenyReason::NotPermitted: return "NotPermitted";
    case DenyReason::AtmOutOfService: return "AtmOutOfService";
    case DenyReason::AuditUnavailable: return "AuditUnavailable";
    }
    return "";
}
