#include "common/EventType.h"

const char* eventTypeToString(EventType t)
{
    switch (t) {
    case EventType::CARD_INSERTED: return "CARD_INSERTED";
    case EventType::CARD_REJECTED: return "CARD_REJECTED";
    case EventType::AUTH_REQUESTED: return "AUTH_REQUESTED";
    case EventType::AUTH_RESULT: return "AUTH_RESULT";
    case EventType::DISPENSE_REQUESTED: return "DISPENSE_REQUESTED";
    case EventType::DISPENSE_COMPLETED: return "DISPENSE_COMPLETED";
    case EventType::DISPENSE_FAILED: return "DISPENSE_FAILED";
    case EventType::CARD_RETURNED: return "CARD_RETURNED";
    case EventType::CARD_RETAINED: return "CARD_RETAINED";
    case EventType::SESSION_ABORTED: return "SESSION_ABORTED";
    case EventType::ILLEGAL_TRANSITION: return "ILLEGAL_TRANSITION";
    case EventType::TAMPER_DETECTED: return "TAMPER_DETECTED";
    case EventType::STAFF_LOGIN: return "STAFF_LOGIN";
    case EventType::STAFF_LOCKED: return "STAFF_LOCKED";
    case EventType::ACCESS_DENIED: return "ACCESS_DENIED";
    case EventType::DUAL_CONTROL_REQUESTED: return "DUAL_CONTROL_REQUESTED";
    case EventType::DUAL_CONTROL_APPROVED: return "DUAL_CONTROL_APPROVED";
    case EventType::DUAL_CONTROL_EXECUTED: return "DUAL_CONTROL_EXECUTED";
    case EventType::KEY_UPDATED: return "KEY_UPDATED";
    case EventType::AUTH_DECISION: return "AUTH_DECISION";
    case EventType::NONCE_REPLAY: return "NONCE_REPLAY";
    case EventType::COMMAND_ISSUED: return "COMMAND_ISSUED";
    case EventType::TX_COMMITTED: return "TX_COMMITTED";
    case EventType::TX_REVERSED: return "TX_REVERSED";
    case EventType::TX_UNCERTAIN: return "TX_UNCERTAIN";
    case EventType::AUDIT_ACCESS: return "AUDIT_ACCESS";
    case EventType::LOG_STARTED:  return "LOG_STARTED";
    case EventType::LOG_INTEGRITY_FAILURE: return "LOG_INTEGRITY_FAILURE";
    }
    return "";
}

std::optional<EventType> eventTypeFromString(std::string_view s)
{
    for (int i = 0; i <= static_cast<int>(EventType::LOG_INTEGRITY_FAILURE); ++i)
    {
        EventType t = static_cast<EventType>(i);
        if (s == eventTypeToString(t)) return t;
    }
    return std::nullopt;
}
