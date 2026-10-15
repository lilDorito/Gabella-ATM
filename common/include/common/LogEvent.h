#pragma once
#include <optional>
#include <string>

#include "common/EventType.h"
#include "common/Money.h"
#include "common/Outcome.h"
#include "common/Role.h"

struct LogEvent
{
    EventType type = EventType::LOG_STARTED;
    Outcome outcome = Outcome::Info;
    std::string sessionId;
    Role actorRole = Role::System;
    std::string actorId;
    std::string maskedPan;
    std::optional<Money> amount;
    std::string details;
};
