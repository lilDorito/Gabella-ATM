#pragma once
#include "audit/IAuditSink.h"

// For events whose actor id may come from the outside: if the log refuses the event (DataPolicy),
// it is recorded once more without the actor id.
inline bool recordBestEffort(IAuditSink& log, LogEvent e)
{
    if (log.record(e)) return true;
    e.actorId.clear();
    e.details += " actor_id=withheld";
    return log.record(e);
}
