#pragma once
#include "audit/IAuditSink.h"

inline bool recordBestEffort(IAuditSink& log, LogEvent e)
{
    if (log.record(e)) return true;
    e.actorId.clear();
    e.details += " actor_id=withheld";
    return log.record(e);
}
