#include "audit/IntentRecovery.h"

#include <string>

RecoveryReport IntentRecovery::run(const std::vector<IIntentResolver*>& resolvers)
{
    RecoveryReport report;
    for (const LogEntry& intent : _verifier.openIntents())
    {
        ++report.open;
        IIntentResolver* owner = nullptr;
        for (IIntentResolver* r : resolvers)
        {
            if (r && r->owns(intent))
            {
                owner = r;
                break;
            }
        }
        if (!owner)
        {
            ++report.unowned;
            continue;
        }

        auto result = owner->resolve(intent);
        if (!result)
        {
            ++report.failed;
            continue;
        }
        result->opId = intent.getEvent().opId;
        if (result->outcome == Outcome::Info) result->outcome = Outcome::Failure;
        if (_log.record(*result))
            ++report.resolved;
        else
            ++report.failed;
    }

    if (report.unowned > 0)
    {
        LogEvent e;
        e.type = EventType::LOG_INTEGRITY_FAILURE;
        e.outcome = Outcome::Info;
        e.details = "reason=unowned_intents count=" + std::to_string(report.unowned);
        (void)_log.record(e);
    }
    return report;
}
