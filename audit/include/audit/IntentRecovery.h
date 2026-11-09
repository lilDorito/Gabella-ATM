#pragma once
#include <cstddef>
#include <optional>
#include <vector>

#include "audit/IAuditSink.h"
#include "audit/LogEntry.h"
#include "audit/LogVerifier.h"

class IIntentResolver
{
public:
    virtual ~IIntentResolver() = default;

    virtual bool owns(const LogEntry& intent) const = 0;
    virtual std::optional<LogEvent> resolve(const LogEntry& intent) = 0;
};

struct RecoveryReport
{
    std::size_t open = 0;
    std::size_t resolved = 0;
    std::size_t unowned = 0;
    std::size_t failed = 0;
};

class IntentRecovery
{
private:
    const LogVerifier& _verifier;
    IAuditSink& _log;

public:
    IntentRecovery(const LogVerifier& verifier, IAuditSink& log) : _verifier(verifier), _log(log) {}

    RecoveryReport run(const std::vector<IIntentResolver*>& resolvers);
};
