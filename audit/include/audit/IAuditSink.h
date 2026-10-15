#pragma once
#include "common/LogEvent.h"

class IAuditSink
{
public:
    virtual ~IAuditSink() = default;
    [[nodiscard]] virtual bool record(const LogEvent& e) = 0;
};
