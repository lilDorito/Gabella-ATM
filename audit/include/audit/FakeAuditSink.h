#pragma once
#include <vector>

#include "audit/IAuditSink.h"

class FakeAuditSink final : public IAuditSink
{
private:
    std::vector<LogEvent> _events;
    bool _fail = false;

public:
    [[nodiscard]] bool record(const LogEvent& e) override
    {
        if (_fail) return false;
        _events.push_back(e);
        return true;
    }

    void setFail(bool fail) { _fail = fail; }
    const std::vector<LogEvent>& events() const { return _events; }
    void clear() { _events.clear(); }
};
