#include "access/SessionRegistry.h"

#include "common/Invariant.h"

SessionRegistry::SessionRegistry(const IClock& clock, std::int64_t ttlSeconds) : _clock(clock), _ttlSeconds(ttlSeconds) { ATM_INVARIANT(_ttlSeconds > 0, "sessions: ttl must be positive"); }

void SessionRegistry::open(const std::string& sessionId)
{
    if (sessionId.empty()) return;
    _sessions[sessionId] = _clock.nowUnix() + _ttlSeconds;
}

void SessionRegistry::close(const std::string& sessionId) { _sessions.erase(sessionId); }

bool SessionRegistry::isOpen(const std::string& sessionId) const
{
    const auto it = _sessions.find(sessionId);
    return it != _sessions.end() && _clock.nowUnix() <= it->second;
}

void SessionRegistry::purgeExpired()
{
    const std::int64_t now = _clock.nowUnix();
    for (auto it = _sessions.begin(); it != _sessions.end();)
    {
        if (now > it->second)
            it = _sessions.erase(it);
        else
            ++it;
    }
}
