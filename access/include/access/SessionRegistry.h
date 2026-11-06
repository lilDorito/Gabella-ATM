#pragma once
#include <cstdint>
#include <map>
#include <string>

#include "common/Clock.h"

class SessionRegistry
{
private:
    const IClock& _clock;
    const std::int64_t _ttlSeconds;
    std::map<std::string, std::int64_t> _sessions;

public:
    explicit SessionRegistry(const IClock& clock, std::int64_t ttlSeconds = 180);

    SessionRegistry(const SessionRegistry&) = delete;
    SessionRegistry& operator=(const SessionRegistry&) = delete;

    void open(const std::string& sessionId);
    void close(const std::string& sessionId);
    [[nodiscard]] bool isOpen(const std::string& sessionId) const;
    void purgeExpired();
};