#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "access/AccessTypes.h"
#include "common/Clock.h"
#include "common/Role.h"

class StaffTokenStore
{
private:
    struct Entry
    {
        StaffIdentity identity;
        std::int64_t issuedAt = 0;
        std::int64_t lastUsed = 0;
    };

    const IClock& _clock;
    RandomBytesFn _rnd;
    const std::int64_t _idleSeconds;
    const std::int64_t _maxSeconds;
    std::map<std::string, Entry> _tokens;

    bool isExpired(const Entry& e, std::int64_t now) const;

public:
    StaffTokenStore(const IClock& clock, RandomBytesFn rnd, std::int64_t idleSeconds = 900, std::int64_t maxSeconds = 28800);

    StaffTokenStore(const StaffTokenStore&) = delete;
    StaffTokenStore& operator=(const StaffTokenStore&) = delete;

    [[nodiscard]] std::string issue(const std::string& staffId, Role r, const std::string& atmId);
    [[nodiscard]] std::optional<StaffIdentity> resolve(const std::string& token);
    void revoke(const std::string& token);
    void purgeExpired();
    std::size_t activeCount() const { return _tokens.size(); }
};
