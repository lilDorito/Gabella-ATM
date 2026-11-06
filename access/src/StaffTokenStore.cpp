#include "access/StaffTokenStore.h"

#include <stdexcept>
#include <utility>
#include <vector>

#include "common/Invariant.h"

namespace
{

    std::string toHexLower(const std::string& bytes)
    {
        static const char* digits = "0123456789abcdef";
        std::string out;
        out.reserve(bytes.size() * 2);
        for (unsigned char c : bytes)
        {
            out.push_back(digits[c >> 4]);
            out.push_back(digits[c & 0x0F]);
        }
        return out;
    }

}

StaffTokenStore::StaffTokenStore(const IClock& clock, RandomBytesFn rnd,
    std::int64_t idleSeconds, std::int64_t maxSeconds)
    : _clock(clock), _rnd(std::move(rnd)), _idleSeconds(idleSeconds), _maxSeconds(maxSeconds)
{
    ATM_INVARIANT(static_cast<bool>(_rnd), "tokens: random source must be set");
    ATM_INVARIANT(_idleSeconds > 0 && _maxSeconds >= _idleSeconds, "tokens: invalid timeouts");
}

bool StaffTokenStore::isExpired(const Entry& e, std::int64_t now) const
{
    return now - e.issuedAt > _maxSeconds || now - e.lastUsed > _idleSeconds;
}

std::string StaffTokenStore::issue(const std::string& staffId, Role r, const std::string& atmId)
{
    const auto bytes = _rnd(16);
    if (!bytes || bytes->size() != 16) throw std::runtime_error("tokens: random source failed");

    std::string token = toHexLower(*bytes);
    ATM_INVARIANT(_tokens.count(token) == 0, "tokens: duplicate token");

    const std::int64_t now = _clock.nowUnix();
    Entry e;
    e.identity.staffId = staffId;
    e.identity.role = r;
    e.identity.atmId = atmId;
    e.issuedAt = now;
    e.lastUsed = now;
    _tokens.emplace(token, std::move(e));
    return token;
}

std::optional<StaffIdentity> StaffTokenStore::resolve(const std::string& token)
{
    const auto it = _tokens.find(token);
    if (it == _tokens.end()) return std::nullopt;

    const std::int64_t now = _clock.nowUnix();
    if (isExpired(it->second, now))
    {
        _tokens.erase(it);
        return std::nullopt;
    }

    it->second.lastUsed = now;
    return it->second.identity;
}

void StaffTokenStore::revoke(const std::string& token)
{
    _tokens.erase(token);
}

void StaffTokenStore::purgeExpired()
{
    const std::int64_t now = _clock.nowUnix();
    for (auto it = _tokens.begin(); it != _tokens.end();)
    {
        if (isExpired(it->second, now)) it = _tokens.erase(it);
        else ++it;
    }
}