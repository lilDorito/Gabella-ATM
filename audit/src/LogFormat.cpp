#include "audit/LogFormat.h"

#include <charconv>
#include <cstring>
#include <vector>

#include "Hex.h"
#include "crypto/CryptoCore.h"

const char* const kLogFieldSeparator = "\xE2\x94\x82";
const char* const kTornEntryMarker = "torn_entry";

namespace {

constexpr std::size_t kFieldCount = 12;

std::size_t sepLen()
{
    return std::strlen(kLogFieldSeparator);
}

std::string escapeField(const std::string& in)
{
    const std::string sep = kLogFieldSeparator;
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i)
    {
        if (in.compare(i, sep.size(), sep) == 0)
        {
            out += "\\s";
            i += sep.size() - 1;
            continue;
        }
        switch (in[i]) {
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        default:   out.push_back(in[i]); break;
        }
    }
    return out;
}

std::optional<std::string> unescapeField(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i)
    {
        if (in[i] != '\\')
        {
            out.push_back(in[i]);
            continue;
        }
        if (i + 1 >= in.size()) return std::nullopt;
        switch (in[++i]) {
        case '\\': out.push_back('\\'); break;
        case 'n':  out.push_back('\n'); break;
        case 'r':  out.push_back('\r'); break;
        case 's':  out += kLogFieldSeparator; break;
        default:   return std::nullopt;
        }
    }
    return out;
}

std::vector<std::string> splitFields(const std::string& line)
{
    const std::string sep = kLogFieldSeparator;
    std::vector<std::string> fields;
    std::size_t start = 0;
    while (true)
    {
        std::size_t pos = line.find(sep, start);
        if (pos == std::string::npos)
        {
            fields.push_back(line.substr(start));
            return fields;
        }
        fields.push_back(line.substr(start, pos - start));
        start = pos + sep.size();
    }
}

template <typename T>
std::optional<T> parseInt(const std::string& s)
{
    if (s.empty()) return std::nullopt;
    T value{};
    const char* first = s.data();
    const char* last = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(first, last, value);
    if (ec != std::errc() || ptr != last) return std::nullopt;
    return value;
}

}

const std::string& genesisHash()
{
    static const std::string zeros(64, '0');
    return zeros;
}

bool isHashHex(const std::string& s)
{
    if (s.size() != 64) return false;
    for (char c : s)
    {
        bool digit = c >= '0' && c <= '9';
        bool lower = c >= 'a' && c <= 'f';
        if (!digit && !lower) return false;
    }
    return true;
}

std::string serializeEntry(std::uint64_t seq, std::int64_t ts, const LogEvent& e)
{
    const std::string sep = kLogFieldSeparator;
    std::string out;
    out += std::to_string(seq);
    out += sep + std::to_string(ts);
    out += sep + eventTypeToString(e.type);
    out += sep + outcomeToString(e.outcome);
    out += sep + escapeField(e.sessionId);
    out += sep + roleToString(e.actorRole);
    out += sep + escapeField(e.actorId);
    out += sep + escapeField(e.maskedPan);
    out += sep + (e.amount ? std::to_string(e.amount->kop()) : std::string());
    out += sep + escapeField(e.details);
    return out;
}

std::string computeEntryHash(const std::string& prevHash, const std::string& canonical)
{
    return toHex(CryptoCore::sha256(prevHash + canonical));
}

std::string formatEntryLine(const LogEntry& entry)
{
    const std::string sep = kLogFieldSeparator;
    return serializeEntry(entry.getSeqNo(), entry.getTimestamp(), entry.getEvent())
        + sep + entry.getPrevHash()
        + sep + entry.getHash();
}

std::optional<LogEntry> parseEntry(const std::string& line)
{
    if (line.empty() || sepLen() == 0) return std::nullopt;

    std::vector<std::string> raw = splitFields(line);
    if (raw.size() != kFieldCount) return std::nullopt;

    std::vector<std::string> f;
    f.reserve(raw.size());
    for (const auto& r : raw)
    {
        auto u = unescapeField(r);
        if (!u) return std::nullopt;
        f.push_back(std::move(*u));
    }

    auto seq = parseInt<std::uint64_t>(f[0]);
    auto ts = parseInt<std::int64_t>(f[1]);
    auto type = eventTypeFromString(f[2]);
    auto outcome = outcomeFromString(f[3]);
    auto role = roleFromString(f[5]);
    if (!seq || !ts || !type || !outcome || !role) return std::nullopt;

    LogEvent e;
    e.type = *type;
    e.outcome = *outcome;
    e.sessionId = f[4];
    e.actorRole = *role;
    e.actorId = f[6];
    e.maskedPan = f[7];
    if (!f[8].empty())
    {
        auto kop = parseInt<std::int64_t>(f[8]);
        if (!kop) return std::nullopt;
        e.amount = Money::fromKop(*kop);
        if (!e.amount) return std::nullopt;
    }
    e.details = f[9];

    if (!isHashHex(f[10]) || !isHashHex(f[11])) return std::nullopt;

    LogEntry entry(*seq, *ts, std::move(e), f[10], f[11]);
    if (formatEntryLine(entry) != line) return std::nullopt;
    return entry;
}
