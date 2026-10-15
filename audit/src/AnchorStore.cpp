#include "audit/AnchorStore.h"

#include <charconv>
#include <fstream>
#include <string>
#include <system_error>
#include <utility>

#include "Hex.h"
#include "audit/LogFormat.h"

namespace {

template <typename T>
std::optional<T> parseInt(const std::string& s)
{
    if (s.empty()) return std::nullopt;
    T value{};
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
    if (ec != std::errc() || ptr != s.data() + s.size()) return std::nullopt;
    return value;
}

}

FileAnchorStore::FileAnchorStore(std::filesystem::path path)
    : _path(std::move(path))
{
    std::error_code ec;
    if (_path.has_parent_path())
        std::filesystem::create_directories(_path.parent_path(), ec);
}

bool FileAnchorStore::save(const Checkpoint& cp)
{
    if (cp.logId.find('\n') != std::string::npos) return false;
    if (!isHashHex(cp.hash)) return false;

    std::filesystem::path tmp = _path;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out << cp.logId << '\n'
            << cp.seqNo << '\n'
            << cp.hash << '\n'
            << cp.timestamp << '\n'
            << toHex(cp.mac) << '\n';
        out.flush();
        if (!out.good()) return false;
    }

    std::error_code ec;
    std::filesystem::rename(tmp, _path, ec);
    return !ec;
}

std::optional<Checkpoint> FileAnchorStore::load() const
{
    std::ifstream in(_path, std::ios::binary);
    if (!in) return std::nullopt;

    std::string logId, seq, hash, ts, mac;
    if (!std::getline(in, logId) || !std::getline(in, seq) || !std::getline(in, hash)
        || !std::getline(in, ts) || !std::getline(in, mac))
        return std::nullopt;

    auto seqNo = parseInt<std::uint64_t>(seq);
    auto timestamp = parseInt<std::int64_t>(ts);
    auto macBytes = fromHex(mac);
    if (!seqNo || !timestamp || !macBytes || !isHashHex(hash)) return std::nullopt;

    Checkpoint cp;
    cp.logId = logId;
    cp.seqNo = *seqNo;
    cp.hash = hash;
    cp.timestamp = *timestamp;
    cp.mac = *macBytes;
    return cp;
}

bool InMemoryAnchorStore::save(const Checkpoint& cp)
{
    if (_failSaves) return false;
    _cp = cp;
    return true;
}
