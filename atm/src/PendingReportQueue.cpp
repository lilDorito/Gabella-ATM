#include "atm/PendingReportQueue.h"

#include <charconv>
#include <fstream>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "common/Canonical.h"
#include "common/Hex.h"
#include "common/Invariant.h"

namespace
{
constexpr const char* kTag = "PEND:";

template <typename T>
std::optional<T> parseNumber(const std::string& text)
{
    if (text.empty()) return std::nullopt;

    T value{};
    auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc() || ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

std::string encodeCounts(const std::map<int, int>& counts)
{
    std::string out;
    for (const auto& [denomination, count] : counts)
    {
        if (!out.empty()) out += ",";
        out += std::to_string(denomination) + "x" + std::to_string(count);
    }
    return out;
}

std::optional<std::map<int, int>> decodeCounts(const std::string& text)
{
    std::map<int, int> counts;
    std::size_t start = 0;
    while (start < text.size())
    {
        std::size_t end = text.find(',', start);
        if (end == std::string::npos) end = text.size();

        const std::string part = text.substr(start, end - start);
        const std::size_t x = part.find('x');
        if (x == std::string::npos) return std::nullopt;

        const auto denomination = parseNumber<int>(part.substr(0, x));
        const auto count = parseNumber<int>(part.substr(x + 1));
        if (!denomination || !count) return std::nullopt;

        counts[*denomination] = *count;
        start = end + 1;
    }
    return counts;
}

std::string serialize(const PendingReport& r)
{
    std::vector<std::string> fields;
    switch (r.kind)
    {
    case PendingKind::DispenseReport:
        fields = { "D", r.dispense.atmId, r.dispense.sessionId, std::to_string(r.dispense.sequence), std::to_string(static_cast<int>(r.dispense.result)), encodeCounts(r.dispense.cassetteCounts),
            std::to_string(r.dispense.timestamp) };
        break;
    case PendingKind::CommandResult: fields = { "R", std::to_string(r.commandSeq), r.commandOk ? "1" : "0" }; break;
    case PendingKind::Checkpoint: fields = { "C", r.checkpoint.logId, std::to_string(r.checkpoint.seqNo), r.checkpoint.hash, std::to_string(r.checkpoint.timestamp), r.checkpoint.mac }; break;
    }
    return toHex(canonicalEncode(kTag, fields));
}

std::optional<PendingReport> deserialize(const std::string& line)
{
    const auto bytes = fromHex(line);
    if (!bytes) return std::nullopt;

    const auto fields = canonicalDecode(kTag, *bytes);
    if (!fields || fields->empty()) return std::nullopt;

    const std::vector<std::string>& f = *fields;
    PendingReport r;

    if (f[0] == "D" && f.size() == 7)
    {
        const auto sequence = parseNumber<std::uint64_t>(f[3]);
        const auto result = parseNumber<int>(f[4]);
        const auto counts = decodeCounts(f[5]);
        const auto timestamp = parseNumber<std::int64_t>(f[6]);
        if (!sequence || !result || !counts || !timestamp) return std::nullopt;
        if (*result < 0 || *result > static_cast<int>(DispenseResult::HardwareFault)) return std::nullopt;

        r.kind = PendingKind::DispenseReport;
        r.dispense.atmId = f[1];
        r.dispense.sessionId = f[2];
        r.dispense.sequence = *sequence;
        r.dispense.result = static_cast<DispenseResult>(*result);
        r.dispense.cassetteCounts = *counts;
        r.dispense.timestamp = *timestamp;
        return r;
    }

    if (f[0] == "R" && f.size() == 3)
    {
        const auto seq = parseNumber<std::uint64_t>(f[1]);
        if (!seq || (f[2] != "0" && f[2] != "1")) return std::nullopt;

        r.kind = PendingKind::CommandResult;
        r.commandSeq = *seq;
        r.commandOk = f[2] == "1";
        return r;
    }

    if (f[0] == "C" && f.size() == 6)
    {
        const auto seq = parseNumber<std::uint64_t>(f[2]);
        const auto timestamp = parseNumber<std::int64_t>(f[4]);
        if (!seq || !timestamp) return std::nullopt;

        r.kind = PendingKind::Checkpoint;
        r.checkpoint.logId = f[1];
        r.checkpoint.seqNo = *seq;
        r.checkpoint.hash = f[3];
        r.checkpoint.timestamp = *timestamp;
        r.checkpoint.mac = f[5];
        return r;
    }

    return std::nullopt;
}
}

PendingReportQueue::PendingReportQueue(std::filesystem::path path) : _path(std::move(path))
{
    std::error_code ec;
    if (_path.has_parent_path()) std::filesystem::create_directories(_path.parent_path(), ec);
}

bool PendingReportQueue::load()
{
    _items.clear();
    _skipped = 0;
    if (_path.empty()) return true;

    std::error_code ec;
    if (!std::filesystem::exists(_path, ec)) return !ec;

    std::ifstream in(_path, std::ios::binary);
    if (!in) return false;

    std::string line;
    while (std::getline(in, line))
    {
        if (line.empty()) continue;

        auto item = deserialize(line);
        if (item)
            _items.push_back(std::move(*item));
        else
            ++_skipped;
    }
    return _skipped == 0;
}

bool PendingReportQueue::push(PendingReport report)
{
    bool persisted = true;
    if (!_path.empty())
    {
        std::ofstream out(_path, std::ios::binary | std::ios::app);
        out << serialize(report) << '\n';
        out.flush();
        persisted = out.good();
    }
    _items.push_back(std::move(report));
    return persisted;
}

bool PendingReportQueue::rewrite(const std::deque<PendingReport>& items) const
{
    std::filesystem::path tmp = _path;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        for (const PendingReport& item : items) out << serialize(item) << '\n';
        out.flush();
        if (!out.good()) return false;
    }

    std::error_code ec;
    std::filesystem::rename(tmp, _path, ec);
    return !ec;
}

bool PendingReportQueue::erase(std::size_t index)
{
    if (index >= _items.size()) return false;

    if (!_path.empty())
    {
        std::deque<PendingReport> remaining = _items;
        remaining.erase(remaining.begin() + static_cast<std::ptrdiff_t>(index));
        if (!rewrite(remaining)) return false;
    }

    _items.erase(_items.begin() + static_cast<std::ptrdiff_t>(index));
    return true;
}

const PendingReport& PendingReportQueue::at(std::size_t index) const
{
    ATM_INVARIANT(index < _items.size(), "pending queue: index out of range");
    return _items[index];
}
