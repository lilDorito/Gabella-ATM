#include "atm/CounterStore.h"

#include <charconv>
#include <fstream>
#include <string>
#include <system_error>
#include <utility>

FileCounterStore::FileCounterStore(std::filesystem::path path) : _path(std::move(path))
{
    std::error_code ec;
    if (_path.has_parent_path()) std::filesystem::create_directories(_path.parent_path(), ec);
}

std::optional<std::uint64_t> FileCounterStore::load() const
{
    std::error_code ec;
    if (!std::filesystem::exists(_path, ec)) return ec ? std::nullopt : std::optional<std::uint64_t>(0);

    std::ifstream in(_path, std::ios::binary);
    std::string text;
    if (!in || !std::getline(in, text) || text.empty()) return std::nullopt;

    std::uint64_t value = 0;
    auto [ptr, err] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (err != std::errc() || ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

bool FileCounterStore::save(std::uint64_t value)
{
    std::filesystem::path tmp = _path;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out << value << '\n';
        out.flush();
        if (!out.good()) return false;
    }
    std::error_code ec;
    std::filesystem::rename(tmp, _path, ec);
    return !ec;
}

std::optional<std::uint64_t> InMemoryCounterStore::load() const
{
    if (_unreadable) return std::nullopt;
    return _value;
}

bool InMemoryCounterStore::save(std::uint64_t value)
{
    if (_failSaves) return false;
    _value = value;
    return true;
}
