#include "audit/LogStorage.h"

#include <system_error>
#include <utility>

namespace {

bool endsWithoutNewline(const std::filesystem::path& path)
{
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) return false;
    auto size = std::filesystem::file_size(path, ec);
    if (ec || size == 0) return false;

    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    in.seekg(-1, std::ios::end);
    char last = '\0';
    in.get(last);
    return last != '\n';
}

}

FileLogStorage::FileLogStorage(std::filesystem::path path)
    : _path(std::move(path))
{
    std::error_code ec;
    if (_path.has_parent_path())
        std::filesystem::create_directories(_path.parent_path(), ec);

    bool needsNewline = endsWithoutNewline(_path);
    _out.open(_path, std::ios::app | std::ios::binary);
    if (_out && needsNewline)
    {
        _out.put('\n');
        _out.flush();
    }
}

bool FileLogStorage::isOpen() const
{
    return _out.is_open() && _out.good();
}

bool FileLogStorage::append(const std::string& line)
{
    if (!isOpen()) return false;
    if (line.find('\n') != std::string::npos) return false;

    _out.write(line.data(), static_cast<std::streamsize>(line.size()));
    _out.put('\n');
    _out.flush();
    return _out.good();
}

std::vector<std::string> FileLogStorage::readAll() const
{
    std::vector<std::string> lines;
    std::ifstream in(_path, std::ios::binary);
    if (!in) return lines;

    std::string line;
    while (std::getline(in, line))
        lines.push_back(line);
    return lines;
}

bool InMemoryLogStorage::append(const std::string& line)
{
    if (_failAppends) return false;
    if (line.find('\n') != std::string::npos) return false;
    _lines.push_back(line);
    return true;
}
