#pragma once
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

class LogStorage
{
public:
    virtual ~LogStorage() = default;
    [[nodiscard]] virtual bool append(const std::string& line) = 0;
    virtual std::vector<std::string> readAll() const = 0;
};

class FileLogStorage final : public LogStorage
{
private:
    std::filesystem::path _path;
    std::ofstream _out;

public:
    explicit FileLogStorage(std::filesystem::path path);

    FileLogStorage(const FileLogStorage&) = delete;
    FileLogStorage& operator=(const FileLogStorage&) = delete;

    [[nodiscard]] bool append(const std::string& line) override;
    std::vector<std::string> readAll() const override;

    bool isOpen() const;
    const std::filesystem::path& path() const { return _path; }
};

class InMemoryLogStorage final : public LogStorage
{
private:
    std::vector<std::string> _lines;
    bool _failAppends = false;

public:
    [[nodiscard]] bool append(const std::string& line) override;
    std::vector<std::string> readAll() const override { return _lines; }

    void setFailAppends(bool fail) { _failAppends = fail; }
    std::vector<std::string>& lines() { return _lines; }
};
