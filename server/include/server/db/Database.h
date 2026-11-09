#pragma once
#include <cstdint>
#include <string>

struct sqlite3;

enum class OpenMode
{
    ReadWrite,
    ReadOnly
};

class Database
{
private:
    sqlite3* _db = nullptr;

    void ensureSchema();

public:
    explicit Database(const std::string& path, OpenMode mode = OpenMode::ReadWrite);
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    Database(Database&&) = delete;
    Database& operator=(Database&&) = delete;

    void exec(const char* sql);
    sqlite3* handle() const { return _db; }
    std::int64_t lastInsertRowId() const;
    int changes() const;
    int schemaVersion() const;
};
