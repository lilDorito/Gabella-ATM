#pragma once
#include <cstdint>
#include <string>

#include "server/db/Database.h"

struct sqlite3_stmt;

class Statement
{
private:
    Database& _db;
    sqlite3_stmt* _stmt = nullptr;

public:
    Statement(Database& db, const char* sql);
    ~Statement();

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    Statement(Statement&&) = delete;
    Statement& operator=(Statement&&) = delete;

    Statement& bind(int index, std::int64_t value);
    Statement& bind(int index, const std::string& value);
    Statement& bindNull(int index);

    [[nodiscard]] bool step();
    void run();
    void reset();

    std::int64_t columnInt64(int index) const;
    std::string columnText(int index) const;
    bool columnIsNull(int index) const;
};
