#pragma once
#include <stdexcept>
#include <string>

class DbError : public std::runtime_error
{
private:
    int _code;

public:
    DbError(int code, const std::string& message) : std::runtime_error("db: " + message), _code(code) {}

    int code() const { return _code; }
};
