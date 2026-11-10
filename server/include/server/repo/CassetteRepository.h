#pragma once
#include <map>
#include <string>

#include "server/db/Database.h"

class CassetteRepository
{
private:
    Database& _db;

public:
    explicit CassetteRepository(Database& db) : _db(db) {}

    static bool isValidDenomination(int denomination);

    std::map<int, int> expected(const std::string& atmId) const;
    void replace(const std::string& atmId, const std::map<int, int>& counts);
};
