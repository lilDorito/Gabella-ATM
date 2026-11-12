#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "common/Role.h"
#include "server/db/Database.h"

struct StaffRecord
{
    std::string staffId;
    Role role = Role::Client;
    std::string passwordHash;
    std::uint32_t failedLogins = 0;
    std::int64_t lockedUntil = 0;
    bool active = true;
};

struct LoginFailure
{
    std::uint32_t attempts = 0;
    bool locked = false;
    std::int64_t lockedUntil = 0;
};

class StaffRepository
{
private:
    Database& _db;

public:
    explicit StaffRepository(Database& db) : _db(db) {}

    static const char* roleToColumn(Role role);
    static std::optional<Role> roleFromColumn(const std::string& text);

    void insert(const StaffRecord& staff);
    std::optional<StaffRecord> find(const std::string& staffId) const;

    // One statement: a failure that arrives after an expired lock starts the count from 1.
    // The lock is set when the count reaches maxFailures and is not extended by later attempts.
    LoginFailure recordFailure(const std::string& staffId, std::int64_t now, std::uint32_t maxFailures, std::int64_t lockoutSeconds);
    void resetFailures(const std::string& staffId);

    std::uint32_t countActiveAdmins() const;
};
