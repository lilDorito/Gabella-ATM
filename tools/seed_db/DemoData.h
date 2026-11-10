#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "common/Role.h"
#include "crypto/BankHsm.h"
#include "server/db/Database.h"

inline constexpr const char* kDemoStaffPassword = "S3cretPass";
inline constexpr const char* kDemoPinKey = "PINPINPINPINPIN1";

struct DemoCard
{
    std::string pan;
    std::string pin;
    std::string accountId;
    std::string owner;
    std::int64_t balanceKop = 0;
    int expMonth = 0;
    int expYear = 0;
    std::uint32_t failedPinAttempts = 0;
    bool blocked = false;
    std::string note;
};

struct DemoStaff
{
    std::string id;
    Role role = Role::Client;
};

const std::vector<DemoCard>& demoCards();
const std::vector<DemoStaff>& demoStaff();
const std::vector<std::string>& demoAtms();
const std::map<int, int>& demoCassettes();

void seedDatabase(Database& db, const BankHsm& hsm);
