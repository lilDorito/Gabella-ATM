#pragma once
#include <cstdint>

struct SystemConfig
{
    std::uint32_t maxWrongPins = 3;
    std::uint32_t maxFailedStaffLogins = 5;
    std::int64_t staffLockoutSeconds = 15 * 60;
    std::int64_t staffTokenIdleSeconds = 15 * 60;
    std::int64_t staffTokenMaxSeconds = 8 * 60 * 60;
    std::int64_t clientSessionSeconds = 3 * 60;
    std::int64_t requestWindowSeconds = 60;
    std::int64_t nonceRetentionSeconds = 10 * 60;
    std::int64_t dispenseCommandLifetimeSeconds = 60;
    std::int64_t uncertainAfterSeconds = 2 * 60;
    std::int64_t manualResolutionAfterSeconds = 24 * 60 * 60;
    std::int64_t dualControlTtlSeconds = 30 * 60;
    std::int64_t maxWithdrawalKop = 10000 * 100;
    std::int64_t dailyWithdrawalLimitKop = 20000 * 100;
    std::int64_t withdrawalStepKop = 100 * 100;
    std::uint32_t checkpointInterval = 50;
};
