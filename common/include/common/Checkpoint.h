#pragma once
#include <cstdint>
#include <string>

struct Checkpoint
{
    std::string logId;
    std::uint64_t seqNo = 0;
    std::string hash;
    std::int64_t timestamp = 0;
    std::string mac;
};
