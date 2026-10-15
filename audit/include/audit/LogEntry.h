#pragma once
#include <cstdint>
#include <string>

#include "common/LogEvent.h"

class LogEntry
{
private:
    std::uint64_t _seqNo;
    std::int64_t _timestamp;
    LogEvent _event;
    std::string _prevHash;
    std::string _hash;

public:
    LogEntry(std::uint64_t seqNo, std::int64_t timestamp, LogEvent event,
        std::string prevHash, std::string hash);

    std::uint64_t getSeqNo() const { return _seqNo; }
    std::int64_t getTimestamp() const { return _timestamp; }
    const LogEvent& getEvent() const { return _event; }
    const std::string& getPrevHash() const { return _prevHash; }
    const std::string& getHash() const { return _hash; }
};
