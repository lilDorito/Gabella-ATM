#include "audit/LogEntry.h"

#include <utility>

LogEntry::LogEntry(std::uint64_t seqNo, std::int64_t timestamp, LogEvent event,
    std::string prevHash, std::string hash)
    : _seqNo(seqNo),
    _timestamp(timestamp),
    _event(std::move(event)),
    _prevHash(std::move(prevHash)),
    _hash(std::move(hash))
{}
