#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "audit/LogEntry.h"
#include "common/LogEvent.h"

extern const char* const kLogFieldSeparator;
extern const char* const kTornEntryMarker;

const std::string& genesisHash();

bool isHashHex(const std::string& s);

std::string serializeEntry(std::uint64_t seq, std::int64_t ts, const LogEvent& e);

std::string computeEntryHash(const std::string& prevHash, const std::string& canonical);

std::string formatEntryLine(const LogEntry& entry);

std::optional<LogEntry> parseEntry(const std::string& line);
