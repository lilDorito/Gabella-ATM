#pragma once
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>

#include "common/Checkpoint.h"
#include "common/ServerMessages.h"

enum class PendingKind
{
    DispenseReport,
    CommandResult,
    Checkpoint
};

struct PendingReport
{
    PendingKind kind = PendingKind::DispenseReport;
    DispenseReport dispense;
    std::uint64_t commandSeq = 0;
    bool commandOk = false;
    Checkpoint checkpoint;
};

class PendingReportQueue
{
private:
    std::filesystem::path _path;
    std::deque<PendingReport> _items;
    std::size_t _skipped = 0;

    [[nodiscard]] bool rewrite(const std::deque<PendingReport>& items) const;

public:
    PendingReportQueue() = default;
    explicit PendingReportQueue(std::filesystem::path path);

    [[nodiscard]] bool load();
    [[nodiscard]] bool push(PendingReport report);
    [[nodiscard]] bool erase(std::size_t index);
    [[nodiscard]] bool pop() { return erase(0); }

    const PendingReport& at(std::size_t index) const;
    const PendingReport& front() const { return at(0); }
    bool empty() const { return _items.empty(); }
    std::size_t size() const { return _items.size(); }
    std::size_t skippedOnLoad() const { return _skipped; }
};
