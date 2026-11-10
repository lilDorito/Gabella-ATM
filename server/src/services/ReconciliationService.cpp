#include "server/services/ReconciliationService.h"

#include <charconv>
#include <vector>

#include "common/AccessTypes.h"
#include "common/EventType.h"
#include "common/Money.h"
#include "server/db/DbError.h"
#include "server/db/Transaction.h"

namespace
{
constexpr const char* kBy = "reconciliation";
constexpr const char* kOpPrefix = "tx/";
constexpr int kDenominations[] = { 100, 200, 500, 1000 };
constexpr int kMaxCount = 1000000;

bool validCounts(const std::map<int, int>& counts)
{
    for (const auto& [denomination, count] : counts)
    {
        if (!CassetteRepository::isValidDenomination(denomination) || count < 0 || count > kMaxCount) return false;
    }
    return true;
}

int countOf(const std::map<int, int>& counts, int denomination)
{
    const auto it = counts.find(denomination);
    return it == counts.end() ? 0 : it->second;
}

std::map<int, int> normalised(const std::map<int, int>& counts)
{
    std::map<int, int> out;
    for (int denomination : kDenominations) out[denomination] = countOf(counts, denomination);
    return out;
}

std::int64_t valueOf(const std::map<int, int>& counts)
{
    std::int64_t total = 0;
    for (int denomination : kDenominations) total += static_cast<std::int64_t>(denomination) * countOf(counts, denomination);
    return total;
}

std::optional<std::int64_t> decreaseValue(const std::map<int, int>& expected, const std::map<int, int>& reported)
{
    std::int64_t decrease = 0;
    for (int denomination : kDenominations)
    {
        const int before = countOf(expected, denomination);
        const int after = countOf(reported, denomination);
        if (after > before) return std::nullopt;
        decrease += static_cast<std::int64_t>(denomination) * (before - after);
    }
    return decrease;
}

bool sameCounts(const std::map<int, int>& a, const std::map<int, int>& b)
{
    for (int denomination : kDenominations)
    {
        if (countOf(a, denomination) != countOf(b, denomination)) return false;
    }
    return true;
}

EventType eventFor(TxStatus status)
{
    switch (status)
    {
    case TxStatus::Committed: return EventType::TX_COMMITTED;
    case TxStatus::Reversed: return EventType::TX_REVERSED;
    default: return EventType::TX_UNCERTAIN;
    }
}

LogEvent txEvent(EventType type, Outcome outcome, const TxRecord& tx, const std::string& reason)
{
    LogEvent e;
    e.type = type;
    e.outcome = outcome;
    e.sessionId = tx.sessionId;
    e.actorRole = Role::System;
    e.actorId = tx.atmId;
    e.amount = Money::fromKop(tx.amountKop);
    e.details = "tx=" + std::to_string(tx.id) + " seq=" + std::to_string(tx.dispenseSeq) + " by=" + kBy + " reason=" + reason;
    return e;
}

LogEvent noteEvent(EventType type, Outcome outcome, const std::string& atmId, const std::string& details)
{
    LogEvent e;
    e.type = type;
    e.outcome = outcome;
    e.actorRole = Role::System;
    e.actorId = atmId;
    e.details = details;
    return e;
}

void recordBestEffort(IAuditSink& log, LogEvent e)
{
    try
    {
        if (log.record(e)) return;
        e.actorId.clear();
        e.details += " actor_id=withheld";
        (void)log.record(e);
    }
    catch (...)
    {
    }
}

struct IntentTarget
{
    std::int64_t txId = 0;
    TxStatus status = TxStatus::Held;
};

std::optional<IntentTarget> parseOpId(const std::string& opId)
{
    const std::string prefix = kOpPrefix;
    if (opId.compare(0, prefix.size(), prefix) != 0) return std::nullopt;

    const std::size_t slash = opId.find('/', prefix.size());
    if (slash == std::string::npos || slash == prefix.size()) return std::nullopt;

    IntentTarget target;
    const char* first = opId.data() + prefix.size();
    const char* last = opId.data() + slash;
    auto [ptr, ec] = std::from_chars(first, last, target.txId);
    if (ec != std::errc() || ptr != last) return std::nullopt;

    const auto status = txStatusFromString(opId.substr(slash + 1));
    if (!status || *status == TxStatus::Held) return std::nullopt;
    target.status = *status;
    return target;
}
}

ReconciliationService::ReconciliationService(Database& db,
    TxRepository& txs,
    AccountRepository& accounts,
    CassetteRepository& cassettes,
    IAccessDecider& access,
    IAuditSink& log,
    const IClock& clock,
    const SystemConfig& config)
    : _db(db),
      _txs(txs),
      _accounts(accounts),
      _cassettes(cassettes),
      _access(access),
      _log(log),
      _clock(clock),
      _config(config)
{
}

std::string ReconciliationService::opIdFor(std::int64_t txId, TxStatus to) { return std::string(kOpPrefix) + std::to_string(txId) + "/" + txStatusToString(to); }

bool ReconciliationService::refuse(const std::string& atmId, const char* call, const std::string& reason)
{
    recordBestEffort(_log, noteEvent(EventType::AUTH_DECISION, Outcome::Failure, atmId, "reason=" + reason + " call=" + call));
    return false;
}

bool ReconciliationService::contradiction(const TxRecord& tx, const std::string& reason)
{
    recordBestEffort(_log, txEvent(eventFor(tx.status), Outcome::Failure, tx, "contradicting_report=" + reason));
    return false;
}

void ReconciliationService::noteMismatch(const std::string& atmId, const char* call, const std::map<int, int>& expected, const std::map<int, int>& reported)
{
    recordBestEffort(_log,
        noteEvent(EventType::AUTH_DECISION, Outcome::Failure, atmId,
            std::string("reason=cassette_mismatch call=") + call + " expected_value=" + std::to_string(valueOf(expected)) + " reported_value=" + std::to_string(valueOf(reported))));
}

bool ReconciliationService::settle(const TxRecord& tx, TxStatus to, const std::string& reason, const std::map<int, int>* newExpected)
{
    LogEvent intent = txEvent(eventFor(to), Outcome::Info, tx, reason);
    intent.opId = opIdFor(tx.id, to);
    if (!_log.record(intent)) return false;

    LogEvent result = intent;
    bool ok = false;
    try
    {
        Transaction dbtx(_db);
        ok = _txs.setStatus(tx.id, to, _clock.nowUnix(), kBy, reason);
        if (ok && to == TxStatus::Committed) ok = _accounts.debit(tx.accountId, tx.amountKop);
        if (ok && newExpected) _cassettes.replace(tx.atmId, normalised(*newExpected));
        if (ok) dbtx.commit();
    }
    catch (const DbError&)
    {
        ok = false;
    }

    result.outcome = ok ? Outcome::Success : Outcome::Failure;
    if (!ok) result.details += " failure=not_applied";
    (void)_log.record(result);
    return ok;
}

bool ReconciliationService::markUncertain(const TxRecord& tx, const std::string& reason)
{
    if (tx.status != TxStatus::Held)
    {
        recordBestEffort(_log, txEvent(EventType::TX_UNCERTAIN, Outcome::Failure, tx, reason));
        return true;
    }
    return settle(tx, TxStatus::Uncertain, reason, nullptr);
}

std::size_t ReconciliationService::tick()
{
    const std::int64_t cutoff = _clock.nowUnix() - _config.uncertainAfterSeconds;
    std::size_t moved = 0;
    for (const TxRecord& tx : _txs.findHeldOlderThan(cutoff))
    {
        if (settle(tx, TxStatus::Uncertain, "no_report_in_time", nullptr)) ++moved;
    }
    return moved;
}

bool ReconciliationService::hasUnresolved(const std::string& atmId) const { return !_txs.findOpenByAtm(atmId).empty(); }

bool ReconciliationService::onDispenseReport(const DispenseReport& report)
{
    (void)tick();

    if (!validCounts(report.cassetteCounts)) return refuse(report.atmId, "ReportDispense", "invalid_counters");

    const auto tx = _txs.findBySeq(report.atmId, report.sequence);
    if (!tx) return refuse(report.atmId, "ReportDispense", "unknown_transaction");
    if (tx->sessionId != report.sessionId) return refuse(report.atmId, "ReportDispense", "session_mismatch");

    const bool claimedOk = report.result == DispenseResult::Ok;

    if (tx->status == TxStatus::Committed) return claimedOk ? true : contradiction(*tx, "failure_after_commit");
    if (tx->status == TxStatus::Reversed) return claimedOk ? contradiction(*tx, "dispensed_after_reversal") : true;

    const auto expected = _cassettes.expected(tx->atmId);
    const auto decrease = decreaseValue(expected, report.cassetteCounts);
    const std::int64_t amount = tx->amountKop / 100;

    if (decrease && claimedOk && *decrease == amount) return settle(*tx, TxStatus::Committed, "dispensed_confirmed_by_counters", &report.cassetteCounts);
    if (decrease && !claimedOk && *decrease == 0) return settle(*tx, TxStatus::Reversed, "failure_confirmed_by_counters", nullptr);

    noteMismatch(tx->atmId, "ReportDispense", expected, report.cassetteCounts);
    return markUncertain(*tx, claimedOk ? "report_ok_counters_disagree" : "report_failed_counters_disagree");
}

bool ReconciliationService::onStatusReport(const StatusReport& report)
{
    (void)tick();

    if (!validCounts(report.cassetteCounts)) return refuse(report.atmId, "SyncStatus", "invalid_counters");

    switch (report.reason)
    {
    case StatusReason::Reconnect: return reconnect(report);
    case StatusReason::CashLoaded: return staffReport(report, Action::LoadCash);
    case StatusReason::CashCollected: return staffReport(report, Action::CollectCash);
    }
    return false;
}

bool ReconciliationService::reconnect(const StatusReport& report)
{
    const auto expected = _cassettes.expected(report.atmId);
    const auto open = _txs.findOpenByAtm(report.atmId);
    const std::int64_t now = _clock.nowUnix();
    const std::int64_t commandDeadline = _config.dispenseCommandLifetimeSeconds + _config.requestWindowSeconds;

    bool ok = true;
    std::vector<TxRecord> executed;
    for (const TxRecord& tx : open)
    {
        if (tx.dispenseSeq > report.lastExecutedSequence)
        {
            if (now > tx.createdAt + commandDeadline) ok = settle(tx, TxStatus::Reversed, "sequence_not_reached", nullptr) && ok;
        }
        else
        {
            executed.push_back(tx);
        }
    }

    if (executed.empty())
    {
        if (open.empty() && !sameCounts(expected, report.cassetteCounts)) noteMismatch(report.atmId, "SyncStatus", expected, report.cassetteCounts);
        return ok;
    }

    std::int64_t total = 0;
    for (const TxRecord& tx : executed) total += tx.amountKop / 100;

    const auto decrease = decreaseValue(expected, report.cassetteCounts);
    if (decrease && *decrease == 0)
    {
        for (const TxRecord& tx : executed) ok = settle(tx, TxStatus::Reversed, "counters_unchanged", nullptr) && ok;
    }
    else if (decrease && *decrease == total)
    {
        for (const TxRecord& tx : executed) ok = settle(tx, TxStatus::Committed, "counters_show_dispense", &report.cassetteCounts) && ok;
    }
    else
    {
        noteMismatch(report.atmId, "SyncStatus", expected, report.cassetteCounts);
        for (const TxRecord& tx : executed) ok = markUncertain(tx, "counters_inconclusive") && ok;
    }
    return ok;
}

bool ReconciliationService::authorised(const std::string& atmId, const std::string& token, Action action)
{
    if (token.empty()) return false;

    AccessRequest request;
    request.atmId = atmId;
    request.staffToken = token;
    request.action = action;

    try
    {
        return _access.decide(request).verdict == Verdict::Allowed;
    }
    catch (...)
    {
        return false;
    }
}

bool ReconciliationService::staffReport(const StatusReport& report, Action action)
{
    if (!authorised(report.atmId, report.staffToken, action))
    {
        recordBestEffort(_log, noteEvent(EventType::ACCESS_DENIED, Outcome::Failure, report.atmId, std::string("reason=not_permitted call=SyncStatus action=") + actionToString(action)));
        return false;
    }

    const bool collected = action == Action::CollectCash;
    const auto expected = _cassettes.expected(report.atmId);
    const std::map<int, int> updated = collected ? normalised({}) : normalised(report.cassetteCounts);

    LogEvent e = noteEvent(EventType::AUDIT_ACCESS, Outcome::Info, report.atmId,
        std::string("action=") + actionToString(action) + " expected_value=" + std::to_string(valueOf(expected)) + " reported_value=" + std::to_string(valueOf(report.cassetteCounts)));
    e.actorRole = collected ? Role::CashCollector : Role::ServiceEngineer;
    if (collected && !sameCounts(expected, report.cassetteCounts))
    {
        e.outcome = Outcome::Failure;
        e.details += " mismatch=yes";
    }
    if (!_log.record(e)) return false;

    try
    {
        Transaction dbtx(_db);
        _cassettes.replace(report.atmId, updated);
        dbtx.commit();
    }
    catch (const DbError&)
    {
        recordBestEffort(_log, noteEvent(EventType::AUDIT_ACCESS, Outcome::Failure, report.atmId, std::string("action=") + actionToString(action) + " failure=not_applied"));
        return false;
    }
    return true;
}

bool ReconciliationService::owns(const LogEntry& intent) const
{
    const EventType type = intent.getEvent().type;
    const bool txEventType = type == EventType::TX_COMMITTED || type == EventType::TX_REVERSED || type == EventType::TX_UNCERTAIN;
    return txEventType && parseOpId(intent.getEvent().opId).has_value();
}

std::optional<LogEvent> ReconciliationService::resolve(const LogEntry& intent)
{
    const auto target = parseOpId(intent.getEvent().opId);
    if (!target) return std::nullopt;

    const auto tx = _txs.findById(target->txId);
    bool applied = false;
    if (tx)
    {
        if (target->status == TxStatus::Uncertain)
            applied = tx->status != TxStatus::Held;
        else
            applied = tx->status == target->status;
    }

    LogEvent result = intent.getEvent();
    result.outcome = applied ? Outcome::Success : Outcome::Failure;
    result.details += applied ? " recovered=applied" : " recovered=absent";
    return result;
}
