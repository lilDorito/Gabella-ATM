#include "server/services/DisputeService.h"

#include <charconv>
#include <exception>

#include "server/services/CommandParams.h"

namespace
{
constexpr std::size_t kMaxReason = 200;

bool validReason(const std::string& reason)
{
    if (reason.empty() || reason.size() > kMaxReason) return false;
    for (char c : reason)
    {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) return false;
    }
    return true;
}

std::optional<std::string> field(const std::string& extra, const std::string& key, std::size_t& pos)
{
    const std::string prefix = key + "=";
    if (extra.compare(pos, prefix.size(), prefix) != 0) return std::nullopt;
    const std::size_t start = pos + prefix.size();
    const std::size_t bar = extra.find('|', start);
    pos = bar == std::string::npos ? extra.size() : bar + 1;
    return extra.substr(start, bar == std::string::npos ? std::string::npos : bar - start);
}
}

const char* resolveResultToString(ResolveResult result)
{
    switch (result)
    {
    case ResolveResult::Resolved: return "Resolved";
    case ResolveResult::AlreadyResolved: return "AlreadyResolved";
    case ResolveResult::NotApproved: return "NotApproved";
    case ResolveResult::NotAResolution: return "NotAResolution";
    case ResolveResult::BadParams: return "BadParams";
    case ResolveResult::Refused: return "Refused";
    case ResolveResult::Failed: return "Failed";
    }
    return "";
}

std::string DisputeService::resolvedBy(const std::string& requestId) { return "dual_control:" + requestId; }

std::optional<std::string> DisputeService::makeParams(const TxRecord& tx, bool commit, const std::string& reason)
{
    if (tx.id <= 0 || !validReason(reason)) return std::nullopt;
    return makeCommandParams(tx.atmId, "tx=" + std::to_string(tx.id) + "|decision=" + (commit ? "COMMIT" : "REVERSE") + "|reason=" + reason);
}

std::optional<Resolution> DisputeService::parseParams(const std::string& params)
{
    const auto target = parseCommandParams(params);
    if (!target) return std::nullopt;

    std::size_t pos = 0;
    const auto tx = field(target->extra, "tx", pos);
    const auto decision = tx ? field(target->extra, "decision", pos) : std::nullopt;
    const auto reason = decision ? field(target->extra, "reason", pos) : std::nullopt;
    if (!reason || pos != target->extra.size() || !validReason(*reason)) return std::nullopt;
    if (*decision != "COMMIT" && *decision != "REVERSE") return std::nullopt;

    Resolution r;
    r.atmId = target->atmId;
    r.commit = *decision == "COMMIT";
    r.reason = *reason;
    const char* first = tx->data();
    const char* last = tx->data() + tx->size();
    auto [ptr, ec] = std::from_chars(first, last, r.txId);
    if (ec != std::errc() || ptr != last || r.txId <= 0) return std::nullopt;
    return r;
}

std::vector<TxRecord> DisputeService::disputed() const
{
    try
    {
        return _reconciliation.disputed();
    }
    catch (const std::exception&)
    {
        return {};
    }
}

ResolveResult DisputeService::executeApproved(const std::string& requestId)
{
    try
    {
        const auto request = _dual.get(requestId);
        if (!request || request->action != Action::ResolveTransaction) return ResolveResult::NotAResolution;
        const auto resolution = parseParams(request->params);
        if (!resolution) return ResolveResult::BadParams;
        if (request->status == RequestStatus::Executed) return ResolveResult::AlreadyResolved;
        if (request->status != RequestStatus::Approved) return ResolveResult::NotApproved;

        const auto tx = _txs.findById(resolution->txId);
        if (!tx || tx->atmId != resolution->atmId) return ResolveResult::BadParams;

        const ManualResult outcome = _reconciliation.resolveManually(resolution->txId, resolution->commit, resolvedBy(requestId), resolution->reason);
        if (outcome != ManualResult::Resolved && outcome != ManualResult::AlreadyResolved) return ResolveResult::Refused;
        if (!_dual.markExecuted(requestId)) return ResolveResult::Failed;
        return outcome == ManualResult::Resolved ? ResolveResult::Resolved : ResolveResult::AlreadyResolved;
    }
    catch (const std::exception&)
    {
        return ResolveResult::Failed;
    }
}

std::size_t DisputeService::tick()
{
    std::size_t done = 0;
    try
    {
        for (const CriticalRequest& request : _requests.listApproved())
            if (request.action == Action::ResolveTransaction && executeApproved(request.requestId) == ResolveResult::Resolved) ++done;
    }
    catch (const std::exception&)
    {
    }
    return done;
}
