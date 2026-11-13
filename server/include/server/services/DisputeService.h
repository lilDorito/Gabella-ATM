#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "access/DualControlManager.h"
#include "server/repo/DualControlRepository.h"
#include "server/repo/TxRepository.h"
#include "server/services/ReconciliationService.h"

enum class ResolveResult
{
    Resolved,
    AlreadyResolved,
    NotApproved,
    NotAResolution,
    BadParams,
    Refused,
    Failed
};

const char* resolveResultToString(ResolveResult result);

struct Resolution
{
    std::string atmId;
    std::int64_t txId = 0;
    bool commit = false;
    std::string reason;
};

class DisputeService final
{
private:
    DualControlManager& _dual;
    DualControlRepository& _requests;
    const TxRepository& _txs;
    ReconciliationService& _reconciliation;

public:
    DisputeService(DualControlManager& dual, DualControlRepository& requests, const TxRepository& txs, ReconciliationService& reconciliation)
        : _dual(dual),
          _requests(requests),
          _txs(txs),
          _reconciliation(reconciliation)
    {
    }

    DisputeService(const DisputeService&) = delete;
    DisputeService& operator=(const DisputeService&) = delete;

    std::vector<TxRecord> disputed() const;
    [[nodiscard]] ResolveResult executeApproved(const std::string& requestId);
    std::size_t tick();

    static std::optional<std::string> makeParams(const TxRecord& tx, bool commit, const std::string& reason);
    static std::optional<Resolution> parseParams(const std::string& params);
    static std::string resolvedBy(const std::string& requestId);
};
