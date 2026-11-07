#pragma once
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "access/AccessTypes.h"

class IDualControlRepository
{
public:
    virtual ~IDualControlRepository() = default;

    [[nodiscard]] virtual bool insertRequest(const CriticalRequest& r) = 0;
    [[nodiscard]] virtual bool insertApproval(const std::string& requestId, const std::string& staffId, std::int64_t approvedAt) = 0;
    [[nodiscard]] virtual std::uint32_t countApprovals(const std::string& requestId) const = 0;
    [[nodiscard]] virtual bool setStatus(const std::string& requestId, RequestStatus from, RequestStatus to) = 0;
    [[nodiscard]] virtual bool setExpiresAt(const std::string& requestId, std::int64_t expiresAt) = 0;
    [[nodiscard]] virtual std::optional<CriticalRequest> find(const std::string& requestId) const = 0;
    [[nodiscard]] virtual std::vector<CriticalRequest> listPending() const = 0;
    [[nodiscard]] virtual bool inTransaction(const std::function<bool()>& fn) = 0;
};
