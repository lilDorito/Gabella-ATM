#pragma once
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "access/IDualControlRepository.h"
#include "server/db/Database.h"

// SQLite implementation of the module-4 interface. Requests and approvals live in
// dual_control_requests / dual_control_approvals; the schema triggers keep status moving forward only.
class DualControlRepository final : public IDualControlRepository
{
private:
    Database& _db;
    int _depth = 0;

    std::vector<std::string> approversOf(const std::string& requestId) const;

public:
    explicit DualControlRepository(Database& db) : _db(db) {}

    static const char* statusToColumn(RequestStatus status);
    static std::optional<RequestStatus> statusFromColumn(const std::string& text);

    [[nodiscard]] bool insertRequest(const CriticalRequest& r) override;
    [[nodiscard]] bool insertApproval(const std::string& requestId, const std::string& staffId, std::int64_t approvedAt) override;
    [[nodiscard]] std::uint32_t countApprovals(const std::string& requestId) const override;
    [[nodiscard]] bool setStatus(const std::string& requestId, RequestStatus from, RequestStatus to) override;
    [[nodiscard]] std::optional<CriticalRequest> find(const std::string& requestId) const override;
    [[nodiscard]] std::vector<CriticalRequest> listPending() const override;
    [[nodiscard]] bool inTransaction(const std::function<bool()>& fn) override;

    // Not part of the module-4 interface: used by CommandService to find approvals that were never queued.
    [[nodiscard]] std::vector<CriticalRequest> listApproved() const;
};
