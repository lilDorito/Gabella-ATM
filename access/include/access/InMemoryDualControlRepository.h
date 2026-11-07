#pragma once
#include <algorithm>
#include <map>
#include <utility>

#include "access/IDualControlRepository.h"

class InMemoryDualControlRepository final : public IDualControlRepository
{
private:
    std::map<std::string, CriticalRequest> _requests;

public:
    bool insertRequest(const CriticalRequest& r) override
    {
        CriticalRequest copy = r;
        copy.approvers.clear();
        return _requests.emplace(r.requestId, std::move(copy)).second;
    }

    bool insertApproval(const std::string& requestId, const std::string& staffId, std::int64_t) override
    {
        auto it = _requests.find(requestId);
        if (it == _requests.end()) return false;
        auto& a = it->second.approvers;
        if (std::find(a.begin(), a.end(), staffId) != a.end()) return false;
        a.push_back(staffId);
        return true;
    }

    std::uint32_t countApprovals(const std::string& requestId) const override
    {
        auto it = _requests.find(requestId);
        return it == _requests.end() ? 0u : static_cast<std::uint32_t>(it->second.approvers.size());
    }

    bool setStatus(const std::string& requestId, RequestStatus from, RequestStatus to) override
    {
        auto it = _requests.find(requestId);
        if (it == _requests.end() || it->second.status != from) return false;
        it->second.status = to;
        return true;
    }

    bool setExpiresAt(const std::string& requestId, std::int64_t expiresAt) override
    {
        auto it = _requests.find(requestId);
        if (it == _requests.end()) return false;
        it->second.expiresAt = expiresAt;
        return true;
    }

    std::optional<CriticalRequest> find(const std::string& requestId) const override
    {
        auto it = _requests.find(requestId);
        if (it == _requests.end()) return std::nullopt;
        return it->second;
    }

    std::vector<CriticalRequest> listPending() const override
    {
        std::vector<CriticalRequest> out;
        for (const auto& [id, r] : _requests)
        {
            if (r.status == RequestStatus::Pending) out.push_back(r);
        }
        return out;
    }

    bool inTransaction(const std::function<bool()>& fn) override
    {
        const auto backup = _requests;
        bool ok = false;
        try
        {
            ok = fn();
        }
        catch (...)
        {
            _requests = backup;
            throw;
        }
        if (!ok) _requests = backup;
        return ok;
    }
};
