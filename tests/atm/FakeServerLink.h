#pragma once
#include <functional>
#include <vector>

#include "atm/IServerLink.h"
#include "crypto/AtmHsm.h"
#include "FakeBank.h"

class FakeServerLink final : public IServerLink
{
private:
    FakeBank& _bank;
    const AtmHsm& _atmHsm;

public:
    bool online = true;
    std::function<void()> beforeReply;
    std::function<void(AuthResponse&)> alterInTransit;
    std::optional<Checkpoint> checkpoint;

    std::vector<SignedCommand> queuedCommands;
    std::vector<DispenseReport> reports;
    std::vector<StatusReport> statusReports;
    std::vector<std::string> endedSessions;
    std::vector<std::string> loggedOut;
    std::vector<std::pair<std::uint64_t, bool>> commandResults;
    bool tamperReported = false;

    FakeServerLink(FakeBank& bank, const AtmHsm& atmHsm) : _bank(bank), _atmHsm(atmHsm) {}

    std::optional<AuthResponse> authorize(const AuthRequest& request) override
    {
        if (!online) return std::nullopt;

        AuthResponse resp = _bank.authorize(request);
        if (beforeReply) beforeReply();
        if (alterInTransit) alterInTransit(resp);

        if (!_atmHsm.verifyServer(SignDomain::Response, responsePayload(resp), resp.signature))
            return std::nullopt;
        return resp;
    }

    void reportDispense(const DispenseReport& report) override
    {
        reports.push_back(report);
        _bank.onDispenseReport(report);
    }

    bool flushPending() override { return true; }

    std::vector<SignedCommand> pollCommands() override
    {
        std::vector<SignedCommand> out = std::move(queuedCommands);
        queuedCommands.clear();
        return out;
    }

    void reportCommandResult(std::uint64_t commandSeq, bool ok) override
    {
        commandResults.emplace_back(commandSeq, ok);
    }

    bool syncStatus(const StatusReport& report) override
    {
        statusReports.push_back(report);
        return true;
    }

    void endSession(const std::string& sessionId) override { endedSessions.push_back(sessionId); }

    std::optional<StaffLoginResult> staffLogin(const std::string& staffId,
        const std::string& sealedPassword) override
    {
        if (!online) return std::nullopt;
        return _bank.staffLogin(staffId, sealedPassword);
    }

    void staffLogout(const std::string& token) override { loggedOut.push_back(token); }

    void reportTamper() override { tamperReported = true; }

    std::optional<Checkpoint> latestCheckpoint() override { return checkpoint; }
};
