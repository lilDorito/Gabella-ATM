#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "access/IAccessDecider.h"
#include "atm/IServerLink.h"
#include "atm/PendingReportQueue.h"
#include "audit/ICheckpointSink.h"
#include "common/Clock.h"
#include "crypto/AtmHsm.h"
#include "server_api/IServerApi.h"

class ServerLink final : public IServerLink, public IAccessDecider, public ICheckpointSink
{
private:
    IServerApi& _server;
    const AtmHsm& _hsm;
    PendingReportQueue& _queue;
    const IClock& _clock;
    const std::string _atmId;
    bool _tamperUnconfirmed = false;

    std::optional<RequestHeader> makeHeader(ApiCall call, const std::string& body) const;
    std::optional<RequestHeader> makeHeader(ApiCall call, const std::string& body, const std::string& nonce, std::int64_t timestamp) const;
    bool deliver(const PendingReport& item);
    bool sendTamper();
    void send(PendingReport item);

public:
    ServerLink(IServerApi& server, const AtmHsm& hsm, PendingReportQueue& queue, const IClock& clock, std::string atmId);

    [[nodiscard]] std::optional<AuthResponse> authorize(const AuthRequest& request) override;
    void reportDispense(const DispenseReport& report) override;
    [[nodiscard]] bool flushPending() override;
    std::vector<SignedCommand> pollCommands() override;
    void reportCommandResult(std::uint64_t commandSeq, bool ok) override;
    bool syncStatus(const StatusReport& report) override;
    void endSession(const std::string& sessionId) override;
    std::optional<StaffLoginResult> staffLogin(const StaffLoginRequest& request) override;
    void staffLogout(const std::string& token) override;
    void reportTamper() override;
    std::optional<SignedCheckpoint> latestCheckpoint(const std::string& auditorToken, const std::string& nonce) override;

    [[nodiscard]] Decision decide(const AccessRequest& request) override;
    [[nodiscard]] bool submit(const Checkpoint& checkpoint) override;
};
