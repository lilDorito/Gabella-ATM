#pragma once
#include <cstdint>
#include <functional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/Clock.h"
#include "crypto/BankHsm.h"
#include "crypto/SignDomain.h"
#include "server_api/IServerApi.h"

class FakeServerApi final : public IServerApi
{
private:
    const BankHsm& _hsm;
    const IClock& _clock;
    std::set<std::string> _nonces;

    bool admit(ApiCall call, const RequestHeader& header, const std::string& body)
    {
        ++received;
        if (throwOnCall) throw std::runtime_error("simulated server failure");
        if (!online) return false;

        const std::int64_t age = _clock.nowUnix() - header.timestamp;
        const bool valid =
            header.atmId == expectedAtm && _hsm.verifyMessage(header.macPayload(call, body), header.mac) && age <= 60 && age >= -60 && !header.nonce.empty() && _nonces.insert(header.nonce).second;
        if (!valid)
        {
            ++rejectedHeaders;
            return false;
        }

        accepted.push_back(apiCallToString(call));
        headers.push_back(header);
        return true;
    }

public:
    std::string expectedAtm = "ATM-001";
    bool online = true;
    bool throwOnCall = false;
    bool refuseDispenseReports = false;
    bool acceptUnauthenticatedTamper = true;
    bool forgeSignature = false;
    std::size_t received = 0;
    std::size_t rejectedHeaders = 0;

    std::vector<std::string> accepted;
    std::vector<RequestHeader> headers;
    std::vector<DispenseReport> dispenseReports;
    std::vector<StatusReport> statusReports;
    std::vector<std::string> endedSessions;
    std::vector<std::string> loggedOut;
    std::vector<StaffLoginRequest> logins;
    std::vector<AccessRequest> decisions;
    std::vector<Checkpoint> checkpoints;
    std::vector<std::pair<std::uint64_t, bool>> commandResults;
    std::vector<SignedCommand> commands;
    std::optional<StaffLoginResult> loginResult = StaffLoginResult{ "tok-test", Role::ServiceEngineer };
    Decision decision;
    std::optional<Checkpoint> latest;
    std::string lastCheckpointNonce;
    bool tamperSeen = false;
    bool tamperAuthenticated = false;
    std::function<AuthResponse(const AuthRequest&)> onAuthorize;

    FakeServerApi(const BankHsm& hsm, const IClock& clock) : _hsm(hsm), _clock(clock)
    {
        decision.verdict = Verdict::Allowed;
        decision.reason = DenyReason::None;
    }

    AuthResponse authorize(const AuthRequest& request) override
    {
        ++received;
        if (throwOnCall) throw std::runtime_error("simulated server failure");

        AuthResponse response;
        response.sessionId = request.getSessionId();
        if (!online) return response;

        if (onAuthorize)
            response = onAuthorize(request);
        else
            response.status = AuthStatus::Approved;

        response.signature = *_hsm.sign(SignDomain::Response, response.signedPayload());
        if (forgeSignature) response.signature[0] = static_cast<char>(response.signature[0] ^ 1);
        accepted.push_back("Authorize");
        return response;
    }

    bool reportDispense(const RequestHeader& header, const DispenseReport& report) override
    {
        if (!admit(ApiCall::ReportDispense, header, report.payload())) return false;
        if (refuseDispenseReports) return false;
        dispenseReports.push_back(report);
        return true;
    }

    bool syncStatus(const RequestHeader& header, const StatusReport& report) override
    {
        if (!admit(ApiCall::SyncStatus, header, report.payload())) return false;
        statusReports.push_back(report);
        return true;
    }

    bool endSession(const RequestHeader& header, const std::string& sessionId) override
    {
        if (!admit(ApiCall::EndSession, header, ApiBody::endSession(sessionId))) return false;
        endedSessions.push_back(sessionId);
        return true;
    }

    std::optional<StaffLoginResult> staffLogin(const RequestHeader& header, const StaffLoginRequest& request) override
    {
        const bool consistent = request.atmId == header.atmId && request.nonce == header.nonce && request.timestamp == header.timestamp;
        if (!admit(ApiCall::StaffLogin, header, request.payload()) || !consistent) return std::nullopt;
        logins.push_back(request);
        return loginResult;
    }

    bool staffLogout(const RequestHeader& header, const std::string& token) override
    {
        if (!admit(ApiCall::StaffLogout, header, ApiBody::staffLogout(token))) return false;
        loggedOut.push_back(token);
        return true;
    }

    Decision decide(const RequestHeader& header, const AccessRequest& request) override
    {
        ++received;
        if (request.atmId != header.atmId || !admit(ApiCall::Decide, header, request.payload())) return Decision{};
        decisions.push_back(request);
        return decision;
    }

    bool submitCheckpoint(const RequestHeader& header, const Checkpoint& checkpoint) override
    {
        if (!admit(ApiCall::SubmitCheckpoint, header, checkpoint.payload())) return false;
        checkpoints.push_back(checkpoint);
        return true;
    }

    std::optional<SignedCheckpoint> latestCheckpoint(const RequestHeader& header, const std::string& auditorToken) override
    {
        if (!admit(ApiCall::LatestCheckpoint, header, ApiBody::latestCheckpoint(auditorToken)) || !latest) return std::nullopt;
        lastCheckpointNonce = header.nonce;

        SignedCheckpoint reply;
        reply.checkpoint = *latest;
        reply.requestNonce = header.nonce;
        reply.signature = *_hsm.sign(SignDomain::Checkpoint, reply.signedPayload());
        return reply;
    }

    bool reportTamper(const RequestHeader& header) override
    {
        ++received;
        if (throwOnCall) throw std::runtime_error("simulated server failure");
        if (!online) return false;

        const bool authentic = _hsm.verifyMessage(header.macPayload(ApiCall::ReportTamper, ApiBody::empty()), header.mac);
        if (!authentic && !acceptUnauthenticatedTamper) return false;

        tamperSeen = true;
        tamperAuthenticated = authentic;
        return true;
    }

    std::vector<SignedCommand> pollCommands(const RequestHeader& header) override
    {
        if (!admit(ApiCall::PollCommands, header, ApiBody::empty())) return {};
        return commands;
    }

    bool reportCommandResult(const RequestHeader& header, std::uint64_t commandSeq, bool ok) override
    {
        if (!admit(ApiCall::ReportCommandResult, header, ApiBody::commandResult(commandSeq, ok))) return false;
        commandResults.emplace_back(commandSeq, ok);
        return true;
    }
};
