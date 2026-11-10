#include "atm/ServerLink.h"

#include <utility>

#include "common/Invariant.h"
#include "crypto/SignDomain.h"

ServerLink::ServerLink(IServerApi& server, const AtmHsm& hsm, PendingReportQueue& queue, const IClock& clock, std::string atmId)
    : _server(server),
      _hsm(hsm),
      _queue(queue),
      _clock(clock),
      _atmId(std::move(atmId))
{
    ATM_INVARIANT(!_atmId.empty(), "server link: atmId must not be empty");
}

std::optional<RequestHeader> ServerLink::makeHeader(ApiCall call, const std::string& body) const
{
    auto nonce = _hsm.generateNonce();
    if (!nonce) return std::nullopt;
    return makeHeader(call, body, *nonce, _clock.nowUnix());
}

std::optional<RequestHeader> ServerLink::makeHeader(ApiCall call, const std::string& body, const std::string& nonce, std::int64_t timestamp) const
{
    RequestHeader header;
    header.atmId = _atmId;
    header.nonce = nonce;
    header.timestamp = timestamp;

    auto mac = _hsm.macMessage(header.macPayload(call, body));
    if (!mac) return std::nullopt;
    header.mac = std::move(*mac);
    return header;
}

bool ServerLink::deliver(const PendingReport& item)
{
    try
    {
        switch (item.kind)
        {
        case PendingKind::DispenseReport:
        {
            const auto header = makeHeader(ApiCall::ReportDispense, item.dispense.payload());
            return header && _server.reportDispense(*header, item.dispense);
        }
        case PendingKind::CommandResult:
        {
            const auto header = makeHeader(ApiCall::ReportCommandResult, ApiBody::commandResult(item.commandSeq, item.commandOk));
            return header && _server.reportCommandResult(*header, item.commandSeq, item.commandOk);
        }
        case PendingKind::Checkpoint:
        {
            const auto header = makeHeader(ApiCall::SubmitCheckpoint, item.checkpoint.payload());
            return header && _server.submitCheckpoint(*header, item.checkpoint);
        }
        }
    }
    catch (...)
    {
    }
    return false;
}

void ServerLink::send(PendingReport item)
{
    if (!_queue.empty()) (void)flushPending();
    if (deliver(item)) return;
    (void)_queue.push(std::move(item));
}

bool ServerLink::flushPending()
{
    std::size_t index = 0;
    while (index < _queue.size())
    {
        if (deliver(_queue.at(index)) && _queue.erase(index)) continue;
        ++index;
    }

    if (_tamperUnconfirmed && sendTamper()) _tamperUnconfirmed = false;
    return _queue.empty();
}

std::optional<AuthResponse> ServerLink::authorize(const AuthRequest& request)
{
    try
    {
        AuthResponse response = _server.authorize(request);
        if (response.sessionId != request.getSessionId()) return std::nullopt;
        if (!_hsm.verifyServer(SignDomain::Response, response.signedPayload(), response.signature)) return std::nullopt;
        return response;
    }
    catch (...)
    {
        return std::nullopt;
    }
}

void ServerLink::reportDispense(const DispenseReport& report)
{
    PendingReport item;
    item.kind = PendingKind::DispenseReport;
    item.dispense = report;
    send(std::move(item));
}

std::vector<SignedCommand> ServerLink::pollCommands()
{
    try
    {
        const auto header = makeHeader(ApiCall::PollCommands, ApiBody::empty());
        if (!header) return {};
        return _server.pollCommands(*header);
    }
    catch (...)
    {
        return {};
    }
}

void ServerLink::reportCommandResult(std::uint64_t commandSeq, bool ok)
{
    PendingReport item;
    item.kind = PendingKind::CommandResult;
    item.commandSeq = commandSeq;
    item.commandOk = ok;
    send(std::move(item));
}

bool ServerLink::syncStatus(const StatusReport& report)
{
    if (!_queue.empty()) (void)flushPending();

    try
    {
        const auto header = makeHeader(ApiCall::SyncStatus, report.payload());
        return header && _server.syncStatus(*header, report);
    }
    catch (...)
    {
        return false;
    }
}

void ServerLink::endSession(const std::string& sessionId)
{
    try
    {
        const auto header = makeHeader(ApiCall::EndSession, ApiBody::endSession(sessionId));
        if (header) (void)_server.endSession(*header, sessionId);
    }
    catch (...)
    {
    }
}

std::optional<StaffLoginResult> ServerLink::staffLogin(const StaffLoginRequest& request)
{
    try
    {
        const auto header = makeHeader(ApiCall::StaffLogin, request.payload(), request.nonce, request.timestamp);
        if (!header) return std::nullopt;
        return _server.staffLogin(*header, request);
    }
    catch (...)
    {
        return std::nullopt;
    }
}

void ServerLink::staffLogout(const std::string& token)
{
    try
    {
        const auto header = makeHeader(ApiCall::StaffLogout, ApiBody::staffLogout(token));
        if (header) (void)_server.staffLogout(*header, token);
    }
    catch (...)
    {
    }
}

bool ServerLink::sendTamper()
{
    try
    {
        RequestHeader header;
        header.atmId = _atmId;
        header.timestamp = _clock.nowUnix();
        if (auto nonce = _hsm.generateNonce()) header.nonce = std::move(*nonce);
        if (auto mac = _hsm.macMessage(header.macPayload(ApiCall::ReportTamper, ApiBody::empty()))) header.mac = std::move(*mac);
        return _server.reportTamper(header);
    }
    catch (...)
    {
        return false;
    }
}

void ServerLink::reportTamper() { _tamperUnconfirmed = !sendTamper(); }

std::optional<SignedCheckpoint> ServerLink::latestCheckpoint(const std::string& auditorToken, const std::string& nonce)
{
    try
    {
        const auto header = makeHeader(ApiCall::LatestCheckpoint, ApiBody::latestCheckpoint(auditorToken), nonce, _clock.nowUnix());
        if (!header) return std::nullopt;
        return _server.latestCheckpoint(*header, auditorToken);
    }
    catch (...)
    {
        return std::nullopt;
    }
}

Decision ServerLink::decide(const AccessRequest& request)
{
    AccessRequest scoped = request;
    if (scoped.atmId.empty()) scoped.atmId = _atmId;
    if (scoped.atmId != _atmId) return Decision{};

    try
    {
        const auto header = makeHeader(ApiCall::Decide, scoped.payload());
        if (!header) return Decision{};
        return _server.decide(*header, scoped);
    }
    catch (...)
    {
        return Decision{};
    }
}

bool ServerLink::submit(const Checkpoint& checkpoint)
{
    PendingReport item;
    item.kind = PendingKind::Checkpoint;
    item.checkpoint = checkpoint;

    if (deliver(item)) return true;
    return _queue.push(std::move(item));
}
