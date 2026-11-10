#include "server/RequestGate.h"

#include "common/Hex.h"

const char* gateVerdictToString(GateVerdict verdict)
{
    switch (verdict)
    {
    case GateVerdict::Admitted: return "Admitted";
    case GateVerdict::UnknownAtm: return "UnknownAtm";
    case GateVerdict::AtmOutOfService: return "AtmOutOfService";
    case GateVerdict::BadMac: return "BadMac";
    case GateVerdict::StaleRequest: return "StaleRequest";
    case GateVerdict::ReplayedNonce: return "ReplayedNonce";
    }
    return "";
}

RequestGate::RequestGate(const BankHsm& hsm, AtmRepository& atms, NonceRepository& nonces, IAuditSink& log, const IClock& clock, const SystemConfig& config)
    : _hsm(hsm),
      _atms(atms),
      _nonces(nonces),
      _log(log),
      _clock(clock),
      _config(config)
{
}

GateVerdict RequestGate::admit(ApiCall call, const RequestHeader& header, const std::string& body, bool allowOutOfService)
{
    return check(apiCallToString(call), header.atmId, header.macPayload(call, body), header.mac, header.timestamp, header.nonce, allowOutOfService);
}

GateVerdict RequestGate::admitAuthorization(const AuthRequest& request)
{
    return check("Authorize", request.getAtmId(), request.macPayload(), request.getMac(), request.getTimestamp(), request.getNonce(), false);
}

GateVerdict RequestGate::check(const char* call, const std::string& atmId, const std::string& macData, const std::string& mac, std::int64_t timestamp, const std::string& nonce, bool allowOutOfService)
{
    const auto atm = _atms.find(atmId);
    GateVerdict verdict = GateVerdict::Admitted;
    if (!atm)
        verdict = GateVerdict::UnknownAtm;
    else if (atm->status == AtmStatus::OutOfService && !allowOutOfService)
        verdict = GateVerdict::AtmOutOfService;
    else if (!_hsm.verifyMessage(atmId, macData, mac))
        verdict = GateVerdict::BadMac;
    else
    {
        const std::int64_t now = _clock.nowUnix();
        const std::int64_t age = now - timestamp;
        if (age > _config.requestWindowSeconds || age < -_config.requestWindowSeconds)
            verdict = GateVerdict::StaleRequest;
        else
        {
            _nonces.purgeOlderThan(now - _config.nonceRetentionSeconds);
            if (nonce.empty() || !_nonces.insertIfNew(toHex(nonce), atmId, now)) verdict = GateVerdict::ReplayedNonce;
        }
    }

    if (verdict != GateVerdict::Admitted) refuse(verdict, call, atmId);
    return verdict;
}

void RequestGate::refuse(GateVerdict verdict, const char* call, const std::string& atmId)
{
    LogEvent e;
    e.type = verdict == GateVerdict::ReplayedNonce ? EventType::NONCE_REPLAY : EventType::ACCESS_DENIED;
    e.outcome = Outcome::Failure;
    e.actorRole = Role::System;
    e.actorId = atmId;
    e.details = std::string("reason=") + gateVerdictToString(verdict) + " call=" + call;
    if (_log.record(e)) return;
    e.actorId.clear();
    e.details += " actor_id=withheld";
    (void)_log.record(e);
}
