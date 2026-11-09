#pragma once
#include <string>

#include "audit/IAuditSink.h"
#include "common/AuthRequest.h"
#include "common/Clock.h"
#include "common/ServerMessages.h"
#include "crypto/BankHsm.h"
#include "server/SystemConfig.h"
#include "server/repo/AtmRepository.h"
#include "server/repo/NonceRepository.h"

enum class GateVerdict
{
    Admitted,
    UnknownAtm,
    AtmOutOfService,
    BadMac,
    StaleRequest,
    ReplayedNonce
};

const char* gateVerdictToString(GateVerdict verdict);

class RequestGate
{
private:
    const BankHsm& _hsm;
    AtmRepository& _atms;
    NonceRepository& _nonces;
    IAuditSink& _log;
    const IClock& _clock;
    const SystemConfig& _config;

    GateVerdict check(const char* call, const std::string& atmId, const std::string& macData, const std::string& mac, std::int64_t timestamp, const std::string& nonce, bool allowOutOfService);
    void refuse(GateVerdict verdict, const char* call, const std::string& atmId);

public:
    RequestGate(const BankHsm& hsm, AtmRepository& atms, NonceRepository& nonces, IAuditSink& log, const IClock& clock, const SystemConfig& config);

    [[nodiscard]] GateVerdict admit(ApiCall call, const RequestHeader& header, const std::string& body, bool allowOutOfService);
    [[nodiscard]] GateVerdict admitAuthorization(const AuthRequest& request);
};
