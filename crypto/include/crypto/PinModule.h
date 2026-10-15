#pragma once
#include <optional>
#include "crypto/AtmHsm.h"
#include "common/Card.h"
#include "common/AuthRequest.h"
#include "crypto/CryptoCore.h"

class PinModule
{
private:
	AtmHsm& _hsm;

public:
	PinModule(AtmHsm& hsm) : _hsm(hsm) {}

    [[nodiscard]] std::optional<AuthRequest> processPin(
        const Card& card,
        const std::string& pin,
        Action action,
        std::int64_t amount,
        const std::string& sessionId,
        const std::string& atmId,
        std::int64_t timestamp) const;
	
};